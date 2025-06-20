import asyncio
import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from bleak import BleakScanner
import requests
import os

def load_json(file):
    try:
        if os.path.exists(file):
            with open(file, "r", encoding="utf-8") as f:
                data = json.load(f)
                print(f"Loaded {file}: {len(data) if isinstance(data, dict) else 'N/A'} entries")
                return data
        else:
            print(f"File {file} not found")
            return {}
    except Exception as e:
        print(f"Failed to load {file}: {e}")
        return {}

VENDORS = load_json("mac_vendors.json")
MANUFACTURERS = load_json("manufacturer_ids.json")
SERVICES = load_json("service_uuids.json")

def get_vendor_local(mac):
    """Get vendor from local MAC address database"""
    if not mac or not VENDORS:
        return "Unknown"
    
    mac_clean = mac.replace(":", "").replace("-", "").upper()
    
    oui_6 = mac_clean[:6]
    if oui_6 in VENDORS:
        return VENDORS[oui_6]
    
    oui_8 = mac_clean[:8]
    if oui_8 in VENDORS:
        return VENDORS[oui_8]
    
    mac_formats = [
        mac.upper()[:8],
        mac.upper()[:9],
        mac.replace(":", "").replace("-", "").upper()[:6],
        mac[:8].upper(),
        mac[:9].upper()
    ]
    
    for mac_format in mac_formats:
        if mac_format in VENDORS:
            return VENDORS[mac_format]
    
    return "Unknown"

def get_vendor_online(mac):
    """Get vendor from online MAC address API"""
    try:
        mac_clean = mac.replace("-", ":").upper()
        response = requests.get(f"https://api.macvendors.com/{mac_clean}", timeout=5)
        if response.status_code == 200:
            vendor = response.text.strip()
            if vendor and vendor.lower() != "not found":
                return vendor
    except requests.RequestException as e:
        print(f"Online lookup failed for {mac}: {e}")
    return "Unknown"

def parse_manufacturer_data(advertisement_data):
    """Parse manufacturer data from BLE advertisement"""
    if not advertisement_data or not hasattr(advertisement_data, 'manufacturer_data'):
        return "N/A"
    
    if not advertisement_data.manufacturer_data:
        return "N/A"
    
    try:
        for company_id, data in advertisement_data.manufacturer_data.items():

            hex_id = f"{company_id:04X}"
            
            manufacturer_name = "Unknown"
            if MANUFACTURERS:

                for key_format in [hex_id, hex_id.lower(), f"0x{hex_id}", f"0x{hex_id.lower()}"]:
                    if key_format in MANUFACTURERS:
                        manufacturer_name = MANUFACTURERS[key_format]
                        break
            
            return f"0x{hex_id} ({manufacturer_name})"
    except Exception as e:
        print(f"Error parsing manufacturer data: {e}")
    
    return "N/A"

def parse_services(advertisement_data):
    """Parse service UUIDs from BLE advertisement"""
    if not advertisement_data or not hasattr(advertisement_data, 'service_uuids'):
        return "N/A"
    
    if not advertisement_data.service_uuids:
        return "N/A"
    
    try:
        service_names = []
        for uuid in advertisement_data.service_uuids:
            uuid_str = str(uuid).lower()
            
            service_name = "Unknown Service"
            if SERVICES:

                for key_format in [uuid_str, uuid_str.upper(), uuid_str[:4], uuid_str[:8]]:
                    if key_format in SERVICES:
                        service_name = SERVICES[key_format]
                        break
            
            service_names.append(f"{service_name} ({uuid_str[:8]}...)")
        
        return ", ".join(service_names) if service_names else "N/A"
    except Exception as e:
        print(f"Error parsing services: {e}")
    
    return "N/A"

class CyberBLEApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberBLE - BLE Device Profiler")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", rowheight=25, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("TButton", font=("Segoe UI", 10), padding=5)
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("TProgressbar", thickness=6)

        self.devices = {}
        self.create_widgets()
        self.check_data_files()

    def check_data_files(self):
        """Check if data files are loaded properly"""
        status_parts = []
        if VENDORS:
            status_parts.append(f"Vendors: {len(VENDORS)}")
        if MANUFACTURERS:
            status_parts.append(f"Manufacturers: {len(MANUFACTURERS)}")
        if SERVICES:
            status_parts.append(f"Services: {len(SERVICES)}")
        
        if status_parts:
            self.status_label.config(text=f"Ready. Loaded - {', '.join(status_parts)}")
        else:
            self.status_label.config(text="Ready. Warning: No lookup data loaded!")

    def create_widgets(self):

        ttk.Label(self.root, text="CyberBLE - BLE Device Profiler", 
                 font=("Segoe UI", 18, "bold")).pack(pady=10)

        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=15, pady=5)

        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill="both", expand=True)

        columns = ("MAC", "Name", "Vendor", "Manuf. ID", "Services", "RSSI")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=16)

        column_widths = {"MAC": 140, "Name": 120, "Vendor": 150, "Manuf. ID": 140, "Services": 250, "RSSI": 60}
        for col in columns:
            self.tree.heading(col, text=col, command=lambda c=col: self.explain_column(c))
            self.tree.column(col, width=column_widths.get(col, 100))

        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)

        self.tree.grid(row=0, column=0, sticky="nsew")
        v_scrollbar.grid(row=0, column=1, sticky="ns")
        h_scrollbar.grid(row=1, column=0, sticky="ew")

        tree_frame.grid_rowconfigure(0, weight=1)
        tree_frame.grid_columnconfigure(0, weight=1)

        self.progress = ttk.Progressbar(main_frame, mode="indeterminate")
        self.progress.pack(fill="x", pady=(10, 5))

        self.status_label = ttk.Label(main_frame, text="Ready.")
        self.status_label.pack(pady=(0, 10))

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=5)

        self.scan_button = ttk.Button(button_frame, text="Scan BLE Devices (Offline)", 
                                     command=self.start_scan_offline)
        self.scan_button.grid(row=0, column=0, padx=5)

        self.scan_online_button = ttk.Button(button_frame, text="Scan BLE Devices (Online)", 
                                           command=self.start_scan_online)
        self.scan_online_button.grid(row=0, column=1, padx=5)

        self.lookup_button = ttk.Button(button_frame, text="Update Vendors Online", 
                                       command=self.lookup_online)
        self.lookup_button.grid(row=0, column=2, padx=5)

        self.clear_button = ttk.Button(button_frame, text="Clear Results", 
                                      command=self.clear_results)
        self.clear_button.grid(row=0, column=3, padx=5)

        ttk.Label(main_frame, text="CyberBLE © 2025 by CyberNilsen", 
                 font=("Segoe UI", 9), foreground="gray").pack(side="bottom", pady=10)

    def explain_column(self, column):
        explanations = {
            "MAC": "The hardware address (Media Access Control) of the device.",
            "Name": "The advertised Bluetooth device name.",
            "Vendor": "The vendor/manufacturer based on MAC address (local or online).",
            "Manuf. ID": "The manufacturer ID from the BLE advertisement.",
            "Services": "Services advertised by the device (e.g. Heart Rate, HID, etc.).",
            "RSSI": "Received Signal Strength Indicator (signal strength in dBm)."
        }
        messagebox.showinfo(f"{column} Info", explanations.get(column, "No info available."))

    def start_scan_offline(self):
        self.start_scan(online_lookup=False)

    def start_scan_online(self):
        self.start_scan(online_lookup=True)

    def start_scan(self, online_lookup=False):
        self.scan_button.config(state="disabled")
        self.scan_online_button.config(state="disabled")
        self.lookup_button.config(state="disabled")
        self.clear_button.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.progress.start()
        
        scan_type = "online" if online_lookup else "offline"
        self.status_label.config(text=f"Scanning BLE devices ({scan_type})...")

        threading.Thread(target=self.run_scan, args=(online_lookup,)).start()

    def run_scan(self, online_lookup=False):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            devices = loop.run_until_complete(self.scan_devices())
            self.root.after(0, lambda: self.update_tree(devices, online_lookup))
        except Exception as e:
            self.root.after(0, lambda: self.scan_error(str(e)))
        finally:
            loop.close()

    async def scan_devices(self):
        try:
            print("Starting BLE scan...")
            devices = await BleakScanner.discover(timeout=8.0, return_adv=True)
            print(f"Found {len(devices)} devices")
            return devices
        except Exception as e:
            print(f"Scan error: {e}")
            raise

    def update_tree(self, devices, online_lookup=False):
        self.progress.stop()
        self.enable_buttons()
        self.devices = devices

        device_count = len(devices)
        self.status_label.config(text=f"Processing {device_count} device(s)...")

        processed = 0
        for device, adv in devices.values():
            mac = device.address or "Unknown"
            
            device_name = device.name
            if not device_name or device_name.strip() == "":

                manuf_id = parse_manufacturer_data(adv)
                if manuf_id != "N/A" and "(" in manuf_id:

                    manuf_name = manuf_id.split("(")[1].split(")")[0]
                    if manuf_name != "Unknown":
                        device_name = f"[{manuf_name} Device]"
                    else:
                        device_name = "[Unknown Device]"
                else:
                    device_name = "[Unnamed Device]"
            
            if online_lookup:
                vendor = get_vendor_online(mac)
                if vendor == "Unknown":
                    vendor = get_vendor_local(mac)
            else:
                vendor = get_vendor_local(mac)
            
            manuf_id = parse_manufacturer_data(adv)
            services = parse_services(adv)
            rssi = getattr(adv, 'rssi', 'N/A')
            
            self.tree.insert("", "end", values=(mac, device_name, vendor, manuf_id, services, rssi))
            
            processed += 1
            if processed % 5 == 0:  
                self.status_label.config(text=f"Processed {processed}/{device_count} devices...")
                self.root.update()

        scan_type = "online" if online_lookup else "offline"
        self.status_label.config(text=f"Scan complete ({scan_type}). {device_count} device(s) found.")

    def lookup_online(self):
        if not self.devices:
            messagebox.showwarning("No Data", "Please scan for devices first.")
            return

        self.lookup_button.config(state="disabled")
        self.status_label.config(text="Looking up vendors online...")
        self.progress.start()

        def task():
            total_items = len(self.tree.get_children())
            processed = 0
            
            for child in self.tree.get_children():
                values = list(self.tree.item(child, "values"))
                mac = values[0]
                
                online_vendor = get_vendor_online(mac)
                if online_vendor != "Unknown":
                    values[2] = online_vendor  
                    self.root.after(0, lambda c=child, v=values: self.tree.item(c, values=v))
                
                processed += 1
                if processed % 3 == 0: 
                    self.root.after(0, lambda p=processed, t=total_items: 
                                   self.status_label.config(text=f"Looking up vendors... {p}/{t}"))
            
            self.root.after(0, self.finish_lookup)

        threading.Thread(target=task).start()

    def finish_lookup(self):
        self.progress.stop()
        self.lookup_button.config(state="normal")
        self.status_label.config(text="Online vendor lookup complete.")

    def clear_results(self):
        self.tree.delete(*self.tree.get_children())
        self.devices = {}
        self.status_label.config(text="Results cleared. Ready for new scan.")

    def scan_error(self, error_msg):
        self.progress.stop()
        self.enable_buttons()
        self.status_label.config(text=f"Scan error: {error_msg}")
        messagebox.showerror("Scan Error", f"Failed to scan BLE devices:\n{error_msg}")

    def enable_buttons(self):
        self.scan_button.config(state="normal")
        self.scan_online_button.config(state="normal")
        self.lookup_button.config(state="normal")
        self.clear_button.config(state="normal")

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberBLEApp(root)
    root.mainloop()