import asyncio
import json
import threading
import tkinter as tk
from tkinter import ttk, messagebox
from bleak import BleakScanner, BleakClient
import requests
import os
import time
import re
from datetime import datetime
import hashlib
import uuid
from tkinter import scrolledtext

def load_json(file):
    try:
        if os.path.exists(file):
            with open(file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                print(f"Loaded {file}: {len(data) if isinstance(data, dict) else 'N/A'} entries")
                return data
        else:
            print(f"File {file} not found")
            return {}
    except Exception as e:
        print(f"Failed to load {file}: {e}")
        return {}

    def clear_results(self):
        self.tree.delete(*self.tree.get_children())
        self.devices = {}
        self.continuous_scan_active = False
        self.continuous_scan_button.config(text="Continuous Scan")
        self.status_label.config(text="Results cleared. Ready for new scan.")

    def scan_error(self, error_msg):
        self.progress.stop()
        self.enable_buttons()
        self.continuous_scan_active = False
        self.continuous_scan_button.config(text="Continuous Scan")
        self.status_label.config(text=f"Scan error: {error_msg}")
        messagebox.showerror("Scan Error", f"Failed to scan BLE devices:\n{error_msg}")

    def disable_buttons(self, continuous=False):
        self.scan_button.config(state="disabled")
        self.scan_online_button.config(state="disabled")
        self.lookup_button.config(state="disabled")
        self.export_button.config(state="disabled")
        self.clear_button.config(state="disabled")
        self.connect_button.config(state="disabled")  
        self.disconnect_button.config(state="disabled")  
        if not continuous:
            self.continuous_scan_button.config(state="disabled")

    def enable_buttons(self):
        self.scan_button.config(state="normal")
        self.scan_online_button.config(state="normal")
        self.lookup_button.config(state="normal")
        self.export_button.config(state="normal")
        self.clear_button.config(state="normal")
        self.continuous_scan_button.config(state="normal")
        self.connect_button.config(state="normal")  
        self.disconnect_button.config(state="normal") 

VENDORS = load_json("mac_vendors.json")
MANUFACTURERS = load_json("manufacturer_ids.json")
SERVICES = load_json("service_uuids.json")

DEVICE_PATTERNS = {
    'Apple': ['iPhone', 'iPad', 'Mac', 'Apple', 'AirPods', 'Watch'],
    'Samsung': ['Galaxy', 'Samsung', 'SM-'],
    'Fitbit': ['Fitbit', 'Versa', 'Charge', 'Ionic'],
    'Garmin': ['Garmin', 'Forerunner', 'Edge', 'Fenix'],
    'Xiaomi': ['Mi ', 'Redmi', 'POCO', 'Xiaomi'],
    'Google': ['Pixel', 'Nest', 'Google'],
    'Tesla': ['Model S', 'Model 3', 'Model X', 'Model Y', 'Tesla'],
    'Tile': ['Tile'],
    'Microsoft': ['Surface', 'Xbox', 'Microsoft'],
    'Beats': ['Beats', 'Studio', 'Solo'],
    'JBL': ['JBL'],
    'Sony': ['Sony', 'WH-', 'WF-', 'SRS-'],
    'Bose': ['Bose', 'QuietComfort', 'SoundLink'],
    'Nintendo': ['Joy-Con', 'Pro Controller', 'Switch'],
    'Logitech': ['Logitech', 'MX ', 'K380', 'M705']
}

def get_vendor_local(mac):
    """Enhanced local vendor lookup with multiple formats"""
    if not mac or not VENDORS:
        return "Unknown"
    
    mac_clean = mac.replace(":", "").replace("-", "").upper()
    
    formats_to_try = [
        mac_clean[:6],   
        mac_clean[:8],   
        mac_clean[:9],   
        mac.upper()[:8], 
        mac.upper()[:9],
        mac.replace(":", "").replace("-", "").upper()[:6]
    ]
    
    for fmt in formats_to_try:
        if fmt in VENDORS:
            return VENDORS[fmt]
    
    return "Unknown"

def get_enhanced_vendor_online(mac):
    """Enhanced online vendor lookup using multiple APIs"""
    vendor_apis = [
        {
            'url': f"https://api.macvendors.com/{mac}",
            'name': 'MacVendors',
            'timeout': 3
        },
        {
            'url': f"https://www.macvendorlookup.com/api/v2/{mac}",
            'name': 'MacVendorLookup',
            'timeout': 4
        },
        {
            'url': f"https://api.maclookup.app/v2/macs/{mac}",
            'name': 'MacLookup',
            'timeout': 4
        }
    ]
    
    for api in vendor_apis:
        try:
            mac_clean = mac.replace("-", ":").upper()
            url = api['url'].replace(mac, mac_clean)
            
            response = requests.get(url, timeout=api['timeout'])
            
            if response.status_code == 200:
                data = response.text.strip()
                
                if api['name'] == 'MacVendors':
                    if data and data.lower() not in ["not found", "n/a", ""]:
                        return data
                elif api['name'] == 'MacVendorLookup':
                    try:
                        json_data = response.json()
                        if isinstance(json_data, list) and len(json_data) > 0:
                            return json_data[0].get('company', 'Unknown')
                    except:
                        pass
                elif api['name'] == 'MacLookup':
                    try:
                        json_data = response.json()
                        if json_data.get('found') and json_data.get('company'):
                            return json_data['company']
                    except:
                        pass
                        
        except requests.RequestException as e:
            print(f"API {api['name']} failed for {mac}: {e}")
            continue
    
    return "Unknown"

def detect_device_type(name, vendor, services, manufacturer_data):
    """Enhanced device type detection"""
    if not name:
        name = ""
    
    SPECIFIC_PATTERNS = {
        'Samsung': ['galaxy watch', 'galaxy buds', 'galaxy', 'samsung', 'sm-'],
        'Apple': ['iphone', 'ipad', 'mac', 'apple watch', 'airpods', 'apple'],
        'Fitbit': ['fitbit', 'versa', 'charge', 'ionic'],
        'Garmin': ['garmin', 'forerunner', 'edge', 'fenix'],
        'Xiaomi': ['mi ', 'redmi', 'poco', 'xiaomi'],
        'Google': ['pixel', 'nest', 'google'],
        'Tesla': ['model s', 'model 3', 'model x', 'model y', 'tesla'],
        'Tile': ['tile'],
        'Microsoft': ['surface', 'xbox', 'microsoft'],
        'Beats': ['beats', 'studio', 'solo'],
        'JBL': ['jbl'],
        'Sony': ['sony', 'wh-', 'wf-', 'srs-'],
        'Bose': ['bose', 'quietcomfort', 'soundlink'],
        'Nintendo': ['joy-con', 'pro controller', 'switch'],
        'Logitech': ['logitech', 'mx ', 'k380', 'm705']
    }
    
    for device_type, patterns in DEVICE_PATTERNS.items():
        for pattern in patterns:
            if pattern.lower() in name.lower():
                return device_type
    
    if vendor and vendor != "Unknown":
        vendor_lower = vendor.lower()
        for device_type, patterns in DEVICE_PATTERNS.items():
            if device_type.lower() in vendor_lower:
                return device_type
    
    if services and services != "N/A":
        services_lower = services.lower()
        if "human interface" in services_lower or "hid" in services_lower:
            return "Input Device"
        elif "heart rate" in services_lower:
            return "Fitness Tracker"
        elif "audio" in services_lower or "a2dp" in services_lower:
            return "Audio Device"
        elif "battery" in services_lower and "health" in services_lower:
            return "Health Device"
    
    return "Unknown Device"

def parse_manufacturer_data_enhanced(advertisement_data):
    """Enhanced manufacturer data parsing"""
    if not advertisement_data or not hasattr(advertisement_data, 'manufacturer_data'):
        return "N/A", {}
    
    if not advertisement_data.manufacturer_data:
        return "N/A", {}
    
    try:
        results = []
        detailed_info = {}
        
        for company_id, data in advertisement_data.manufacturer_data.items():
            hex_id = f"{company_id:04X}"
            
            manufacturer_name = "Unknown"
            if MANUFACTURERS:
                for key_format in [hex_id, hex_id.lower(), f"0x{hex_id}", f"0x{hex_id.lower()}"]:
                    if key_format in MANUFACTURERS:
                        manufacturer_name = MANUFACTURERS[key_format]
                        break
            
            data_hex = data.hex() if data else ""
            data_analysis = analyze_manufacturer_data(company_id, data)
            
            result_str = f"0x{hex_id} ({manufacturer_name})"
            results.append(result_str)
            
            detailed_info[hex_id] = {
                'name': manufacturer_name,
                'data': data_hex,
                'analysis': data_analysis
            }
        
        return ", ".join(results), detailed_info
    except Exception as e:
        print(f"Error parsing manufacturer data: {e}")
    
    return "N/A", {}

def analyze_manufacturer_data(company_id, data):
    """Analyze manufacturer-specific data for additional insights"""
    if not data:
        return "No data"
    
    data_hex = data.hex()
    
    if company_id == 0x004C:
        if len(data) >= 2:
            type_byte = data[0]
            if type_byte == 0x02:
                return "iBeacon"
            elif type_byte == 0x05:
                return "AirDrop"
            elif type_byte == 0x07:
                return "AirPods"
            elif type_byte == 0x09:
                return "AirPlay"
            elif type_byte == 0x10:
                return "Nearby"
    
    elif company_id == 0x0006:
        if len(data) >= 1:
            if data[0] == 0x01:
                return "Microsoft CDP"
    
    if len(data) == 2:
        return f"Short data: {data_hex}"
    elif len(data) >= 16:
        return f"Long data ({len(data)} bytes)"
    else:
        return f"Data ({len(data)} bytes): {data_hex[:16]}..."

def parse_services_enhanced(advertisement_data):
    """Enhanced service parsing with detailed information"""
    if not advertisement_data or not hasattr(advertisement_data, 'service_uuids'):
        return "N/A", {}
    
    if not advertisement_data.service_uuids:
        return "N/A", {}
    
    try:
        service_info = []
        detailed_services = {}
        
        for uuid in advertisement_data.service_uuids:
            uuid_str = str(uuid).lower()
            uuid_short = uuid_str[:8] if len(uuid_str) > 8 else uuid_str
            
            service_name = "Unknown Service"
            if SERVICES:
                for key_format in [uuid_str, uuid_str.upper(), uuid_short, uuid_str[:4]]:
                    if key_format in SERVICES:
                        service_name = SERVICES[key_format]
                        break
            
            if service_name == "Unknown Service":
                service_name = detect_common_service(uuid_str)
            
            service_display = f"{service_name} ({uuid_short})"
            service_info.append(service_display)
            
            detailed_services[uuid_str] = {
                'name': service_name,
                'uuid': uuid_str,
                'short_uuid': uuid_short
            }
        
        return ", ".join(service_info), detailed_services
    except Exception as e:
        print(f"Error parsing services: {e}")
    
    return "N/A", {}

def detect_common_service(uuid_str):
    """Detect common BLE services by UUID"""
    common_services = {
        '1800': 'Generic Access',
        '1801': 'Generic Attribute',
        '180a': 'Device Information',
        '180d': 'Heart Rate',
        '180f': 'Battery Service',
        '1812': 'Human Interface Device',
        '110a': 'Audio Source',
        '110b': 'Audio Sink',
        '1108': 'Headset',
        '111e': 'Handsfree',
        '1200': 'PnP Information'
    }
    
    short_uuid = uuid_str[:4]
    if short_uuid in common_services:
        return common_services[short_uuid]
    
    for uuid_pattern, service_name in common_services.items():
        if uuid_pattern in uuid_str:
            return service_name
    
    return "Unknown Service"

class CyberBLEApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberBLE - Advanced BLE Device Profiler")
        self.root.geometry("1100x870")
        self.root.resizable(True, True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", rowheight=30, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))
        style.configure("TButton", font=("Segoe UI", 10), padding=6)
        style.configure("TLabel", font=("Segoe UI", 10))
        style.configure("TProgressbar", thickness=8)

        self.devices = {}
        self.scan_start_time = None

        self.connected_devices = {}  
        self.connection_windows = {}  

        self.create_widgets()
        self.check_data_files()

        self.continuous_scan_active = False
        self.center_window()

    def center_window(self):
        """Center the main window on screen"""
        self.root.update_idletasks()  
        
        window_width = self.root.winfo_width()
        window_height = self.root.winfo_height()
        
        screen_width = self.root.winfo_screenwidth()
        screen_height = self.root.winfo_screenheight()
        
        center_x = int(screen_width/2 - window_width/2)
        center_y = int(screen_height/2 - window_height/2)
        
        self.root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

    def check_data_files(self):
        """Enhanced data file checking"""
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

        title_frame = ttk.Frame(self.root)
        title_frame.pack(pady=10)
        
        ttk.Label(title_frame, text="CyberBLE", 
                 font=("Segoe UI", 20, "bold")).pack()
        ttk.Label(title_frame, text="Advanced BLE Device Profiler & Analyzer", 
                 font=("Segoe UI", 11), foreground="gray").pack()

        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=15, pady=5)

        tree_frame = ttk.Frame(main_frame)
        tree_frame.pack(fill="both", expand=True)

        columns = ("MAC", "Name", "Type", "Vendor", "Manuf. ID", "Services", "RSSI", "Last Seen")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=18)

        column_widths = {
            "MAC": 130, "Name": 140, "Type": 100, "Vendor": 140, 
            "Manuf. ID": 130, "Services": 200, "RSSI": 60, "Last Seen": 80
        }
        
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

        self.tree.bind("<Double-1>", self.show_device_details)

        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill="x", pady=(10, 5))
        
        self.progress = ttk.Progressbar(progress_frame, mode="indeterminate")
        self.progress.pack(fill="x")
        
        self.status_label = ttk.Label(main_frame, text="Ready.")
        self.status_label.pack(pady=(0, 10))

        button_frame = ttk.Frame(main_frame)
        button_frame.pack(pady=5)

        scan_frame = ttk.Frame(button_frame)
        scan_frame.pack(pady=2)
        
        self.scan_button = ttk.Button(scan_frame, text="Quick Scan (Offline)", 
                                     command=self.start_scan_offline)
        self.scan_button.grid(row=0, column=0, padx=3)

        self.scan_online_button = ttk.Button(scan_frame, text="Deep Scan (Online)", 
                                           command=self.start_scan_online)
        self.scan_online_button.grid(row=0, column=1, padx=3)
        
        self.continuous_scan_button = ttk.Button(scan_frame, text="Continuous Scan", 
                                               command=self.start_continuous_scan)
        self.continuous_scan_button.grid(row=0, column=2, padx=3)

        action_frame = ttk.Frame(button_frame)
        action_frame.pack(pady=2)

        connection_frame = ttk.Frame(button_frame)
        connection_frame.pack(pady=2)

        self.connect_button = ttk.Button(connection_frame, text="Connect to Device", 
                                   command=self.connect_to_selected_device)
        self.connect_button.grid(row=0, column=0, padx=3)
        
        self.pair_button = ttk.Button(connection_frame, text="Pair Device", 
                                    command=self.pair_selected_device)
        self.pair_button.grid(row=0, column=1, padx=3)
        
        self.disconnect_button = ttk.Button(connection_frame, text="Disconnect All", 
                                        command=self.disconnect_all_devices)
        self.disconnect_button.grid(row=0, column=2, padx=3)
        
        power_frame = ttk.Frame(button_frame)
        power_frame.pack(pady=2)
        
        ttk.Label(power_frame, text="⚡ Power Controls:", 
                font=("Segoe UI", 9, "bold"), foreground="blue").pack(side="left", padx=2)
        
        self.power_off_button = ttk.Button(power_frame, text="Power Off Device", 
                                        command=self.power_off_selected_device)
        self.power_off_button.pack(side="left", padx=3)
        
        self.restart_button = ttk.Button(power_frame, text="Restart Device", 
                                    command=self.restart_selected_device)
        self.restart_button.pack(side="left", padx=3)
        
        self.sleep_button = ttk.Button(power_frame, text="Sleep Device", 
                                    command=self.sleep_selected_device)
        self.sleep_button.pack(side="left", padx=3)
        
        self.connect_button = ttk.Button(connection_frame, text="Connect to Device", 
                                       command=self.connect_to_selected_device)
        self.connect_button.grid(row=0, column=0, padx=3)
        
        self.lookup_button = ttk.Button(action_frame, text="Enhance Vendors", 
                                       command=self.lookup_online)
        self.lookup_button.grid(row=0, column=0, padx=3)

        self.export_button = ttk.Button(action_frame, text="Export Results", 
                                       command=self.export_results)
        self.export_button.grid(row=0, column=1, padx=3)

        self.clear_button = ttk.Button(action_frame, text="Clear Results", 
                                      command=self.clear_results)
        self.clear_button.grid(row=0, column=2, padx=3)

        copyright_frame = ttk.Frame(main_frame)
        copyright_frame.pack(side="bottom", pady=10)
        ttk.Label(copyright_frame, text="CyberBLE © 2025 by CyberNilsen", 
                 font=("Segoe UI", 9), foreground="gray").pack()
        ttk.Label(copyright_frame, text="Enhanced BLE Analysis & Device Profiling", 
                 font=("Segoe UI", 8), foreground="lightgray").pack()

        self.continuous_scan_active = False

    def explain_column(self, column):
        explanations = {
            "MAC": "The hardware address (Media Access Control) of the device.",
            "Name": "The advertised Bluetooth device name or detected identifier.",
            "Type": "Detected device type based on name, vendor, and services.",
            "Vendor": "The vendor/manufacturer based on MAC address lookup.",
            "Manuf. ID": "The manufacturer ID from the BLE advertisement data.",
            "Services": "BLE services advertised by the device.",
            "RSSI": "Received Signal Strength Indicator (signal strength in dBm).",
            "Last Seen": "Time when the device was last detected."
        }
        messagebox.showinfo(f"{column} Info", explanations.get(column, "No info available."))

    def show_device_details(self, event):
        """Show detailed device information"""
        selected = self.tree.selection()
        if not selected:
            return
        
        item = self.tree.item(selected[0])
        values = item['values']
        
        if len(values) < 6:
            return
        
        mac = values[0]
        details = f"Device Details for {mac}:\n\n"
        details += f"MAC Address: {values[0]}\n"
        details += f"Name: {values[1]}\n"
        details += f"Type: {values[2]}\n"
        details += f"Vendor: {values[3]}\n"
        details += f"Manufacturer ID: {values[4]}\n"
        details += f"Services: {values[5]}\n"
        details += f"RSSI: {values[6]}\n"
        details += f"Last Seen: {values[7]}\n"
        
        messagebox.showinfo("Device Details", details)

    def start_scan_offline(self):
        self.start_scan(online_lookup=False, continuous=False)

    def start_scan_online(self):
        self.start_scan(online_lookup=True, continuous=False)
        
    def start_continuous_scan(self):
        if self.continuous_scan_active:

            self.continuous_scan_active = False
            self.continuous_scan_button.config(text="Continuous Scan")
            self.progress.stop()  
            self.enable_buttons()
            self.status_label.config(text="Continuous scan stopped.")
        else:

            self.start_scan(online_lookup=False, continuous=True)

    def start_scan(self, online_lookup=False, continuous=False):
        if continuous:
            self.continuous_scan_active = True
            self.continuous_scan_button.config(text="Stop Continuous")
        
        self.disable_buttons(continuous)
        if not continuous:
            self.tree.delete(*self.tree.get_children())
        
        self.progress.start()
        self.scan_start_time = time.time()
        
        scan_type = "continuous" if continuous else ("deep online" if online_lookup else "quick offline")
        self.status_label.config(text=f"Scanning BLE devices ({scan_type})...")

        threading.Thread(target=self.run_scan, args=(online_lookup, continuous)).start()

    def run_scan(self, online_lookup=False, continuous=False):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            if continuous:
                self.run_continuous_scan(loop, online_lookup)
            else:
                devices = loop.run_until_complete(self.scan_devices_enhanced())
                self.root.after(0, lambda: self.update_tree(devices, online_lookup))
        except Exception as e:
            self.root.after(0, lambda: self.scan_error(str(e)))
        finally:
            loop.close()

    def run_continuous_scan(self, loop, online_lookup):
        """Run continuous scanning"""
        scan_count = 0
        while self.continuous_scan_active:
            try:
                scan_count += 1
                devices = loop.run_until_complete(self.scan_devices_enhanced())
                self.root.after(0, lambda d=devices, ol=online_lookup, sc=scan_count: 
                          self.update_tree_continuous(d, ol, sc))
            
                if self.continuous_scan_active:
                    time.sleep(2)  
            except Exception as e:
                print(f"Continuous scan error: {e}")

                self.root.after(0, lambda: self.stop_continuous_scan_on_error(str(e)))
                break

    def stop_continuous_scan_on_error(self, error_msg):
        """Stop continuous scan due to error"""
        self.continuous_scan_active = False
        self.continuous_scan_button.config(text="Continuous Scan")
        self.progress.stop()
        self.enable_buttons()
        self.status_label.config(text=f"Continuous scan stopped due to error: {error_msg}")       

    async def scan_devices_enhanced(self):
        """Enhanced device scanning with better timeout and error handling"""
        try:
            print("Starting enhanced BLE scan...")

            devices = await BleakScanner.discover(timeout=12.0, return_adv=True)
            print(f"Found {len(devices)} devices")
            return devices
        except Exception as e:
            print(f"Enhanced scan error: {e}")
            raise

    def update_tree(self, devices, online_lookup=False):
        self.progress.stop()
        if not self.continuous_scan_active:
            self.enable_buttons()
        
        self.devices = devices
        device_count = len(devices)
        
        if device_count == 0:
            self.status_label.config(text="No BLE devices found. Try moving closer to devices or checking Bluetooth adapter.")
            return
        
        self.status_label.config(text=f"Processing {device_count} device(s)...")
        
        processed = 0
        for device, adv in devices.values():
            self.process_single_device(device, adv, online_lookup)
            processed += 1
            
            if processed % 3 == 0:
                self.status_label.config(text=f"Processed {processed}/{device_count} devices...")
                self.root.update()

        scan_time = time.time() - self.scan_start_time if self.scan_start_time else 0
        scan_type = "deep online" if online_lookup else "quick offline"
        self.status_label.config(text=f"Scan complete ({scan_type}). {device_count} device(s) found in {scan_time:.1f}s.")

    def update_tree_continuous(self, devices, online_lookup, scan_count):
        """Update tree for continuous scanning"""
        if not self.continuous_scan_active:  
            return
        
        current_time = datetime.now().strftime("%H:%M:%S")
        new_devices = 0
    
        for device, adv in devices.values():
            mac = device.address or "Unknown"
            existing_item = self.find_device_in_tree(mac)
        
            if existing_item:

                values = list(self.tree.item(existing_item, "values"))
                old_rssi = values[6]
                new_rssi = str(getattr(adv, 'rssi', 'N/A'))
            
                values[6] = new_rssi  
                values[7] = current_time  
                self.tree.item(existing_item, values=values)
            else:
                
                self.process_single_device(device, adv, online_lookup, current_time)
                new_devices += 1
    
        total_devices = len(self.tree.get_children())
        status_text = f"Continuous scan #{scan_count} - {total_devices} devices tracked"
        if new_devices > 0:
            status_text += f" (+{new_devices} new)"
    
        self.status_label.config(text=status_text)

    def find_device_in_tree(self, mac):
        """Find device in tree by MAC address"""
        for child in self.tree.get_children():
            values = self.tree.item(child, "values")
            if values and values[0] == mac:
                return child
        return None

    def process_single_device(self, device, adv, online_lookup, current_time=None):
        """Process a single device and add to tree"""
        mac = device.address or "Unknown"
        
        device_name = device.name
        if not device_name or device_name.strip() == "":
            manuf_info, _ = parse_manufacturer_data_enhanced(adv)
            if manuf_info != "N/A" and "(" in manuf_info:
                manuf_name = manuf_info.split("(")[1].split(")")[0]
                if manuf_name != "Unknown":
                    device_name = f"[{manuf_name} Device]"
                else:
                    device_name = "[Unnamed Device]"
            else:
                device_name = "[Unknown Device]"
        
        if online_lookup:
            vendor = get_enhanced_vendor_online(mac)
            if vendor == "Unknown":
                vendor = get_vendor_local(mac)
        else:
            vendor = get_vendor_local(mac)
        
        manuf_info, _ = parse_manufacturer_data_enhanced(adv)
        services_info, _ = parse_services_enhanced(adv)
        device_type = detect_device_type(device_name, vendor, services_info, manuf_info)
        rssi = getattr(adv, 'rssi', 'N/A')
        last_seen = current_time or datetime.now().strftime("%H:%M:%S")
        
        self.tree.insert("", "end", values=(
            mac, device_name, device_type, vendor, manuf_info, services_info, rssi, last_seen
        ))

    def lookup_online(self):
        """Enhanced online lookup with better progress tracking"""
        if not self.tree.get_children():
            messagebox.showwarning("No Data", "Please scan for devices first.")
            return

        self.disable_buttons()
        self.status_label.config(text="Enhancing vendor information...")
        self.progress.start()

        def task():
            total_items = len(self.tree.get_children())
            processed = 0
            updated = 0
            
            for child in self.tree.get_children():
                values = list(self.tree.item(child, "values"))
                mac = values[0]
                current_vendor = values[3]
                
                if current_vendor == "Unknown" or "Unknown" in current_vendor:
                    enhanced_vendor = get_enhanced_vendor_online(mac)
                    if enhanced_vendor != "Unknown":
                        values[3] = enhanced_vendor

                        values[2] = detect_device_type(values[1], enhanced_vendor, values[5], values[4])
                        self.root.after(0, lambda c=child, v=values: self.tree.item(c, values=v))
                        updated += 1
                
                processed += 1
                if processed % 2 == 0:
                    self.root.after(0, lambda p=processed, t=total_items, u=updated: 
                                   self.status_label.config(text=f"Enhancing... {p}/{t} ({u} updated)"))
                
                time.sleep(0.5)  
            
            self.root.after(0, lambda u=updated: self.finish_lookup(u))

        threading.Thread(target=task).start()

    def finish_lookup(self, updated_count):
        self.progress.stop()
        self.enable_buttons()
        self.status_label.config(text=f"Enhanced vendor lookup complete. {updated_count} devices updated.")


    def export_results(self):
        """Export scan results to JSON file"""
        if not self.tree.get_children():
            messagebox.showwarning("No Data", "No devices to export.")
            return
        
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"cyberble_scan_{timestamp}.json"
            
            export_data = {
                'scan_info': {
                    'timestamp': datetime.now().isoformat(),
                    'device_count': len(self.tree.get_children()),
                    'tool': 'CyberBLE'
                },
                'devices': []
            }
            
            for child in self.tree.get_children():
                values = self.tree.item(child, "values")
                device_data = {
                    'mac': values[0],
                    'name': values[1],
                    'type': values[2],
                    'vendor': values[3],
                    'manufacturer_id': values[4],
                    'services': values[5],
                    'rssi': values[6],
                    'last_seen': values[7]
                }
                export_data['devices'].append(device_data)
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            messagebox.showinfo("Export Complete", f"Results exported to {filename}")
            self.status_label.config(text=f"Results exported to {filename}")
            
        except Exception as e:
            messagebox.showerror("Export Error", f"Failed to export results:\n{str(e)}")

    def clear_results(self):
        self.tree.delete(*self.tree.get_children())
        self.devices = {}
        self.continuous_scan_active = False
        self.continuous_scan_button.config(text="Continuous Scan")
        self.status_label.config(text="Results cleared. Ready for new scan.")

    def scan_error(self, error_msg):
        self.progress.stop()
        self.enable_buttons()
        self.continuous_scan_active = False
        self.continuous_scan_button.config(text="Continuous Scan")
        self.status_label.config(text=f"Scan error: {error_msg}")
        messagebox.showerror("Scan Error", f"Failed to scan BLE devices:\n{error_msg}")

    def disable_buttons(self, continuous=False):
        self.scan_button.config(state="disabled")
        self.scan_online_button.config(state="disabled")
        self.lookup_button.config(state="disabled")
        self.export_button.config(state="disabled")
        self.clear_button.config(state="disabled")
        if not continuous:
            self.continuous_scan_button.config(state="disabled")

    def enable_buttons(self):
        self.scan_button.config(state="normal")
        self.scan_online_button.config(state="normal")
        self.lookup_button.config(state="normal")
        self.export_button.config(state="normal")
        self.clear_button.config(state="normal")
        self.continuous_scan_button.config(state="normal")


    def connect_to_selected_device(self):
        """Connect to the selected device in the tree"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a device to connect to.")
            return
        
        item = self.tree.item(selected[0])
        values = item['values']
        if len(values) < 2:
            return
        
        mac = values[0]
        name = values[1]
        
        if mac in self.connected_devices:
            messagebox.showinfo("Already Connected", f"Already connected to {name} ({mac})")
            return
        
        # Show security warning
        warning_msg = (
            "⚠️ SECURITY WARNING ⚠️\n\n"
            "Only connect to devices you own or have explicit permission to access.\n"
            "Unauthorized device access may be illegal.\n\n"
            f"Device: {name}\n"
            f"MAC: {mac}\n\n"
            "Do you want to proceed with the connection?"
        )
        
        if not messagebox.askyesno("Connection Warning", warning_msg):
            return
        
        self.status_label.config(text=f"Connecting to {name}...")
        self.disable_buttons()
        
        threading.Thread(target=self.perform_connection, args=(mac, name)).start()

    def perform_connection(self, mac, name):
        """Perform the actual BLE connection"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(self.connect_device_async(mac, name))
            self.root.after(0, lambda: self.connection_result(result, mac, name))
        except Exception as e:
            self.root.after(0, lambda: self.connection_error(str(e), mac, name))
        finally:
            loop.close()

    async def connect_device_async(self, mac, name):
        """Async function to connect to BLE device with better error handling"""
        client = None
        try:
            client = BleakClient(mac)
        
            await asyncio.wait_for(client.connect(), timeout=15.0)
        
            if client.is_connected:
                try:
                    services = await client.get_services()
                    services_list = list(services)
                except Exception as e:
                    print(f"Error getting services: {e}")
                    services_list = []
            
                device_info = {
                    'client': client,
                    'name': name,
                    'mac': mac,
                    'services': services_list,
                    'connected_at': datetime.now()
                }
            
                return {'success': True, 'device_info': device_info}
            else:
                if client:
                    try:
                        await client.disconnect()
                    except:
                        pass
                return {'success': False, 'error': 'Failed to establish connection'}
            
        except asyncio.TimeoutError:
            if client:
                try:
                    await client.disconnect()
                except:
                    pass
            return {'success': False, 'error': 'Connection timeout'}
        except Exception as e:
            if client:
                try:
                    await client.disconnect()
                except:
                    pass
            return {'success': False, 'error': str(e)}

    def connection_result(self, result, mac, name):
        """Handle connection result"""
        self.enable_buttons()
        
        if result['success']:
            device_info = result['device_info']
            self.connected_devices[mac] = device_info
            self.status_label.config(text=f"Connected to {name} ({mac})")
            
            self.show_connection_window(device_info)
            
            messagebox.showinfo("Connection Success", f"Successfully connected to {name}")
        else:
            self.status_label.config(text=f"Failed to connect to {name}")
            messagebox.showerror("Connection Failed", f"Failed to connect to {name}:\n{result['error']}")

    def connection_error(self, error_msg, mac, name):
        """Handle connection error"""
        self.enable_buttons()
        self.status_label.config(text=f"Connection error: {error_msg}")
        messagebox.showerror("Connection Error", f"Failed to connect to {name}:\n{error_msg}")

    def show_connection_window(self, device_info):
        """Enhanced connection window with more interactive features"""
        mac = device_info['mac']
        name = device_info['name']
        
        if mac in self.connection_windows:
            self.connection_windows[mac].lift()
            return
        
        conn_window = tk.Toplevel(self.root)
        conn_window.title(f"Connected: {name} ({mac})")
        conn_window.geometry("700x600")
        conn_window.resizable(True, True)
        
        self.connection_windows[mac] = conn_window
        
        def on_window_close():
            if mac in self.connection_windows:
                del self.connection_windows[mac]
            conn_window.destroy()
        
        conn_window.protocol("WM_DELETE_WINDOW", on_window_close)
        
        title_frame = ttk.Frame(conn_window)
        title_frame.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(title_frame, text=f"Device: {name}", 
                font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(title_frame, text=f"MAC: {mac}", 
                font=("Segoe UI", 10)).pack(anchor="w")
        ttk.Label(title_frame, text=f"Connected: {device_info['connected_at'].strftime('%H:%M:%S')}", 
                font=("Segoe UI", 9), foreground="green").pack(anchor="w")
        
        control_frame = ttk.Frame(conn_window)
        control_frame.pack(fill="x", padx=10, pady=5)
        
        row1_frame = ttk.Frame(control_frame)
        row1_frame.pack(fill="x", pady=2)
        
        ttk.Button(row1_frame, text="Read Device Info", 
                command=lambda: self.read_device_info(mac)).pack(side="left", padx=2)
        ttk.Button(row1_frame, text="Scan Services", 
                command=lambda: self.scan_device_services(mac)).pack(side="left", padx=2)
        ttk.Button(row1_frame, text="Read Battery", 
                command=lambda: self.read_battery_level(mac)).pack(side="left", padx=2)
        ttk.Button(row1_frame, text="Disconnect", 
                command=lambda: self.disconnect_device(mac)).pack(side="left", padx=2)
        
        row2_frame = ttk.Frame(control_frame)
        row2_frame.pack(fill="x", pady=2)
        
        ttk.Button(row2_frame, text="Read All Characteristics", 
                command=lambda: self.read_all_characteristics(mac)).pack(side="left", padx=2)
        ttk.Button(row2_frame, text="Monitor Notifications", 
                command=lambda: self.start_notifications(mac)).pack(side="left", padx=2)
        ttk.Button(row2_frame, text="Send Custom Command", 
                command=lambda: self.send_custom_command(mac)).pack(side="left", padx=2)
        
        security_frame = ttk.Frame(control_frame)
        security_frame.pack(fill="x", pady=2)
        
        ttk.Label(security_frame, text="🔐 Security & Analysis:", 
                font=("Segoe UI", 9, "bold"), foreground="purple").pack(side="left", padx=2)
        ttk.Button(security_frame, text="Security Scan", 
                command=lambda: self.perform_security_scan(mac)).pack(side="left", padx=2)
        ttk.Button(security_frame, text="Vulnerability Check", 
                command=lambda: self.check_vulnerabilities(mac)).pack(side="left", padx=2)
        ttk.Button(security_frame, text="Encryption Status", 
                command=lambda: self.check_encryption_status(mac)).pack(side="left", padx=2)

        row3_frame = ttk.Frame(control_frame)
        row3_frame.pack(fill="x", pady=2)
        
        ttk.Label(row3_frame, text="⚠️ Advanced Controls:", 
                font=("Segoe UI", 9, "bold"), foreground="red").pack(side="left", padx=2)
        ttk.Button(row3_frame, text="Find Device (Vibrate/Beep)", 
                command=lambda: self.trigger_find_device(mac)).pack(side="left", padx=2)
        ttk.Button(row3_frame, text="Reset Connection", 
                command=lambda: self.reset_device_connection(mac)).pack(side="left", padx=2)
        
        service_frame = ttk.LabelFrame(conn_window, text="Quick Service Access")
        service_frame.pack(fill="x", padx=10, pady=5)
        
        service_list_frame = ttk.Frame(service_frame)
        service_list_frame.pack(fill="x", padx=5, pady=5)
        
        ttk.Label(service_list_frame, text="Select Service:").pack(side="left", padx=2)
        service_var = tk.StringVar()
        service_combo = ttk.Combobox(service_list_frame, textvariable=service_var, 
                                    width=40, state="readonly")
        service_combo.pack(side="left", padx=5, fill="x", expand=True)
        
        ttk.Button(service_list_frame, text="Interact", 
                command=lambda: self.interact_with_service(mac, service_var.get())).pack(side="left", padx=2)
        
        self.populate_service_combo(mac, service_combo)
        
        data_frame = ttk.Frame(conn_window)
        data_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        ttk.Label(data_frame, text="Device Data & Logs:", font=("Segoe UI", 10, "bold")).pack(anchor="w")
        
        data_text = scrolledtext.ScrolledText(data_frame, height=20, width=80, 
                                            font=("Consolas", 9))
        data_text.pack(fill="both", expand=True)
        
        device_info['data_widget'] = data_text
        device_info['service_combo'] = service_combo
        
        initial_data = f"🔗 Connected to: {name} ({mac})\n"
        initial_data += f"⏰ Connection time: {device_info['connected_at']}\n"
        initial_data += f"🔧 Services found: {len(list(device_info['services']))}\n\n"
        initial_data += "💡 Use the buttons above to interact with the device.\n"
        initial_data += "⚠️  Only read data from devices you own - avoid writing to unknown characteristics!\n"
        initial_data += "🚀 Try 'Read All Characteristics' to discover what the device can do.\n\n"
        
        data_text.insert(tk.END, initial_data)

    def perform_security_scan(self, mac):
        """Perform security analysis of connected device"""
        if mac not in self.connected_devices:
            return
        
        self.display_device_info(mac, ["🔐 Starting security scan..."])
        threading.Thread(target=self.security_scan_thread, args=(mac,)).start()

    def security_scan_thread(self, mac):
        """Security scan background thread"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(self.security_scan_async(mac))
            self.root.after(0, lambda: self.display_device_info(mac, result))
        except Exception as e:
            self.root.after(0, lambda: self.display_error(mac, f"Security scan error: {str(e)}"))
        finally:
            loop.close()

    async def security_scan_async(self, mac):
        """Async security scanning"""
        device_info = self.connected_devices[mac]
        client = device_info['client']
        services = device_info['services']
        
        results = []
        results.append("🔐 === SECURITY ANALYSIS ===")
        
        open_chars = 0
        protected_chars = 0
        
        for service in services:
            for char in service.characteristics:
                if "read" in char.properties:
                    try:
                        await client.read_gatt_char(char.uuid)
                        open_chars += 1
                    except Exception as e:
                        if "authentication" in str(e).lower() or "authorization" in str(e).lower():
                            protected_chars += 1
        
        results.append(f"📊 Open characteristics: {open_chars}")
        results.append(f"🔒 Protected characteristics: {protected_chars}")
        
        vulnerable_services = [
            ("00001800-0000-1000-8000-00805f9b34fb", "Generic Access - Often unprotected"),
            ("0000180a-0000-1000-8000-00805f9b34fb", "Device Info - May leak device details"),
            ("6e400001-b5a3-f393-e0a9-e50e24dcca9e", "Nordic UART - Debug interface risk"),
        ]
        
        results.append("\n🚨 Potential Security Issues:")
        for vuln_uuid, description in vulnerable_services:
            for service in services:
                if vuln_uuid.lower() in str(service.uuid).lower():
                    results.append(f"  ⚠️ {description}")
        
        return results

    def check_vulnerabilities(self, mac):
        """Check for known BLE vulnerabilities"""
        if mac not in self.connected_devices:
            return
        
        device_info = self.connected_devices[mac]
        
        vulns = []
        vulns.append("🕵️ === VULNERABILITY CHECK ===")
        vulns.append("Checking for known BLE attack vectors...")
        vulns.append("")
        vulns.append("⚠️ BLEEDINGBIT: Check if device firmware is updated")
        vulns.append("⚠️ BLUEBORNE: Verify Bluetooth stack security")
        vulns.append("⚠️ SWEYNTOOTH: Nordic/TI chipset vulnerabilities")
        vulns.append("⚠️ BRAKTOOTH: Baseband firmware issues")
        vulns.append("")
        vulns.append("💡 Recommendations:")
        vulns.append("  • Keep device firmware updated")
        vulns.append("  • Use strong pairing mechanisms")
        vulns.append("  • Implement proper authentication")
        vulns.append("  • Monitor for unauthorized connections")
        
        self.display_device_info(mac, vulns)

    def check_encryption_status(self, mac):
        """Check encryption and security status"""
        if mac not in self.connected_devices:
            return
        
        enc_info = []
        enc_info.append("🔐 === ENCRYPTION STATUS ===")
        enc_info.append("ℹ️ BLE Security Levels:")
        enc_info.append("  • Level 1: No authentication/encryption")
        enc_info.append("  • Level 2: Unauthenticated pairing")
        enc_info.append("  • Level 3: Authenticated pairing")
        enc_info.append("  • Level 4: Authenticated LE Secure Connections")
        enc_info.append("")
        enc_info.append("🔍 Current Connection:")
        enc_info.append("  • Connection appears active")
        enc_info.append("  • Encryption status: Unknown (requires deeper analysis)")
        enc_info.append("  • Recommend using specialized BLE security tools")
        
        self.display_device_info(mac, enc_info)

    def populate_service_combo(self, mac, combo):
        """Populate the service combobox with available services"""
        if mac not in self.connected_devices:
            return
        
        device_info = self.connected_devices[mac]
        services = device_info['services']
        
        service_list = []
        for service in services:
            service_name = self.get_service_name(str(service.uuid))
            service_list.append(f"{service_name} ({str(service.uuid)[:8]}...)")
        
        combo['values'] = service_list

    def get_service_name(self, uuid):
        """Get human-readable service name"""
        uuid_lower = uuid.lower()
        
        common_services = {
            '1800': 'Generic Access',
            '1801': 'Generic Attribute', 
            '180a': 'Device Information',
            '180d': 'Heart Rate',
            '180f': 'Battery Service',
            '1812': 'Human Interface Device',
            '1816': 'Cycling Speed and Cadence',
            '181a': 'Environmental Sensing',
            '181c': 'User Data',
            '181d': 'Weight Scale',
            '1826': 'Fitness Machine',
            'fef5': 'Google Fast Pair',
            '6e400001': 'Nordic UART Service'
        }
        
        for short_uuid, name in common_services.items():
            if short_uuid in uuid_lower:
                return name
        
        return "Unknown Service"
    
    def read_battery_level(self, mac):
        """Read battery level if available"""
        if mac not in self.connected_devices:
            return
        
        self.display_device_info(mac, ["🔋 Reading battery level..."])
        threading.Thread(target=self.perform_battery_read, args=(mac,)).start()

    def perform_battery_read(self, mac):
        """Perform battery level reading"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(self.read_battery_async(mac))
            self.root.after(0, lambda: self.display_device_info(mac, result))
        except Exception as e:
            self.root.after(0, lambda: self.display_error(mac, f"Battery read error: {str(e)}"))
        finally:
            loop.close()

    async def read_battery_async(self, mac):
        """Async battery level reading"""
        device_info = self.connected_devices[mac]
        client = device_info['client']
        
        BATTERY_SERVICE = "0000180f-0000-1000-8000-00805f9b34fb"
        BATTERY_LEVEL_CHAR = "00002a19-0000-1000-8000-00805f9b34fb"
        
        try:
            battery_value = await client.read_gatt_char(BATTERY_LEVEL_CHAR)
            battery_percent = int.from_bytes(battery_value, byteorder='little')
            return [f"🔋 Battery Level: {battery_percent}%"]
        except Exception as e:
            return [f"🔋 Battery service not available or not readable: {str(e)}"]
        
        
    def read_all_characteristics(self, mac):
        """Read all readable characteristics"""
        if mac not in self.connected_devices:
            return
        
        self.display_device_info(mac, ["📖 Reading all characteristics... (this may take a while)"])
        threading.Thread(target=self.perform_read_all_characteristics, args=(mac,)).start()

    def perform_read_all_characteristics(self, mac):
        """Perform reading of all characteristics"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(self.read_all_characteristics_async(mac))
            self.root.after(0, lambda: self.display_device_info(mac, result))
        except Exception as e:
            self.root.after(0, lambda: self.display_error(mac, f"Read all characteristics error: {str(e)}"))
        finally:
            loop.close()

    async def read_all_characteristics_async(self, mac):
        """Async function to read all characteristics"""
        device_info = self.connected_devices[mac]
        client = device_info['client']
        services = device_info['services']
        
        results = []
        results.append("📖 === READING ALL CHARACTERISTICS ===")
        readable_count = 0
        total_count = 0
        
        for service in services:
            service_name = self.get_service_name(str(service.uuid))
            results.append(f"\n🔧 Service: {service_name}")
            results.append(f"   UUID: {service.uuid}")
            
            for char in service.characteristics:
                total_count += 1
                char_name = f"Characteristic {str(char.uuid)[:8]}..."
                
                if "read" in char.properties:
                    try:
                        value = await client.read_gatt_char(char.uuid)
                        readable_count += 1
                        
                        try:
                            text_value = value.decode('utf-8', errors='ignore').strip()
                            if text_value and all(ord(c) < 127 for c in text_value):
                                results.append(f"   ✅ {char_name}: '{text_value}'")
                            else:
                                raise UnicodeDecodeError("Not text", b"", 0, 0, "")
                        except UnicodeDecodeError:
                            hex_value = value.hex()
                            if len(hex_value) > 32:
                                hex_value = hex_value[:32] + "..."
                            results.append(f"   ✅ {char_name}: {hex_value} (hex)")
                            
                            if len(value) <= 4:
                                try:
                                    int_value = int.from_bytes(value, byteorder='little')
                                    results.append(f"      💡 As integer: {int_value}")
                                except:
                                    pass
                                    
                    except Exception as e:
                        results.append(f"   ❌ {char_name}: Error - {str(e)}")
                else:
                    properties = ", ".join(char.properties)
                    results.append(f"   ⚪ {char_name}: Not readable ({properties})")
        
        results.append(f"\n📊 Summary: {readable_count}/{total_count} characteristics read successfully")
        return results

    def start_notifications(self, mac):
        """Start monitoring notifications from the device"""
        if mac not in self.connected_devices:
            return
        
        self.display_device_info(mac, ["🔔 Starting notification monitoring..."])
        threading.Thread(target=self.perform_notification_monitoring, args=(mac,)).start()

    def perform_notification_monitoring(self, mac):
        """Perform notification monitoring"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            loop.run_until_complete(self.monitor_notifications_async(mac))
        except Exception as e:
            self.root.after(0, lambda: self.display_error(mac, f"Notification monitoring error: {str(e)}"))
        finally:
            loop.close()

    async def monitor_notifications_async(self, mac):
        """Async notification monitoring"""
        device_info = self.connected_devices[mac]
        client = device_info['client']
        services = device_info['services']
        
        def notification_handler(characteristic, data):
            timestamp = datetime.now().strftime("%H:%M:%S")
            char_uuid = str(characteristic.uuid)[:8]
            
            try:
                text_data = data.decode('utf-8', errors='ignore')
                message = f"🔔 [{timestamp}] {char_uuid}...: '{text_data}'"
            except:
                hex_data = data.hex()
                message = f"🔔 [{timestamp}] {char_uuid}...: {hex_data} (hex)"
            
            self.root.after(0, lambda: self.display_device_info(mac, [message]))
        
        notification_count = 0
        
        for service in services:
            for char in service.characteristics:
                if "notify" in char.properties or "indicate" in char.properties:
                    try:
                        await client.start_notify(char.uuid, notification_handler)
                        notification_count += 1
                        self.root.after(0, lambda c=char: self.display_device_info(mac, 
                            [f"✅ Subscribed to notifications: {str(c.uuid)[:8]}..."]))
                    except Exception as e:
                        self.root.after(0, lambda c=char, e=e: self.display_device_info(mac,
                            [f"❌ Failed to subscribe to {str(c.uuid)[:8]}...: {str(e)}"]))
        
        if notification_count > 0:
            self.root.after(0, lambda: self.display_device_info(mac, 
                [f"🔔 Monitoring {notification_count} notification sources. Data will appear below..."]))
            
            await asyncio.sleep(60)
            
            self.root.after(0, lambda: self.display_device_info(mac, 
                ["⏰ Notification monitoring stopped after 60 seconds."]))
        else:
            self.root.after(0, lambda: self.display_device_info(mac, 
                ["ℹ️ No notification-capable characteristics found on this device."]))

    def trigger_find_device(self, mac):
        """Trigger find device function (vibrate/beep)"""
        if mac not in self.connected_devices:
            return
        
        warning = messagebox.askyesno("Find Device", 
            "This will attempt to make the device vibrate, beep, or flash.\n"
            "Only proceed if you own this device.\n\n"
            "Continue?")
        
        if not warning:
            return
        
        self.display_device_info(mac, ["🔍 Attempting to trigger find device..."])
        threading.Thread(target=self.perform_find_device, args=(mac,)).start()

    def perform_find_device(self, mac):
        """Perform find device operation"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(self.find_device_async(mac))
            self.root.after(0, lambda: self.display_device_info(mac, result))
        except Exception as e:
            self.root.after(0, lambda: self.display_error(mac, f"Find device error: {str(e)}"))
        finally:
            loop.close()

    async def find_device_async(self, mac):
        """Async find device function"""
        device_info = self.connected_devices[mac]
        client = device_info['client']
        services = device_info['services']
        
        find_service_uuids = [
            "00001802-0000-1000-8000-00805f9b34fb",  
            "0000180f-0000-1000-8000-00805f9b34fb",  
        ]
        
        alert_char_uuids = [
            "00002a06-0000-1000-8000-00805f9b34fb",  
            "00002a44-0000-1000-8000-00805f9b34fb",  
        ]
        
        results = []
        
        for char_uuid in alert_char_uuids:
            try:
                await client.write_gatt_char(char_uuid, bytes([2]))  # High alert
                results.append(f"✅ Find device signal sent via {char_uuid[:8]}...")
                await asyncio.sleep(0.5)
                # Turn off alert
                await client.write_gatt_char(char_uuid, bytes([0]))
                results.append("🔇 Alert turned off")
                return results
            except Exception as e:
                results.append(f"❌ Alert attempt failed for {char_uuid[:8]}...: {str(e)}")
        
        results.append("🔍 Trying alternative find methods...")
        
        for service in services:
            for char in service.characteristics:
                if "write" in char.properties:
                    try:
                        await client.write_gatt_char(char.uuid, bytes([1, 0, 1, 0, 1]))
                        results.append(f"✅ Pattern sent to {str(char.uuid)[:8]}...")
                        await asyncio.sleep(0.1)
                        break
                    except:
                        continue
        
        if len(results) <= 1:
            results.append("❌ No find device capability detected on this device")
        
        return results

    def send_custom_command(self, mac):
        """Send a custom command to the device"""
        if mac not in self.connected_devices:
            return
        
        custom_window = tk.Toplevel(self.root)
        custom_window.title("Send Custom Command")
        custom_window.geometry("400x300")
        custom_window.transient(self.root)
        custom_window.grab_set()
        
        ttk.Label(custom_window, text="⚠️ WARNING: Only send commands to devices you own!", 
                font=("Segoe UI", 10, "bold"), foreground="red").pack(pady=10)
        
        ttk.Label(custom_window, text="Characteristic UUID:").pack(anchor="w", padx=10)
        uuid_entry = ttk.Entry(custom_window, width=50)
        uuid_entry.pack(fill="x", padx=10, pady=5)
        
        ttk.Label(custom_window, text="Data (hex format, e.g., 01FF02):").pack(anchor="w", padx=10)
        data_entry = ttk.Entry(custom_window, width=50)
        data_entry.pack(fill="x", padx=10, pady=5)
        
        def send_command():
            uuid = uuid_entry.get().strip()
            data_hex = data_entry.get().strip()
            
            if not uuid or not data_hex:
                messagebox.showerror("Error", "Please enter both UUID and data")
                return
            
            try:
                data_bytes = bytes.fromhex(data_hex)
                custom_window.destroy()
                self.execute_custom_command(mac, uuid, data_bytes)
            except ValueError:
                messagebox.showerror("Error", "Invalid hex data format")
        
        button_frame = ttk.Frame(custom_window)
        button_frame.pack(pady=20)
        
        ttk.Button(button_frame, text="Send Command", command=send_command).pack(side="left", padx=5)
        ttk.Button(button_frame, text="Cancel", command=custom_window.destroy).pack(side="left", padx=5)

    def execute_custom_command(self, mac, uuid, data):
        """Execute the custom command"""
        self.display_device_info(mac, [f"📤 Sending custom command to {uuid[:8]}...: {data.hex()}"])
        threading.Thread(target=self.perform_custom_command, args=(mac, uuid, data)).start()

    def perform_custom_command(self, mac, uuid, data):
        """Perform custom command execution"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(self.custom_command_async(mac, uuid, data))
            self.root.after(0, lambda: self.display_device_info(mac, result))
        except Exception as e:
            self.root.after(0, lambda: self.display_error(mac, f"Custom command error: {str(e)}"))
        finally:
            loop.close()

    async def custom_command_async(self, mac, uuid, data):
        """Async custom command execution"""
        device_info = self.connected_devices[mac]
        client = device_info['client']
        
        try:
            await client.write_gatt_char(uuid, data)
            return [f"✅ Custom command sent successfully to {uuid[:8]}..."]
        except Exception as e:
            return [f"❌ Custom command failed: {str(e)}"]

    def interact_with_service(self, mac, service_selection):
        """Interact with a selected service"""
        if not service_selection or mac not in self.connected_devices:
            return
        
        uuid_part = service_selection.split("(")[1].split(")")[0]
        
        device_info = self.connected_devices[mac]
        services = device_info['services']
        
        selected_service = None
        for service in services:
            if str(service.uuid).startswith(uuid_part):
                selected_service = service
                break
        
        if not selected_service:
            self.display_error(mac, "Selected service not found")
            return
        
        results = []
        results.append(f"🔧 Interacting with service: {service_selection}")
        results.append(f"   Full UUID: {selected_service.uuid}")
        results.append(f"   Characteristics: {len(selected_service.characteristics)}")
        
        for i, char in enumerate(selected_service.characteristics, 1):
            props = ", ".join(char.properties)
            results.append(f"   {i}. {str(char.uuid)[:13]}... ({props})")
        
        self.display_device_info(mac, results)

    def reset_device_connection(self, mac):
        """Reset the device connection"""
        if mac not in self.connected_devices:
            return
        
        warning = messagebox.askyesno("Reset Connection", 
            "This will disconnect and reconnect to the device.\n"
            "Continue?")
        
        if not warning:
            return
        
        device_info = self.connected_devices[mac]
        name = device_info['name']
        
        self.display_device_info(mac, ["🔄 Resetting connection..."])
        
        self.disconnect_device(mac)
        
        self.root.after(2000, lambda: self.reconnect_device(mac, name))

    def reconnect_device(self, mac, name):
        """Reconnect to a device"""
        self.status_label.config(text=f"Reconnecting to {name}...")
        threading.Thread(target=self.perform_connection, args=(mac, name)).start()

    def read_device_info(self, mac):
        """Read basic device information"""
        if mac not in self.connected_devices:
            messagebox.showerror("Error", "Device not connected")
            return
        
        threading.Thread(target=self.perform_device_info_read, args=(mac,)).start()

    def perform_device_info_read(self, mac):
        """Perform device info reading in background"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(self.read_device_info_async(mac))
            self.root.after(0, lambda: self.display_device_info(mac, result))
        except Exception as e:
            self.root.after(0, lambda: self.display_error(mac, f"Error reading device info: {str(e)}"))
        finally:
            loop.close()

    async def read_device_info_async(self, mac):
        """Async function to read device information"""
        device_info = self.connected_devices[mac]
        client = device_info['client']
        
        info_data = []
        
        DEVICE_INFO_SERVICE = "0000180a-0000-1000-8000-00805f9b34fb"
        
        try:
            services = device_info['services']
            
            for service in services:
                if str(service.uuid).lower() == DEVICE_INFO_SERVICE.lower():
                    info_data.append(f"Found Device Information Service: {service.uuid}")
                    
                    for char in service.characteristics:
                        try:
                            if "read" in char.properties:
                                value = await client.read_gatt_char(char.uuid)
                                decoded_value = value.decode('utf-8', errors='ignore').strip()
                                info_data.append(f"  {char.description}: {decoded_value}")
                        except Exception as e:
                            info_data.append(f"  {char.description}: Error reading ({str(e)})")
            
            if not info_data:
                info_data.append("No Device Information Service found")
                info_data.append(f"Available services: {len(services)}")
                for service in services[:5]: 
                    info_data.append(f"  - {service.uuid}")
        
        except Exception as e:
            info_data.append(f"Error: {str(e)}")
        
        return info_data

    def scan_device_services(self, mac):
        """Scan and display device services"""
        if mac not in self.connected_devices:
            messagebox.showerror("Error", "Device not connected")
            return
        
        device_info = self.connected_devices[mac]
        services = device_info['services']
        
        service_data = []
        service_data.append(f"=== SERVICES SCAN ===")
        service_data.append(f"Total services: {len(list(services))}\n")
        
        for i, service in enumerate(services, 1):
            service_data.append(f"Service {i}: {service.uuid}")
            service_data.append(f"  Handle: {service.handle}")
            
            if service.characteristics:
                service_data.append(f"  Characteristics ({len(service.characteristics)}):")
                for char in service.characteristics:
                    props = ", ".join(char.properties)
                    service_data.append(f"    - {char.uuid} ({props})")
            else:
                service_data.append("    - No characteristics")
            service_data.append("")
        
        self.display_device_info(mac, service_data)

    def display_device_info(self, mac, data):
        """Display device information in the connection window"""
        if mac not in self.connected_devices:
            return
        
        device_info = self.connected_devices[mac]
        if 'data_widget' in device_info:
            text_widget = device_info['data_widget']
            text_widget.insert(tk.END, f"\n--- {datetime.now().strftime('%H:%M:%S')} ---\n")
            for line in data:
                text_widget.insert(tk.END, f"{line}\n")
            text_widget.see(tk.END)

    def display_error(self, mac, error_msg):
        """Display error in the connection window"""
        self.display_device_info(mac, [f"ERROR: {error_msg}"])


    def pair_selected_device(self):
        """Attempt to pair with selected device"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a device to pair with.")
            return
        
        item = self.tree.item(selected[0])
        values = item['values']
        mac = values[0]
        name = values[1]
        
        # Security warning
        warning_msg = (
            "🔐 PAIRING ATTEMPT 🔐\n\n"
            "This will attempt to pair with the device.\n"
            "You may need to:\n"
            "• Accept pairing on the target device\n"
            "• Enter a PIN code\n"
            "• Confirm the connection\n\n"
            f"Device: {name}\nMAC: {mac}\n\n"
            "Continue with pairing?"
        )
        
        if not messagebox.askyesno("Pairing Warning", warning_msg):
            return
        
        self.status_label.config(text=f"Attempting to pair with {name}...")
        threading.Thread(target=self.perform_pairing, args=(mac, name)).start()

    def perform_pairing(self, mac, name):
        """Perform BLE pairing process"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(self.pair_device_async(mac, name))
            self.root.after(0, lambda: self.pairing_result(result, mac, name))
        except Exception as e:
            self.root.after(0, lambda: self.pairing_error(str(e), mac, name))
        finally:
            loop.close()

    async def pair_device_async(self, mac, name):
        """Async pairing function"""
        try:
            client = BleakClient(mac)
            
            # Try to connect first
            await asyncio.wait_for(client.connect(), timeout=20.0)
            
            if client.is_connected:
                # Attempt to trigger pairing by accessing protected characteristics
                services = await client.get_services()
                
                pairing_triggered = False
                for service in services:
                    for char in service.characteristics:
                        if "read" in char.properties:
                            try:
                                await client.read_gatt_char(char.uuid)
                                pairing_triggered = True
                                break
                            except Exception as e:
                                if "authentication" in str(e).lower() or "pairing" in str(e).lower():
                                    pairing_triggered = True
                                    break
                                continue
                    if pairing_triggered:
                        break
                
                # Keep connection alive for pairing process
                await asyncio.sleep(10)
                
                if client.is_connected:
                    await client.disconnect()
                    return {'success': True, 'message': 'Pairing process initiated'}
                else:
                    return {'success': False, 'error': 'Connection lost during pairing'}
            else:
                return {'success': False, 'error': 'Failed to establish connection'}
                
        except asyncio.TimeoutError:
            return {'success': False, 'error': 'Pairing timeout - device may require manual confirmation'}
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def pairing_result(self, result, mac, name):
        """Handle pairing result"""
        if result['success']:
            self.status_label.config(text=f"Pairing initiated with {name}")
            messagebox.showinfo("Pairing", f"Pairing process started with {name}.\n"
                                        "Check the device for pairing confirmation.")
        else:
            self.status_label.config(text=f"Pairing failed: {result['error']}")
            messagebox.showerror("Pairing Failed", f"Failed to pair with {name}:\n{result['error']}")

    def pairing_error(self, error_msg, mac, name):
        """Handle pairing error"""
        self.status_label.config(text=f"Pairing error: {error_msg}")
        messagebox.showerror("Pairing Error", f"Pairing error with {name}:\n{error_msg}")

    def power_off_selected_device(self):
        """Attempt to power off selected device"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a device to power off.")
            return
        
        item = self.tree.item(selected[0])
        values = item['values']
        mac = values[0]
        name = values[1]
        
        # STRONG WARNING
        warning_msg = (
            "⚠️ DANGER: POWER OFF DEVICE ⚠️\n\n"
            "This will attempt to PERMANENTLY POWER OFF the device!\n"
            "This action may:\n"
            "• Turn off the device completely\n"
            "• Require physical button press to restart\n"
            "• Potentially brick some devices\n\n"
            "ONLY use on devices you own and understand!\n\n"
            f"Device: {name}\nMAC: {mac}\n\n"
            "Are you absolutely sure you want to continue?"
        )
        
        if not messagebox.askyesno("POWER OFF WARNING", warning_msg):
            return
        
        # Double confirmation
        if not messagebox.askyesno("FINAL CONFIRMATION", "Last chance - really power off device?"):
            return
        
        self.execute_power_command(mac, name, "power_off")

    def restart_selected_device(self):
        """Attempt to restart selected device"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a device to restart.")
            return
        
        item = self.tree.item(selected[0])
        values = item['values']
        mac = values[0]
        name = values[1]
        
        warning_msg = (
            "🔄 RESTART DEVICE 🔄\n\n"
            "This will attempt to restart the device.\n"
            "The device should reboot and reconnect.\n\n"
            f"Device: {name}\nMAC: {mac}\n\n"
            "Continue with restart?"
        )
        
        if not messagebox.askyesno("Restart Confirmation", warning_msg):
            return
        
        self.execute_power_command(mac, name, "restart")

    def sleep_selected_device(self):
        """Put selected device to sleep"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Please select a device to put to sleep.")
            return
        
        item = self.tree.item(selected[0])
        values = item['values']
        mac = values[0]
        name = values[1]
        
        self.execute_power_command(mac, name, "sleep")

    def execute_power_command(self, mac, name, command):
        """Execute power management command"""
        self.status_label.config(text=f"Executing {command} on {name}...")
        threading.Thread(target=self.perform_power_command, args=(mac, name, command)).start()

    def perform_power_command(self, mac, name, command):
        """Perform power management command"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        try:
            result = loop.run_until_complete(self.power_command_async(mac, name, command))
            self.root.after(0, lambda: self.power_command_result(result, mac, name, command))
        except Exception as e:
            self.root.after(0, lambda: self.power_command_error(str(e), mac, name, command))
        finally:
            loop.close()

    async def power_command_async(self, mac, name, command):
        """Async power command execution"""
        try:
            client = BleakClient(mac)
            await asyncio.wait_for(client.connect(), timeout=15.0)
            
            if not client.is_connected:
                return {'success': False, 'error': 'Could not connect to device'}
            
            services = await client.get_services()
            results = []
            command_sent = False
            
            # Power management UUIDs (common ones)
            power_service_uuids = [
                "00001800-0000-1000-8000-00805f9b34fb",  # Generic Access
                "00001801-0000-1000-8000-00805f9b34fb",  # Generic Attribute
                "0000180a-0000-1000-8000-00805f9b34fb",  # Device Information
            ]
            
            power_char_uuids = [
                "00002a05-0000-1000-8000-00805f9b34fb",  # Service Changed
                "00002a00-0000-1000-8000-00805f9b34fb",  # Device Name
                "00002a01-0000-1000-8000-00805f9b34fb",  # Appearance
            ]
            
            # Command mappings
            command_data = {
                'power_off': [
                    bytes([0xFF, 0x00, 0x00, 0x00]),  # Power off sequence
                    bytes([0x02, 0x01, 0x00]),        # Alt power off
                    bytes([0x50, 0x4F, 0x57, 0x52]),  # "POWR" command
                ],
                'restart': [
                    bytes([0xFF, 0xFF, 0x00, 0x01]),  # Restart sequence
                    bytes([0x02, 0x02, 0x00]),        # Alt restart
                    bytes([0x52, 0x53, 0x54, 0x52]),  # "RSTR" command
                ],
                'sleep': [
                    bytes([0x53, 0x4C, 0x45, 0x50]),  # "SLEP" command
                    bytes([0x01, 0x00, 0x00]),        # Sleep mode
                    bytes([0xFF, 0x01, 0x00, 0x00]),  # Alt sleep
                ]
            }
            
            # Try writing to writable characteristics
            for service in services:
                for char in service.characteristics:
                    if "write" in char.properties or "write-without-response" in char.properties:
                        for data in command_data.get(command, []):
                            try:
                                await client.write_gatt_char(char.uuid, data)
                                results.append(f"✅ {command} command sent to {str(char.uuid)[:8]}...")
                                command_sent = True
                                await asyncio.sleep(0.5)
                            except Exception as e:
                                results.append(f"❌ Failed on {str(char.uuid)[:8]}...: {str(e)}")
            
            # Try proprietary vendor commands
            vendor_commands = [
                bytes([0xAA, 0xBB, 0xCC, 0xDD]),  # Generic vendor command
                bytes([0x12, 0x34, 0x56, 0x78]),  # Alt vendor command
            ]
            
            if not command_sent:
                for service in services:
                    for char in service.characteristics:
                        if "write" in char.properties:
                            for vendor_cmd in vendor_commands:
                                try:
                                    await client.write_gatt_char(char.uuid, vendor_cmd)
                                    results.append(f"✅ Vendor {command} command attempted")
                                    command_sent = True
                                    break
                                except:
                                    continue
                            if command_sent:
                                break
                    if command_sent:
                        break
            
            await client.disconnect()
            
            if command_sent:
                return {'success': True, 'results': results}
            else:
                return {'success': False, 'error': 'No writable characteristics found for power commands'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}

    def power_command_result(self, result, mac, name, command):
        """Handle power command result"""
        if result['success']:
            self.status_label.config(text=f"{command} command sent to {name}")
            results_text = '\n'.join(result['results'])
            messagebox.showinfo("Command Sent", f"{command} command sent to {name}:\n\n{results_text}")
        else:
            self.status_label.config(text=f"{command} command failed")
            messagebox.showerror("Command Failed", f"Failed to {command} {name}:\n{result['error']}")

    def power_command_error(self, error_msg, mac, name, command):
        """Handle power command error"""
        self.status_label.config(text=f"{command} error: {error_msg}")
        messagebox.showerror("Power Command Error", f"{command} error on {name}:\n{error_msg}")

    def disconnect_device(self, mac):
        """Disconnect a specific device"""
        if mac not in self.connected_devices:
            messagebox.showinfo("Not Connected", "Device is not currently connected.")
            return
    
        device_info = self.connected_devices.pop(mac, None)
        if not device_info:
            return
    
        name = device_info['name']
        self.status_label.config(text=f"Disconnecting from {name}...")
    
        if mac in self.connection_windows:
            self.connection_windows[mac].destroy()
            del self.connection_windows[mac]
    
        threading.Thread(target=self.perform_disconnect, args=(mac, device_info)).start()

    def perform_disconnect(self, mac, device_info):
        """Perform device disconnection with proper cleanup"""
        name = device_info['name']
        client = device_info['client']
    
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    
        try:
            async def disconnect_safely():
                try:
                    if hasattr(client, 'is_connected') and client.is_connected:
                        await client.disconnect()
                        await asyncio.sleep(0.5)
                    return True
                except Exception as e:
                    print(f"Disconnect error for {mac}: {e}")
                    return False
        
            success = loop.run_until_complete(disconnect_safely())
        
            pending_tasks = [task for task in asyncio.all_tasks(loop) if not task.done()]
            if pending_tasks:
                for task in pending_tasks:
                    task.cancel()
                loop.run_until_complete(asyncio.gather(*pending_tasks, return_exceptions=True))
        
            self.root.after(0, lambda: self.device_disconnected_complete(mac, name, success))
        
        except Exception as e:
            print(f"Exception during disconnect: {e}")
            self.root.after(0, lambda: self.device_disconnected_complete(mac, name, False))
        finally:
            try:
                if not loop.is_closed():
                    loop.close()
            except Exception as e:
                print(f"Error closing loop: {e}")

    def device_disconnected_complete(self, mac, name, success):
        """Handle completion of device disconnection"""
        if success:
            self.status_label.config(text=f"Successfully disconnected from {name} ({mac})")
        else:
            self.status_label.config(text=f"Disconnected from {name} ({mac}) with errors")

    def device_disconnected(self, mac):
        """Handle device disconnection"""
        if mac in self.connected_devices:
            device_info = self.connected_devices[mac]
            name = device_info['name']
            del self.connected_devices[mac]
            
            if mac in self.connection_windows:
                self.connection_windows[mac].destroy()
                del self.connection_windows[mac]
            
            self.status_label.config(text=f"Disconnected from {name} ({mac})")

    def disconnect_all_devices(self):
        """Disconnect all connected devices"""
        if not self.connected_devices:
            messagebox.showinfo("No Connections", "No devices are currently connected.")
            return
        
        count = len(self.connected_devices)
        for mac in list(self.connected_devices.keys()):
            self.disconnect_device(mac)
        
        self.status_label.config(text=f"Disconnecting {count} device(s)...")

    def cleanup_all_connections(self):
        """Clean up all connections when closing the application"""
        if self.connected_devices:
            print("Cleaning up connections...")
            for mac in list(self.connected_devices.keys()):
                try:
                    device_info = self.connected_devices.pop(mac, None)
                    if device_info and device_info.get('client'):
                        client = device_info['client']
                        try:
                            if hasattr(client, '_client') and client._client:
                                client._client = None
                        except:
                            pass
                except Exception as e:
                    print(f"Error cleaning up {mac}: {e}")
    
        for window in list(self.connection_windows.values()):
            try:
                window.destroy()
            except:
                pass
        self.connection_windows.clear()

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberBLEApp(root)
    
    def on_closing():
        try:
            app.cleanup_all_connections()
        except:
            pass
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()