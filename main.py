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
        if not continuous:
            self.continuous_scan_button.config(state="disabled")

    def enable_buttons(self):
        self.scan_button.config(state="normal")
        self.scan_online_button.config(state="normal")
        self.lookup_button.config(state="normal")
        self.export_button.config(state="normal")
        self.clear_button.config(state="normal")
        self.continuous_scan_button.config(state="normal")

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
        self.create_widgets()
        self.check_data_files()

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

if __name__ == "__main__":
    root = tk.Tk()
    app = CyberBLEApp(root)
    root.mainloop()