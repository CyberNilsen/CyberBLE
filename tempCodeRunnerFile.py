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