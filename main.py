import asyncio
import threading
import tkinter as tk
from tkinter import ttk
from bleak import BleakScanner


class BLEScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberBLE - Bluetooth Low Energy Scanner")
        self.root.geometry("700x450")
        self.root.resizable(True, True)
        self.devices = {}

        self.setup_ui()

    def setup_ui(self):
        # Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("Treeview", font=("Segoe UI", 10), rowheight=25)

        # Frame
        frame = ttk.LabelFrame(self.root, text="Detected BLE Devices", padding=10)
        frame.pack(fill="both", expand=True, padx=10, pady=(10, 5))

        # Treeview
        self.tree = ttk.Treeview(frame, columns=("Name", "Address", "RSSI"), show="headings")
        self.tree.heading("Name", text="Device Name")
        self.tree.heading("Address", text="MAC Address")
        self.tree.heading("RSSI", text="Signal Strength (RSSI)")
        self.tree.column("Name", width=200)
        self.tree.column("Address", width=200)
        self.tree.column("RSSI", width=100)
        self.tree.pack(fill="both", expand=True)

        # Progress Bar
        self.progress = ttk.Progressbar(self.root, mode="indeterminate")
        self.progress.pack(fill="x", padx=10, pady=(5, 0))

        # Status bar
        self.status = ttk.Label(self.root, text="Ready", anchor="w", relief="sunken")
        self.status.pack(fill="x", padx=10, pady=(2, 5))

        # Buttons
        button_frame = ttk.Frame(self.root)
        button_frame.pack(pady=(0, 10))

        self.scan_btn = ttk.Button(button_frame, text="Scan for Devices", command=self.start_scan)
        self.scan_btn.pack()

    def start_scan(self):
        self.progress.start()
        self.status.config(text="Scanning for BLE devices...")
        self.scan_btn.config(state="disabled")
        threading.Thread(target=self.scan_ble_devices, daemon=True).start()

    def scan_ble_devices(self):
        self.devices.clear()
        asyncio.run(self.run_ble_scan())
        self.progress.stop()
        self.status.config(text=f"Scan complete. {len(self.devices)} device(s) found.")
        self.scan_btn.config(state="normal")

    async def run_ble_scan(self):
        devices = await BleakScanner.discover(timeout=5)
        self.tree.delete(*self.tree.get_children())

        for d in devices:
            name = d.name or "Unknown"
            address = d.address
            rssi = d.rssi
            self.devices[address] = (name, rssi)
            self.tree.insert("", "end", values=(name, address, rssi))


if __name__ == "__main__":
    root = tk.Tk()
    app = BLEScannerApp(root)
    root.mainloop()
