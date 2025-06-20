# CyberBLE

Advanced BLE Device Profiler & Analyzer

## Overview

CyberBLE is a comprehensive Bluetooth Low Energy (BLE) scanning and analysis tool with an intuitive GUI. It discovers nearby BLE devices and provides detailed information about their characteristics, including vendor identification, device types, services, and manufacturer data.

![CyberBLE](https://github.com/user-attachments/assets/928c643b-1a2e-43d6-b8ef-e5ffc999f722)

Mac adresses are hid for privacy reasons


## Features

- **Quick Offline Scan** - Fast BLE device discovery using local databases
- **Deep Online Scan** - Enhanced scanning with online vendor lookup
- **Continuous Monitoring** - Real-time device tracking with live updates
- **Device Profiling** - Automatic device type detection and classification
- **Vendor Identification** - MAC address to vendor mapping
- **Service Analysis** - BLE service UUID identification and parsing
- **Manufacturer Data** - Detailed manufacturer-specific data analysis
- **Export Functionality** - Save scan results to JSON format
- **User-Friendly Interface** - Clean, professional GUI with detailed device information

## Requirements

### Data Files (Optional)
- `mac_vendors.json` - MAC address to vendor mapping
- `manufacturer_ids.json` - BLE manufacturer ID database
- `service_uuids.json` - BLE service UUID definitions

## Installation

1. Clone the repository:
```bash
git clone https://github.com/CyberNilsen/CyberBLE
cd CyberBLE
```

2. Install required dependencies:
```bash
pip install -r requirements.txt
```

3. Run the application:
```bash
python CyberBLE.py
```

## Usage

### Basic Scanning
1. **Quick Scan (Offline)** - Uses local databases for fast device identification
2. **Deep Scan (Online)** - Performs online vendor lookups for enhanced accuracy
3. **Continuous Scan** - Monitors devices in real-time with automatic updates

### Features
- **Double-click** any device in the list to view detailed information
- **Click column headers** to get explanations of each data field
- **Enhance Vendors** button performs online lookups for unknown vendors
- **Export Results** saves all discovered devices to a timestamped JSON file
- **Clear Results** removes all devices from the current view

### Device Information Displayed
- **MAC Address** - Hardware identifier
- **Name** - Device name or detected identifier
- **Type** - Classified device category
- **Vendor** - Manufacturer based on MAC lookup
- **Manufacturer ID** - BLE advertisement manufacturer data
- **Services** - Available BLE services
- **RSSI** - Signal strength indicator
- **Last Seen** - Time of last detection

## Device Types Detected

The tool automatically classifies devices into categories:
- Apple devices (iPhone, iPad, AirPods, etc.)
- Samsung devices (Galaxy series, etc.)
- Fitness trackers (Fitbit, Garmin, etc.)
- Audio devices (Beats, JBL, Sony, Bose, etc.)
- Gaming devices (Nintendo, Xbox, etc.)
- Smart home devices (Google, Tesla, etc.)
- Input devices (keyboards, mice, etc.)

## Data Files Format

### mac_vendors.json
```json
{
  "001122": "Apple, Inc.",
  "AABBCC": "Samsung Electronics Co.,Ltd"
}
```

### manufacturer_ids.json
```json
{
  "004C": "Apple, Inc.",
  "0075": "Samsung Electronics Co. Ltd."
}
```

### service_uuids.json
```json
{
  "180d": "Heart Rate",
  "180f": "Battery Service"
}
```

## Export Format

Results are exported as JSON with the following structure:
```json
{
  "scan_info": {
    "timestamp": "2025-01-15T10:30:00",
    "device_count": 5,
    "tool": "CyberBLE Pro"
  },
  "devices": [
    {
      "mac": "AA:BB:CC:DD:EE:FF",
      "name": "iPhone",
      "type": "Apple",
      "vendor": "Apple, Inc.",
      "manufacturer_id": "0x004C (Apple, Inc.)",
      "services": "Generic Access (1800)",
      "rssi": "-45",
      "last_seen": "10:30:15"
    }
  ]
}
```

## System Requirements

- **Operating System**: Windows, macOS, or Linux
- **Python**: 3.7 or higher
- **Bluetooth**: BLE-capable Bluetooth adapter
- **Permissions**: May require administrator/root privileges on some systems

## Troubleshooting

### Common Issues
- **No devices found**: Check if Bluetooth is enabled and BLE adapter is working
- **Permission errors**: Run as administrator/root if required
- **Slow scanning**: Move closer to target devices or check for interference
- **Online lookup fails**: Check internet connection

### Platform-Specific Notes
- **Linux**: May need to run with `sudo` for BLE access
- **Windows**: Ensure Windows 10 version 1903 or later for best BLE support
- **macOS**: Grant Bluetooth permissions when prompted

## Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for bugs and feature requests.

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

This tool is intended for educational and authorized testing purposes only. Users are responsible for complying with local laws and regulations regarding wireless device scanning and analysis.

## Author

CyberBLE © 2025 by CyberNilsen  
Enhanced BLE Analysis & Device Profiling

---

**Note**: This tool performs passive BLE scanning and does not connect to or interact with discovered devices.
