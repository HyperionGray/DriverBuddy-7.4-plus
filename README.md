# DriverBuddy

```
    ╔═══════════════════════════════════════════════════════════════╗
    ║                       DriverBuddy                             ║
    ║           Windows Kernel Driver Analysis Toolkit             ║
    ║                                                                ║
    ║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║
    ╚═══════════════════════════════════════════════════════════════╝
```

## Overview

DriverBuddy is a comprehensive toolkit for analyzing Windows kernel drivers across multiple reverse engineering platforms. It automates tedious aspects of driver analysis, helping security researchers identify potential vulnerabilities and understand driver behavior more efficiently.

### Supported Platforms

- **IDA Pro** 7.x+ (Python 3)
- **Ghidra** 10.x+
- **Binary Ninja** 3.x+
- **Radare2** 5.x+

## Features

```
    ☠  Automated driver type identification (WDM, WDF, Mini-Filter, NDIS)
    ☠  DispatchDeviceControl and DispatchInternalDeviceControl location
    ☠  Automatic IOCTL code discovery and decoding
    ☠  Detection of dangerous C/C++ functions (buffer overflows, etc.)
    ☠  Windows API function identification and analysis
    ☠  WDM structure labeling (IRP, IO_STACK_LOCATION, DEVICE_OBJECT)
    ☠  WDF function pointer identification and labeling
    ☠  Cross-reference tracking for security-sensitive functions
```

## Installation

### IDA Pro

1. Copy `DriverBuddy.py` and the `DriverBuddy/` folder to your IDA plugins directory:
   - **Windows**: `C:\Program Files\IDA Pro 7.x\plugins\`
   - **Linux**: `~/.idapro/plugins/`
   - **macOS**: `~/Library/Application Support/IDA Pro/plugins/`

2. Restart IDA Pro

### Ghidra

1. Open Ghidra Script Manager (Window → Script Manager)
2. Click the "Script Directories" button
3. Add the directory containing `DriverBuddy_Ghidra.py`
4. Refresh the script list

### Binary Ninja

1. Copy `DriverBuddy_BinaryNinja.py` to your Binary Ninja plugins directory:
   - **Windows**: `%APPDATA%\Binary Ninja\plugins\`
   - **Linux**: `~/.binaryninja/plugins/`
   - **macOS**: `~/Library/Application Support/Binary Ninja/plugins/`

2. Restart Binary Ninja

### Radare2

1. Install r2pipe: `pip3 install r2pipe`
2. Run from within radare2:
   ```bash
   r2 -i DriverBuddy_Radare2.py driver.sys
   ```
   Or from the r2 console:
   ```bash
   #!pipe python3 DriverBuddy_Radare2.py
   ```

## Usage

### IDA Pro

```
    ☠  Method 1: Edit → Plugins → Driver Buddy
    ☠  Method 2: Press Ctrl+Alt+D
    ☠  Decode IOCTL: Highlight suspected IOCTL value and press Ctrl+Alt+I
```

**Example Output:**
```
╔═══════════════════════════════════════════════════════════════╗
║              DriverBuddy for IDA Pro                          ║
║              Windows Kernel Driver Analysis                   ║
║                                                                ║
║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║
╚═══════════════════════════════════════════════════════════════╝
[+] Welcome to Driver Buddy
[+] DriverEntry found
[+] Driver type detected: WDM
[+] Found DispatchDeviceControl 0x00011234
[+] Found strcpy with 3 references
[+] Found IOCTL: 0x00222004
    Device   : 0x0022
    Function : 0x801
    Method   : METHOD_BUFFERED
    Access   : FILE_ANY_ACCESS
```

### Ghidra

1. Open your Windows driver in Ghidra
2. Open Script Manager (Window → Script Manager)
3. Run `DriverBuddy_Ghidra.py`
4. Check the console output for analysis results

### Binary Ninja

1. Open your Windows driver in Binary Ninja
2. Navigate to Plugins → DriverBuddy → Analyze Driver
3. View results in the log window

### Radare2

```bash
# Method 1: Load driver and run script
r2 -i DriverBuddy_Radare2.py driver.sys

# Method 2: Run from r2 console
r2 driver.sys
[0x00000000]> aaa
[0x00000000]> #!pipe python3 DriverBuddy_Radare2.py
```

## Analysis Capabilities

### Driver Type Detection

```
    ☠  WDM (Windows Driver Model)
    ☠  WDF (Windows Driver Framework)
    ☠  Mini-Filter (File System Filter)
    ☠  NDIS (Network Driver Interface Specification)
```

### IOCTL Decoding

DriverBuddy automatically decodes Windows I/O Control codes to reveal:

- **Device Type**: The type of device the IOCTL is intended for
- **Function Code**: The specific operation being requested
- **Transfer Method**: How data is transferred (buffered, direct, neither)
- **Access Rights**: Required access permissions

**Example:**
```
[+] IOCTL: 0x00222004
    Device   : FILE_DEVICE_UNKNOWN (0x0022)
    Function : 0x801
    Method   : METHOD_BUFFERED
    Access   : FILE_ANY_ACCESS
```

### Dangerous Function Detection

```
    ☠  Buffer Overflow Prone: strcpy, strcat, sprintf, gets
    ☠  Memory Operations: memcpy, RtlCopyMemory
    ☠  Format String Issues: scanf, printf variants
```

### Windows API Monitoring

```
    ☠  Access Control: SeAccessCheck, SeQueryAuthenticationIdToken
    ☠  Device Management: IoRegisterDeviceInterface, IoCreateDevice
    ☠  Object Management: ObReferenceObject, ObDereferenceObject
    ☠  System Calls: Zw* functions (ZwCreateFile, ZwOpenKey, etc.)
    ☠  Process/Thread: PsCreateSystemThread, PsLookupProcessByProcessId
```

## Architecture

```
DriverBuddy/
├── __init__.py           # Module initialization
├── data.py               # Driver structure and function analysis
├── ioctl.py              # IOCTL decoding logic
├── wdm.py                # WDM-specific analysis
└── wdf.py                # WDF-specific analysis (function table parsing)
```

## Technical Details

### DispatchDeviceControl Location

DriverBuddy locates the `DispatchDeviceControl` function by:

1. Finding `DriverEntry` function
2. Analyzing assignments to `DRIVER_OBJECT.MajorFunction[0x0E]`
3. Following references to identify the actual dispatch handler

### Structure Identification

For WDM drivers, DriverBuddy automatically identifies and labels:

- **IRP** (I/O Request Packet): Offset-based detection of `SystemBuffer`, `IoStatus.Information`
- **IO_STACK_LOCATION**: Identification of `DeviceIoControlCode`, `InputBufferLength`, `OutputBufferLength`
- **DEVICE_OBJECT**: Detection of device extension and characteristic fields

### WDF Function Parsing

For WDF drivers, DriverBuddy:

1. Locates the `WdfFunctions` structure via the `WdfVersionBind` reference
2. Parses the function pointer table based on WDF version
3. Labels function pointers for improved readability

## Security Research Applications

```
    ☠  Vulnerability Discovery: Identify unsafe function usage patterns
    ☠  Attack Surface Analysis: Map all IOCTLs and their handlers
    ☠  Privilege Escalation: Track access control checks and object references
    ☠  Fuzzing Preparation: Extract IOCTL codes for targeted fuzzing
    ☠  Exploit Development: Understand driver control flow and data structures
```

## Troubleshooting

### IDA Pro

- **Issue**: Plugin not loading
  - **Solution**: Ensure Python 3 is configured in IDA (Edit → Preferences → Python)
  - **Solution**: Check IDA console for error messages

### Ghidra

- **Issue**: Script not appearing
  - **Solution**: Refresh script list in Script Manager
  - **Solution**: Ensure script is in a configured script directory

### Binary Ninja

- **Issue**: Plugin not visible in menu
  - **Solution**: Check console for import errors
  - **Solution**: Verify Binary Ninja API version compatibility

### Radare2

- **Issue**: r2pipe connection failed
  - **Solution**: Install r2pipe: `pip3 install r2pipe`
  - **Solution**: Run script from within radare2, not standalone

## Development

### Contributing

Contributions are welcome! Areas for improvement:

- Enhanced IOCTL discovery heuristics
- Additional driver type detection
- GUI interfaces for each platform
- Automated vulnerability pattern detection
- IRP tracking and taint analysis

### Future Enhancements

```
    ☠  Reference counting analysis (ObReferenceObject/ObDereferenceObject tracking)
    ☠  Time-of-check/time-of-use (TOCTOU) detection
    ☠  ProbeForRead/ProbeForWrite validation
    ☠  Input validation pattern recognition
    ☠  Race condition detection
```

## Credits

```
    ☠  Original DriverBuddy: Braden Hollembaek and Adam Pond (NCC Group)
    ☠  IOCTL Decoder: Satoshi Tanda (https://github.com/tandasat/WinIoCtlDecoder)
    ☠  WDF Functions: Red Plait, Nicolas Guigo
    ☠  Modernization: Community contributors
```

## References

- [Windows Driver Development](https://docs.microsoft.com/en-us/windows-hardware/drivers/)
- [WDM Driver Architecture](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/)
- [WDF Framework](https://docs.microsoft.com/en-us/windows-hardware/drivers/wdf/)
- [Windows Driver Security](https://docs.microsoft.com/en-us/windows-hardware/drivers/driversecurity/)

## License

This software is released under the MIT License. See LICENSE file for details.

```
    ╔═══════════════════════════════════════════════════════════════╗
    ║                                                                ║
    ║         ☠  Happy Hunting!  ☠                                  ║
    ║                                                                ║
    ╚═══════════════════════════════════════════════════════════════╝
```
