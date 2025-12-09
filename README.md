
```
    ██████╗ ██████╗ ██╗██╗   ██╗███████╗██████╗ ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗   ██╗
    ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔══██╗╚██╗ ██╔╝
    ██║  ██║██████╔╝██║██║   ██║█████╗  ██████╔╝██████╔╝██║   ██║██║  ██║██║  ██║ ╚████╔╝ 
    ██║  ██║██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══██╗██║   ██║██║  ██║██║  ██║  ╚██╔╝  
    ██████╔╝██║  ██║██║ ╚████╔╝ ███████╗██║  ██║██████╔╝╚██████╔╝██████╔╝██████╔╝   ██║   
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝    ╚═╝   
                                                                                           
                    ☠ Modern Multi-Platform Windows Driver Analysis Tool ☠
```

**DriverBuddy** is a comprehensive Windows kernel driver analysis framework that works across multiple reverse engineering platforms. Originally created by NCC Group, this modernized version supports the latest versions of IDA Pro, Ghidra, Binary Ninja, and Radare2.

## ☠ Supported Platforms ☠

| Platform | Version | Status |
|----------|---------|--------|
| **IDA Pro** | 7.x, 8.x | ✅ Full Support |
| **Ghidra** | 10.x+ | ✅ Full Support |
| **Binary Ninja** | 3.x+ | ✅ Full Support |
| **Radare2** | 5.x+ | ✅ Full Support |

## ☠ Features ☠

### Core Analysis Capabilities
- **Driver Type Detection**: Automatically identifies WDM, WDF, KMDF, and UMDF drivers
- **DriverEntry Location**: Finds and labels the main driver entry point
- **Dispatch Function Discovery**: Locates IRP dispatch handlers (CREATE, READ, WRITE, DEVICE_CONTROL, etc.)
- **IOCTL Analysis**: Finds and decodes Windows I/O Control codes
- **Dangerous Function Flagging**: Identifies potentially vulnerable API calls
- **Cross-Reference Analysis**: Maps function relationships and call patterns

### Platform-Specific Integration
- **Function Naming**: Automatically renames functions with descriptive names
- **Smart Commenting**: Adds detailed comments explaining driver structures and IOCTLs
- **Structure Identification**: Labels common Windows driver structures (IRP, IO_STACK_LOCATION, etc.)
- **Import Analysis**: Analyzes imported functions for security implications

## ☠ Quick Start ☠

### Installation

#### For IDA Pro
```bash
# Copy to IDA plugins directory
cp -r DriverBuddy/ "C:\Program Files\IDA Pro 8.0\plugins\"
cp DriverBuddy.py "C:\Program Files\IDA Pro 8.0\plugins\"
```

#### For Ghidra
```bash
# Copy script to Ghidra scripts directory
cp scripts/ghidra_driverbuddy.py ~/ghidra_scripts/
cp -r DriverBuddy/ ~/ghidra_scripts/
```

#### For Binary Ninja
```bash
# Copy to Binary Ninja plugins directory
cp scripts/binja_driverbuddy.py ~/.binaryninja/plugins/
cp -r DriverBuddy/ ~/.binaryninja/plugins/
```

#### For Radare2
```bash
# Install r2pipe if not already installed
pip install r2pipe

# Copy script to accessible location
cp scripts/r2_driverbuddy.py /path/to/your/scripts/
cp -r DriverBuddy/ /path/to/your/scripts/
```

### Usage

#### IDA Pro
1. Load your Windows driver in IDA Pro
2. Press `Ctrl+Alt+D` or go to `Edit → Plugins → DriverBuddy`
3. Check the Output window for analysis results
4. Use `Ctrl+Alt+I` to decode IOCTLs at cursor position

#### Ghidra
1. Load your Windows driver in Ghidra
2. Open Script Manager (`Window → Script Manager`)
3. Run `ghidra_driverbuddy.py`
4. Check console output for results

#### Binary Ninja
1. Load your Windows driver in Binary Ninja
2. Go to `Tools → DriverBuddy → Analyze Driver`
3. Check the log for analysis results

#### Radare2
```bash
# Load driver and run analysis
r2 driver.sys
[0x00000000]> #!pipe python3 /path/to/r2_driverbuddy.py
```

## ☠ Analysis Output ☠

DriverBuddy provides comprehensive analysis results:

```
☠ ☠ ☠ ANALYSIS SUMMARY ☠ ☠ ☠
Platform: IDA Pro 8.0
Driver Type: WDM
DriverEntry: 0x1400014c0
Dispatch Functions: 5
  IRP_MJ_CREATE: 0x140001500
  IRP_MJ_CLOSE: 0x140001520
  IRP_MJ_DEVICE_CONTROL: 0x140001600
  IRP_MJ_CLEANUP: 0x140001540
  IRP_MJ_PNP: 0x140001700
IOCTLs Found: 12
Dangerous Functions: 3
☠ ☠ ☠ ANALYSIS COMPLETE ☠ ☠ ☠
```

### IOCTL Decoding Example
```
☠ IOCTL Decoded ☠
IOCTL Code: 0x22E004
  Device Type: 0x0022
  Function: 0x801 (2049)
  Method: METHOD_BUFFERED (0)
  Access: FILE_ANY_ACCESS (0)
```

## ☠ Advanced Features ☠

### Dangerous Function Detection
DriverBuddy automatically flags potentially dangerous functions:
- Buffer manipulation: `strcpy`, `strcat`, `memcpy`
- Memory allocation: `ExAllocatePool`, `ExAllocatePoolWithTag`
- Probing functions: `ProbeForRead`, `ProbeForWrite`
- And many more...

### Driver Structure Analysis
- **WDM Drivers**: Identifies classic Windows Driver Model patterns
- **WDF Drivers**: Recognizes Windows Driver Framework usage
- **KMDF/UMDF**: Distinguishes between kernel and user-mode frameworks

### Cross-Platform Compatibility
The modular architecture ensures consistent analysis across all supported platforms while leveraging each tool's unique capabilities.

## ☠ Development ☠

### Architecture
```
DriverBuddy/
├── __init__.py          # Main package interface
├── core.py              # Platform-independent analysis engine
└── platforms/           # Platform-specific adapters
    ├── __init__.py      # Platform detection and loading
    ├── base.py          # Abstract platform interface
    ├── ida_adapter.py   # IDA Pro integration
    ├── ghidra_adapter.py # Ghidra integration
    ├── binja_adapter.py # Binary Ninja integration
    └── r2_adapter.py    # Radare2 integration
```

### Adding New Platforms
1. Create a new adapter class inheriting from `PlatformAdapter`
2. Implement all required abstract methods
3. Add platform detection logic to `platforms/__init__.py`
4. Create a platform-specific script in `scripts/`

### Contributing
Contributions are welcome! Please ensure:
- Code follows Python 3.6+ standards
- All platforms are tested
- Documentation includes ASCII skull branding
- New features maintain cross-platform compatibility

## ☠ Troubleshooting ☠

### Common Issues

**Import Errors**
```bash
# Ensure DriverBuddy is in Python path
export PYTHONPATH="/path/to/DriverBuddy:$PYTHONPATH"
```

**Platform Not Detected**
- Verify you're running the script within the target platform
- Check that required platform modules are installed
- Ensure platform-specific dependencies are available

**Analysis Fails**
- Confirm the binary is a valid Windows driver
- Check that the platform has completed its auto-analysis
- Verify the binary is properly loaded and analyzed

### Debug Mode
Enable verbose logging by modifying the platform adapter:
```python
# Add to any platform adapter
def log(self, message: str) -> None:
    print(f"[DEBUG] {message}")
    # Platform-specific logging...
```

## ☠ Credits ☠

### Original DriverBuddy
- **Authors**: Braden Hollembaek and Adam Pond (NCC Group)
- **IOCTL Decoder**: Based on Satoshi Tanda's WinIoCtlDecoder
- **WDF Functions**: Based on Red Plait's research, ported by Nicolas Guigo

### Modern Multi-Platform Version
- **Modernization**: Updated for 2024 with multi-platform support
- **Architecture**: Redesigned with modular platform adapters
- **Python 3**: Fully updated to modern Python standards

## ☠ License ☠

This software is released under the MIT License.

```
MIT License

Copyright (c) 2024 NCC Group (Original), Modernized Version

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

```
                                    ☠ ☠ ☠
                              Happy Driver Hunting!
                                    ☠ ☠ ☠
```
