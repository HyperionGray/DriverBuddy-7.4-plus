# DriverBuddy for Radare2
# Windows Driver Analysis Script for Radare2
# Based on the original DriverBuddy by NCC Group
# Modernized for Radare2 5.x+
#
# Usage: 
#   r2 -i DriverBuddy_Radare2.py driver.sys
# Or from r2 console:
#   #!pipe python3 DriverBuddy_Radare2.py

import r2pipe
import sys
import json

PLUGIN_NAME = "DriverBuddy"
PLUGIN_VERSION = "2.0"

# Dangerous C/C++ functions to flag
DANGEROUS_FUNCTIONS = [
    "sprintf", "strcpy", "strcat", "memcpy", "RtlCopyMemory",
    "gets", "scanf", "strncpy", "strncat", "wcscpy", "wcscat"
]

# Windows API functions of interest
INTERESTING_WINAPI = [
    "SeAccessCheck", "ProbeFor", "SeQueryAuthenticationIdToken",
    "IoRegisterDeviceInterface", "Ob", "Zw", "IofCallDriver",
    "PsCreateSystemThread", "ExAllocatePool", "IoCreateDevice"
]

class DriverBuddyR2:
    def __init__(self):
        try:
            self.r2 = r2pipe.open()
        except:
            print("[-] Error: Could not connect to r2pipe")
            print("[-] Make sure you're running this from within radare2")
            sys.exit(1)
        
    def print_header(self):
        """Print ASCII art header"""
        print("╔═══════════════════════════════════════════════════════════════╗")
        print("║              DriverBuddy for Radare2                          ║")
        print("║              Windows Kernel Driver Analysis                   ║")
        print("║                                                                ║")
        print("║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║")
        print("╚═══════════════════════════════════════════════════════════════╝")
    
    def find_driver_entry(self):
        """Find DriverEntry function"""
        print("[+] Searching for DriverEntry...")
        
        # Search for DriverEntry symbol
        result = self.r2.cmd("afl~DriverEntry")
        if result:
            lines = result.strip().split('\n')
            for line in lines:
                if 'DriverEntry' in line:
                    parts = line.split()
                    if len(parts) >= 1:
                        addr = parts[0]
                        print(f"[+] Found DriverEntry at: {addr}")
                        return addr
        
        print("[-] DriverEntry not found")
        return None
    
    def determine_driver_type(self):
        """Determine the type of Windows driver"""
        print("[+] Determining driver type...")
        
        driver_type = "WDM"  # Default to WDM
        
        # Check for WDF driver
        wdf_symbols = ["WdfVersionBind", "WdfDriverCreate"]
        for sym_name in wdf_symbols:
            result = self.r2.cmd(f"afl~{sym_name}")
            if result.strip():
                driver_type = "WDF"
                break
        
        # Check for filter driver
        result = self.r2.cmd("afl~FltRegisterFilter")
        if result.strip():
            driver_type = "Mini-Filter"
        
        # Check for NDIS driver
        result = self.r2.cmd("afl~NdisRegisterProtocolDriver")
        if result.strip():
            driver_type = "NDIS"
        
        print(f"[+] Driver type: {driver_type}")
        return driver_type
    
    def find_dispatch_device_control(self, driver_entry_addr):
        """Attempt to locate DispatchDeviceControl function"""
        print("[+] Searching for DispatchDeviceControl...")
        
        if not driver_entry_addr:
            return []
        
        # Seek to DriverEntry
        self.r2.cmd(f"s {driver_entry_addr}")
        
        # Analyze function
        self.r2.cmd("af")
        
        # Get function disassembly and look for offset 0xE0 (IRP_MJ_DEVICE_CONTROL)
        disasm = self.r2.cmd("pdf")
        
        found_refs = []
        for line in disasm.split('\n'):
            # Look for references to offset 0xE0 or 0xE8
            if '0xe0' in line.lower() or '0xe8' in line.lower():
                if 'mov' in line.lower() or 'lea' in line.lower():
                    print(f"[+] Possible DispatchDeviceControl reference: {line.strip()}")
                    found_refs.append(line.strip())
        
        if not found_refs:
            print("[-] DispatchDeviceControl not found")
        
        return found_refs
    
    def find_dangerous_functions(self):
        """Find and report dangerous C function calls"""
        print("[+] Searching for dangerous C functions...")
        found_count = 0
        
        for func_name in DANGEROUS_FUNCTIONS:
            # Search for function
            result = self.r2.cmd(f"afl~{func_name}")
            if result.strip():
                # Get cross-references
                xrefs = self.r2.cmd(f"axt sym.imp.{func_name}")
                if xrefs.strip():
                    ref_count = len(xrefs.strip().split('\n'))
                    found_count += 1
                    print(f"[+] Found {func_name} with {ref_count} references")
                    
                    # Show first few references
                    for i, line in enumerate(xrefs.strip().split('\n')[:5]):
                        print(f"    └─ {line}")
        
        if found_count == 0:
            print("[-] No dangerous C functions detected")
        else:
            print(f"[+] Total dangerous functions found: {found_count}")
    
    def find_interesting_winapi(self):
        """Find interesting Windows API calls"""
        print("[+] Searching for interesting Windows API functions...")
        found_count = 0
        
        # Get all functions
        funcs_json = self.r2.cmd("aflj")
        try:
            funcs = json.loads(funcs_json)
        except:
            funcs = []
        
        for api_prefix in INTERESTING_WINAPI:
            for func in funcs:
                func_name = func.get('name', '')
                if func_name.startswith(api_prefix) or func_name.startswith(f"sym.imp.{api_prefix}"):
                    # Get cross-references
                    xrefs = self.r2.cmd(f"axt {func.get('offset', 0):x}")
                    if xrefs.strip():
                        ref_count = len(xrefs.strip().split('\n'))
                        found_count += 1
                        print(f"[+] Found {func_name} with {ref_count} references")
                        
                        # Show first few references
                        for i, line in enumerate(xrefs.strip().split('\n')[:3]):
                            print(f"    └─ {line}")
        
        if found_count == 0:
            print("[-] No interesting Windows API functions detected")
        else:
            print(f"[+] Total interesting API functions found: {found_count}")
    
    def decode_ioctl(self, ioctl_code):
        """Decode Windows IOCTL code"""
        device = (ioctl_code >> 16) & 0xFFFF
        access = (ioctl_code >> 14) & 0x3
        function = (ioctl_code >> 2) & 0xFFF
        method = ioctl_code & 0x3
        
        access_names = ['FILE_ANY_ACCESS', 'FILE_READ_ACCESS', 'FILE_WRITE_ACCESS', 'FILE_READ_ACCESS | FILE_WRITE_ACCESS']
        method_names = ['METHOD_BUFFERED', 'METHOD_IN_DIRECT', 'METHOD_OUT_DIRECT', 'METHOD_NEITHER']
        
        print(f"[+] IOCTL: 0x{ioctl_code:08X}")
        print(f"    Device   : 0x{device:04X}")
        print(f"    Function : 0x{function:03X}")
        print(f"    Method   : {method_names[method]}")
        print(f"    Access   : {access_names[access]}")
    
    def find_ioctls(self):
        """Search for IOCTL codes in the binary"""
        print("[+] Searching for IOCTLs...")
        found_ioctls = set()
        
        # Search for constant comparisons that might be IOCTLs
        # Look for CMP instructions with immediate values in IOCTL range
        result = self.r2.cmd("/c cmp")
        
        if result.strip():
            for line in result.strip().split('\n'):
                # Parse hex values that might be IOCTLs
                parts = line.split()
                for part in parts:
                    if part.startswith('0x'):
                        try:
                            val = int(part, 16)
                            # Check if this looks like an IOCTL
                            if 0x00020000 < val < 0x00500000:
                                if val not in found_ioctls:
                                    found_ioctls.add(val)
                                    self.decode_ioctl(val)
                        except:
                            pass
        
        if len(found_ioctls) == 0:
            print("[-] No IOCTLs found")
        else:
            print(f"[+] Total IOCTLs found: {len(found_ioctls)}")
    
    def analyze(self):
        """Main analysis routine"""
        self.print_header()
        print("[+] Starting DriverBuddy analysis...")
        
        # Get binary info
        info = self.r2.cmd("ij")
        try:
            info_json = json.loads(info)
            filename = info_json.get('core', {}).get('file', 'unknown')
            print(f"[+] Binary: {filename}")
        except:
            pass
        
        print("")
        
        # Analyze binary
        print("[+] Analyzing binary (this may take a moment)...")
        self.r2.cmd("aaa")
        
        # Find DriverEntry
        driver_entry = self.find_driver_entry()
        if not driver_entry:
            print("[-] This may not be a Windows driver")
            print("[-] Exiting...")
            return
        
        print("")
        
        # Determine driver type
        driver_type = self.determine_driver_type()
        print("")
        
        # Find dispatch functions
        self.find_dispatch_device_control(driver_entry)
        print("")
        
        # Find dangerous functions
        self.find_dangerous_functions()
        print("")
        
        # Find interesting WinAPI
        self.find_interesting_winapi()
        print("")
        
        # Find IOCTLs
        self.find_ioctls()
        print("")
        
        print("[+] DriverBuddy analysis complete!")
        print("╔═══════════════════════════════════════════════════════════════╗")
        print("║                    Analysis Complete                          ║")
        print("║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║")
        print("╚═══════════════════════════════════════════════════════════════╝")

def main():
    """Entry point"""
    try:
        analyzer = DriverBuddyR2()
        analyzer.analyze()
    except KeyboardInterrupt:
        print("\n[-] Analysis interrupted by user")
    except Exception as e:
        print(f"[-] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    main()
