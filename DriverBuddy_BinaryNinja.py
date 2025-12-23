# DriverBuddy for Binary Ninja
# Windows Driver Analysis Plugin for Binary Ninja
# Based on the original DriverBuddy by NCC Group
# Modernized for Binary Ninja 3.x+

from binaryninja import *

PLUGIN_NAME = "DriverBuddy"
PLUGIN_DESC = "Windows Kernel Driver Analysis Plugin"
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

def print_header():
    """Print ASCII art header"""
    log_info("╔═══════════════════════════════════════════════════════════════╗")
    log_info("║              DriverBuddy for Binary Ninja                    ║")
    log_info("║              Windows Kernel Driver Analysis                   ║")
    log_info("║                                                                ║")
    log_info("║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║")
    log_info("╚═══════════════════════════════════════════════════════════════╝")

def find_driver_entry(bv):
    """Find DriverEntry function"""
    log_info("[+] Searching for DriverEntry...")
    
    # Look for DriverEntry symbol
    for symbol in bv.symbols.get("DriverEntry", []):
        log_info(f"[+] Found DriverEntry at: {hex(symbol.address)}")
        return symbol.address
    
    # Search through functions
    for func in bv.functions:
        if func.name == "DriverEntry":
            log_info(f"[+] Found DriverEntry at: {hex(func.start)}")
            return func.start
    
    log_warn("[-] DriverEntry not found")
    return None

def determine_driver_type(bv):
    """Determine the type of Windows driver"""
    log_info("[+] Determining driver type...")
    
    driver_type = "WDM"  # Default to WDM
    
    # Check for WDF driver
    wdf_symbols = ["WdfVersionBind", "WdfDriverCreate"]
    for sym_name in wdf_symbols:
        if bv.symbols.get(sym_name):
            driver_type = "WDF"
            break
    
    # Check for filter driver
    if bv.symbols.get("FltRegisterFilter"):
        driver_type = "Mini-Filter"
    
    # Check for NDIS driver
    if bv.symbols.get("NdisRegisterProtocolDriver"):
        driver_type = "NDIS"
    
    log_info(f"[+] Driver type: {driver_type}")
    return driver_type

def find_dispatch_device_control(bv, driver_entry_addr):
    """Attempt to locate DispatchDeviceControl function"""
    log_info("[+] Searching for DispatchDeviceControl...")
    
    if not driver_entry_addr:
        return None
    
    funcs = bv.get_functions_at(driver_entry_addr)
    if not funcs:
        return None
    
    func = funcs[0]
    
    # Look for assignments to DRIVER_OBJECT.MajorFunction[0x0E]
    # This is typically at offset 0xE0 in the DRIVER_OBJECT structure
    found_handlers = []
    
    for block in func.mlil:
        for instr in block:
            # Look for store operations with offset 0xE0 or 0xE8
            if instr.operation == MediumLevelILOperation.MLIL_STORE:
                try:
                    dest = instr.dest
                    if hasattr(dest, 'offset'):
                        if dest.offset in [0xE0, 0xE8]:
                            log_info(f"[+] Possible DispatchDeviceControl assignment at: {hex(instr.address)}")
                            found_handlers.append(instr.address)
                except:
                    pass
    
    if not found_handlers:
        log_warn("[-] DispatchDeviceControl not found")
    
    return found_handlers

def find_dangerous_functions(bv):
    """Find and report dangerous C function calls"""
    log_info("[+] Searching for dangerous C functions...")
    found_count = 0
    
    for func_name in DANGEROUS_FUNCTIONS:
        symbols = bv.symbols.get(func_name, [])
        for symbol in symbols:
            refs = bv.get_code_refs(symbol.address)
            ref_list = list(refs)
            if len(ref_list) > 0:
                found_count += 1
                log_info(f"[+] Found {func_name} with {len(ref_list)} references")
                for ref in ref_list[:5]:  # Limit to first 5
                    log_info(f"    └─ Reference at: {hex(ref.address)}")
    
    if found_count == 0:
        log_warn("[-] No dangerous C functions detected")
    else:
        log_info(f"[+] Total dangerous functions found: {found_count}")

def find_interesting_winapi(bv):
    """Find interesting Windows API calls"""
    log_info("[+] Searching for interesting Windows API functions...")
    found_count = 0
    
    for api_prefix in INTERESTING_WINAPI:
        for symbol_name in bv.symbols:
            if symbol_name.startswith(api_prefix):
                symbols = bv.symbols.get(symbol_name, [])
                for symbol in symbols:
                    refs = bv.get_code_refs(symbol.address)
                    ref_list = list(refs)
                    if len(ref_list) > 0:
                        found_count += 1
                        log_info(f"[+] Found {symbol_name} with {len(ref_list)} references")
                        for ref in ref_list[:3]:  # Limit to first 3
                            log_info(f"    └─ Reference at: {hex(ref.address)}")
    
    if found_count == 0:
        log_warn("[-] No interesting Windows API functions detected")
    else:
        log_info(f"[+] Total interesting API functions found: {found_count}")

def decode_ioctl(ioctl_code):
    """Decode Windows IOCTL code"""
    device = (ioctl_code >> 16) & 0xFFFF
    access = (ioctl_code >> 14) & 0x3
    function = (ioctl_code >> 2) & 0xFFF
    method = ioctl_code & 0x3
    
    access_names = ['FILE_ANY_ACCESS', 'FILE_READ_ACCESS', 'FILE_WRITE_ACCESS', 'FILE_READ_ACCESS | FILE_WRITE_ACCESS']
    method_names = ['METHOD_BUFFERED', 'METHOD_IN_DIRECT', 'METHOD_OUT_DIRECT', 'METHOD_NEITHER']
    
    log_info(f"[+] IOCTL: 0x{ioctl_code:08X}")
    log_info(f"    Device   : 0x{device:04X}")
    log_info(f"    Function : 0x{function:03X}")
    log_info(f"    Method   : {method_names[method]}")
    log_info(f"    Access   : {access_names[access]}")

def find_ioctls(bv):
    """Search for IOCTL codes in the binary"""
    log_info("[+] Searching for IOCTLs...")
    found_ioctls = set()
    
    # Search for constant values that look like IOCTLs
    for func in bv.functions:
        for block in func.mlil:
            for instr in block:
                # Look for constant comparisons
                if instr.operation in [MediumLevelILOperation.MLIL_CMP_E, 
                                      MediumLevelILOperation.MLIL_CMP_NE]:
                    try:
                        for operand in [instr.left, instr.right]:
                            if hasattr(operand, 'constant'):
                                val = operand.constant
                                # Check if this looks like an IOCTL
                                if 0x00020000 < val < 0x00500000:
                                    if val not in found_ioctls:
                                        found_ioctls.add(val)
                                        decode_ioctl(val)
                    except:
                        pass
    
    if len(found_ioctls) == 0:
        log_warn("[-] No IOCTLs found")
    else:
        log_info(f"[+] Total IOCTLs found: {len(found_ioctls)}")

def analyze_driver(bv):
    """Main analysis routine"""
    print_header()
    log_info("[+] Starting DriverBuddy analysis...")
    log_info(f"[+] Binary: {bv.file.filename}")
    log_info("")
    
    # Find DriverEntry
    driver_entry = find_driver_entry(bv)
    if not driver_entry:
        log_warn("[-] This may not be a Windows driver")
        log_warn("[-] Exiting...")
        return
    
    log_info("")
    
    # Determine driver type
    driver_type = determine_driver_type(bv)
    log_info("")
    
    # Find dispatch functions
    find_dispatch_device_control(bv, driver_entry)
    log_info("")
    
    # Find dangerous functions
    find_dangerous_functions(bv)
    log_info("")
    
    # Find interesting WinAPI
    find_interesting_winapi(bv)
    log_info("")
    
    # Find IOCTLs
    find_ioctls(bv)
    log_info("")
    
    log_info("[+] DriverBuddy analysis complete!")
    log_info("╔═══════════════════════════════════════════════════════════════╗")
    log_info("║                    Analysis Complete                          ║")
    log_info("║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║")
    log_info("╚═══════════════════════════════════════════════════════════════╝")

def run_driver_buddy(bv):
    """Plugin entry point"""
    analyze_driver(bv)

# Register plugin
PluginCommand.register(
    "DriverBuddy\\Analyze Driver",
    "Analyze Windows kernel driver for security issues",
    run_driver_buddy
)
