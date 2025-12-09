# DriverBuddy for Ghidra
# Windows Driver Analysis Script for Ghidra
# Based on the original DriverBuddy by NCC Group
# Modernized for Ghidra 10.x+

from ghidra.program.model.symbol import SourceType
from ghidra.program.model.listing import CodeUnit
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║              DriverBuddy for Ghidra                           ║
    ║              Windows Kernel Driver Analysis                   ║
    ║                                                                ║
    ║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║
    ╚═══════════════════════════════════════════════════════════════╝
""")

# Get current program
program = currentProgram
listing = program.getListing()
symbolTable = program.getSymbolTable()
functionManager = program.getFunctionManager()
memory = program.getMemory()
monitor = ConsoleTaskMonitor()

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

def find_driver_entry():
    """Find DriverEntry function"""
    driver_entry = symbolTable.getExternalSymbol("DriverEntry")
    if driver_entry:
        print("[+] Found DriverEntry at: {}".format(driver_entry.getAddress()))
        return driver_entry.getAddress()
    
    # Search for DriverEntry in functions
    for func in functionManager.getFunctions(True):
        if func.getName() == "DriverEntry":
            print("[+] Found DriverEntry at: {}".format(func.getEntryPoint()))
            return func.getEntryPoint()
    
    print("[-] DriverEntry not found")
    return None

def find_dispatch_device_control():
    """Attempt to locate DispatchDeviceControl function"""
    print("[+] Searching for DispatchDeviceControl...")
    
    # Look for MajorFunction[0x0E] assignment (IRP_MJ_DEVICE_CONTROL)
    # This is typically at offset 0xE0 in DRIVER_OBJECT
    driver_entry = find_driver_entry()
    if not driver_entry:
        return []
    
    func = functionManager.getFunctionAt(driver_entry)
    if not func:
        return []
    
    found_handlers = []
    # Search for references to offset 0xE0 (DispatchDeviceControl)
    for ref in func.getBody().getAddresses(True):
        instruction = listing.getInstructionAt(ref)
        if instruction:
            # Look for MOV instructions with offset 0xE0
            if "0xe0" in str(instruction).lower() or "0xe8" in str(instruction).lower():
                print("[+] Possible DispatchDeviceControl reference at: {}".format(ref))
    
    return found_handlers

def find_dangerous_functions():
    """Find and report dangerous C function calls"""
    print("[+] Searching for dangerous C functions...")
    found_count = 0
    
    for func_name in DANGEROUS_FUNCTIONS:
        symbols = symbolTable.getSymbols(func_name)
        for symbol in symbols:
            refs = symbol.getReferences()
            if len(refs) > 0:
                found_count += 1
                print("[+] Found {} with {} references".format(func_name, len(refs)))
                for ref in refs[:5]:  # Limit to first 5 references
                    print("    └─ Reference at: {}".format(ref.getFromAddress()))
    
    if found_count == 0:
        print("[-] No dangerous C functions detected")
    else:
        print("[+] Total dangerous functions found: {}".format(found_count))

def find_interesting_winapi():
    """Find interesting Windows API calls"""
    print("[+] Searching for interesting Windows API functions...")
    found_count = 0
    
    for api_prefix in INTERESTING_WINAPI:
        # Search for symbols starting with this prefix
        for symbol in symbolTable.getAllSymbols(True):
            symbol_name = symbol.getName()
            if symbol_name.startswith(api_prefix):
                refs = symbol.getReferences()
                if len(refs) > 0:
                    found_count += 1
                    print("[+] Found {} with {} references".format(symbol_name, len(refs)))
                    for ref in refs[:3]:  # Limit to first 3 references
                        print("    └─ Reference at: {}".format(ref.getFromAddress()))
    
    if found_count == 0:
        print("[-] No interesting Windows API functions detected")
    else:
        print("[+] Total interesting API functions found: {}".format(found_count))

def decode_ioctl(ioctl_code):
    """Decode Windows IOCTL code"""
    device = (ioctl_code >> 16) & 0xFFFF
    access = (ioctl_code >> 14) & 0x3
    function = (ioctl_code >> 2) & 0xFFF
    method = ioctl_code & 0x3
    
    access_names = ['FILE_ANY_ACCESS', 'FILE_READ_ACCESS', 'FILE_WRITE_ACCESS', 'FILE_READ_ACCESS | FILE_WRITE_ACCESS']
    method_names = ['METHOD_BUFFERED', 'METHOD_IN_DIRECT', 'METHOD_OUT_DIRECT', 'METHOD_NEITHER']
    
    print("[+] IOCTL: 0x{:08X}".format(ioctl_code))
    print("    Device   : 0x{:04X}".format(device))
    print("    Function : 0x{:03X}".format(function))
    print("    Method   : {}".format(method_names[method]))
    print("    Access   : {}".format(access_names[access]))

def find_ioctls():
    """Search for IOCTL codes in the binary"""
    print("[+] Searching for IOCTLs...")
    found_ioctls = []
    
    # Search for patterns that look like IOCTL codes
    # IOCTLs typically have bits set in specific positions
    for func in functionManager.getFunctions(True):
        for ref in func.getBody().getAddresses(True):
            instruction = listing.getInstructionAt(ref)
            if instruction:
                # Look for CMP or MOV with immediate values that look like IOCTLs
                mnemonic = instruction.getMnemonicString()
                if mnemonic in ["CMP", "MOV", "TEST"]:
                    for i in range(instruction.getNumOperands()):
                        op = instruction.getOpObjects(i)
                        if op and len(op) > 0:
                            try:
                                val = instruction.getScalar(i)
                                if val:
                                    val_int = val.getValue()
                                    # Check if this looks like an IOCTL (high bits set)
                                    if val_int > 0x00020000 and val_int < 0x00500000:
                                        if val_int not in found_ioctls:
                                            found_ioctls.append(val_int)
                                            decode_ioctl(val_int)
                            except:
                                pass
    
    if len(found_ioctls) == 0:
        print("[-] No IOCTLs found")
    else:
        print("[+] Total IOCTLs found: {}".format(len(found_ioctls)))

def determine_driver_type():
    """Determine the type of Windows driver"""
    print("[+] Determining driver type...")
    
    driver_type = "WDM"  # Default to WDM
    
    # Check for WDF driver
    wdf_symbols = ["WdfVersionBind", "WdfDriverCreate"]
    for sym_name in wdf_symbols:
        if symbolTable.getSymbol(sym_name, None):
            driver_type = "WDF"
            break
    
    # Check for filter driver
    if symbolTable.getSymbol("FltRegisterFilter", None):
        driver_type = "Mini-Filter"
    
    # Check for NDIS driver
    if symbolTable.getSymbol("NdisRegisterProtocolDriver", None):
        driver_type = "NDIS"
    
    print("[+] Driver type: {}".format(driver_type))
    return driver_type

def main():
    """Main analysis routine"""
    print("[+] Starting DriverBuddy analysis...")
    print("[+] Program: {}".format(program.getName()))
    print("")
    
    # Find DriverEntry
    driver_entry = find_driver_entry()
    if not driver_entry:
        print("[-] This may not be a Windows driver")
        print("[-] Exiting...")
        return
    
    print("")
    
    # Determine driver type
    driver_type = determine_driver_type()
    print("")
    
    # Find dispatch functions
    find_dispatch_device_control()
    print("")
    
    # Find dangerous functions
    find_dangerous_functions()
    print("")
    
    # Find interesting WinAPI
    find_interesting_winapi()
    print("")
    
    # Find IOCTLs
    find_ioctls()
    print("")
    
    print("[+] DriverBuddy analysis complete!")
    print("""
    ╔═══════════════════════════════════════════════════════════════╗
    ║                    Analysis Complete                          ║
    ║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

# Run the analysis
if __name__ == '__main__':
    main()
