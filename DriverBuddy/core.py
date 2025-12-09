"""
DriverBuddy Core Analysis Engine

    ☠ ☠ ☠ CORE DRIVER ANALYSIS FUNCTIONALITY ☠ ☠ ☠

This module contains the platform-independent driver analysis logic.
"""

import struct
import re
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum


class DriverType(Enum):
    """Windows driver types"""
    WDM = "WDM"
    WDF = "WDF" 
    KMDF = "KMDF"
    UMDF = "UMDF"
    UNKNOWN = "UNKNOWN"


class IOCTLInfo:
    """IOCTL code information"""
    def __init__(self, code: int):
        self.code = code
        self.device_type = (code >> 16) & 0xFFFF
        self.function = (code >> 2) & 0xFFF
        self.method = code & 0x3
        self.access = (code >> 14) & 0x3
        
    def __str__(self):
        methods = ["METHOD_BUFFERED", "METHOD_IN_DIRECT", "METHOD_OUT_DIRECT", "METHOD_NEITHER"]
        access_types = ["FILE_ANY_ACCESS", "FILE_READ_ACCESS", "FILE_WRITE_ACCESS", "FILE_READ_WRITE_ACCESS"]
        
        return (f"IOCTL Code: 0x{self.code:08X}\n"
                f"  Device Type: 0x{self.device_type:04X}\n"
                f"  Function: 0x{self.function:03X} ({self.function})\n"
                f"  Method: {methods[self.method]} ({self.method})\n"
                f"  Access: {access_types[self.access]} ({self.access})")


class DriverAnalyzer:
    """
    ☠ Main driver analysis engine ☠
    
    Platform-independent analysis of Windows kernel drivers
    """
    
    def __init__(self, platform_adapter):
        self.platform = platform_adapter
        self.driver_type = DriverType.UNKNOWN
        self.driver_entry = None
        self.dispatch_functions = {}
        self.ioctls = []
        self.dangerous_functions = []
        
        # Common dangerous functions in drivers
        self.dangerous_api_list = [
            'strcpy', 'strcat', 'sprintf', 'vsprintf', 'gets', 'scanf',
            'ProbeForRead', 'ProbeForWrite', 'memcpy', 'memmove',
            'RtlCopyMemory', 'RtlMoveMemory', 'ExAllocatePool',
            'ExAllocatePoolWithTag', 'IoAllocateMdl', 'MmMapLockedPages'
        ]
        
        # WDF function signatures for identification
        self.wdf_functions = [
            'WdfDriverCreate', 'WdfDeviceCreate', 'WdfIoQueueCreate',
            'WdfRequestRetrieveInputBuffer', 'WdfRequestRetrieveOutputBuffer',
            'WdfObjectDelete', 'WdfDeviceInitSetIoType'
        ]
        
        # Common driver dispatch function indices
        self.dispatch_indices = {
            0x0: 'IRP_MJ_CREATE',
            0x1: 'IRP_MJ_CREATE_NAMED_PIPE', 
            0x2: 'IRP_MJ_CLOSE',
            0x3: 'IRP_MJ_READ',
            0x4: 'IRP_MJ_WRITE',
            0x5: 'IRP_MJ_QUERY_INFORMATION',
            0x6: 'IRP_MJ_SET_INFORMATION',
            0x7: 'IRP_MJ_QUERY_EA',
            0x8: 'IRP_MJ_SET_EA',
            0x9: 'IRP_MJ_FLUSH_BUFFERS',
            0xA: 'IRP_MJ_QUERY_VOLUME_INFORMATION',
            0xB: 'IRP_MJ_SET_VOLUME_INFORMATION',
            0xC: 'IRP_MJ_DIRECTORY_CONTROL',
            0xD: 'IRP_MJ_FILE_SYSTEM_CONTROL',
            0xE: 'IRP_MJ_DEVICE_CONTROL',
            0xF: 'IRP_MJ_INTERNAL_DEVICE_CONTROL',
            0x10: 'IRP_MJ_SHUTDOWN',
            0x11: 'IRP_MJ_LOCK_CONTROL',
            0x12: 'IRP_MJ_CLEANUP',
            0x13: 'IRP_MJ_CREATE_MAILSLOT',
            0x14: 'IRP_MJ_QUERY_SECURITY',
            0x15: 'IRP_MJ_SET_SECURITY',
            0x16: 'IRP_MJ_POWER',
            0x17: 'IRP_MJ_SYSTEM_CONTROL',
            0x18: 'IRP_MJ_DEVICE_CHANGE',
            0x19: 'IRP_MJ_QUERY_QUOTA',
            0x1A: 'IRP_MJ_SET_QUOTA',
            0x1B: 'IRP_MJ_PNP'
        }

    def analyze_driver(self) -> bool:
        """
        ☠ Main analysis entry point ☠
        
        Performs comprehensive driver analysis
        """
        self.platform.log("[+] Starting DriverBuddy analysis...")
        
        # Wait for platform analysis to complete
        self.platform.wait_for_analysis()
        
        # Find driver entry point
        if not self._find_driver_entry():
            self.platform.log("[-] No DriverEntry function found")
            return False
            
        self.platform.log(f"[+] DriverEntry found at: {hex(self.driver_entry)}")
        
        # Determine driver type
        self._identify_driver_type()
        self.platform.log(f"[+] Driver type: {self.driver_type.value}")
        
        # Find dispatch functions
        self._find_dispatch_functions()
        
        # Find IOCTLs
        self._find_ioctls()
        
        # Flag dangerous functions
        self._flag_dangerous_functions()
        
        # Apply labels and comments
        self._apply_analysis_results()
        
        self.platform.log("[+] Analysis complete!")
        return True
    
    def _find_driver_entry(self) -> bool:
        """Find the DriverEntry function"""
        # Look for DriverEntry export
        entry = self.platform.get_function_by_name("DriverEntry")
        if entry:
            self.driver_entry = entry
            return True
            
        # Look for function that takes DRIVER_OBJECT and UNICODE_STRING parameters
        functions = self.platform.get_all_functions()
        for func_addr in functions:
            # Check if function signature matches DriverEntry pattern
            if self._is_driver_entry_candidate(func_addr):
                self.driver_entry = func_addr
                return True
                
        return False
    
    def _is_driver_entry_candidate(self, func_addr: int) -> bool:
        """Check if function could be DriverEntry based on signature and content"""
        # Get function instructions
        instructions = self.platform.get_function_instructions(func_addr)
        
        # Look for patterns typical in DriverEntry:
        # - Setting up driver object dispatch table
        # - Calls to IoCreateDevice or WdfDriverCreate
        patterns = [
            r'mov.*DriverObject',
            r'call.*IoCreateDevice',
            r'call.*WdfDriverCreate',
            r'mov.*MajorFunction'
        ]
        
        matches = 0
        for instr in instructions:
            for pattern in patterns:
                if re.search(pattern, instr, re.IGNORECASE):
                    matches += 1
                    
        return matches >= 2
    
    def _identify_driver_type(self):
        """Identify if this is WDM, WDF, KMDF, or UMDF driver"""
        if not self.driver_entry:
            return
            
        # Check for WDF imports
        imports = self.platform.get_imports()
        wdf_imports = [imp for imp in imports if any(wdf_func in imp for wdf_func in self.wdf_functions)]
        
        if wdf_imports:
            # Check if it's KMDF or UMDF based on imports
            if any('Wdf' in imp and 'Kernel' in imp for imp in imports):
                self.driver_type = DriverType.KMDF
            elif any('Wdf' in imp and 'User' in imp for imp in imports):
                self.driver_type = DriverType.UMDF
            else:
                self.driver_type = DriverType.WDF
        else:
            # Assume WDM if no WDF imports found
            self.driver_type = DriverType.WDM
    
    def _find_dispatch_functions(self):
        """Find IRP dispatch functions"""
        if not self.driver_entry:
            return
            
        # Analyze DriverEntry to find dispatch table setup
        instructions = self.platform.get_function_instructions(self.driver_entry)
        
        for instr in instructions:
            # Look for MajorFunction array assignments
            # Pattern: mov [reg+offset], function_addr
            match = re.search(r'mov.*\[.*\+0x([0-9A-Fa-f]+)\].*0x([0-9A-Fa-f]+)', instr)
            if match:
                offset = int(match.group(1), 16)
                func_addr = int(match.group(2), 16)
                
                # Check if offset corresponds to a known dispatch index
                dispatch_index = offset // self.platform.get_pointer_size()
                if dispatch_index in self.dispatch_indices:
                    dispatch_name = self.dispatch_indices[dispatch_index]
                    self.dispatch_functions[dispatch_name] = func_addr
                    self.platform.log(f"[+] Found {dispatch_name} at {hex(func_addr)}")
    
    def _find_ioctls(self):
        """Find and decode IOCTL codes in the binary"""
        # Look for IOCTL constants (typically 4-byte values starting with specific patterns)
        data_sections = self.platform.get_data_sections()
        
        for section_start, section_end in data_sections:
            addr = section_start
            while addr < section_end - 4:
                try:
                    value = self.platform.read_dword(addr)
                    if self._is_potential_ioctl(value):
                        ioctl_info = IOCTLInfo(value)
                        self.ioctls.append((addr, ioctl_info))
                        self.platform.log(f"[+] Potential IOCTL found at {hex(addr)}: {hex(value)}")
                except:
                    pass
                addr += 4
    
    def _is_potential_ioctl(self, value: int) -> bool:
        """Check if a value could be an IOCTL code"""
        # IOCTL codes have specific bit patterns
        if value == 0 or value == 0xFFFFFFFF:
            return False
            
        # Check device type (should be reasonable)
        device_type = (value >> 16) & 0xFFFF
        if device_type == 0 or device_type > 0x8000:
            return False
            
        # Check method (should be 0-3)
        method = value & 0x3
        if method > 3:
            return False
            
        return True
    
    def _flag_dangerous_functions(self):
        """Flag potentially dangerous function calls"""
        imports = self.platform.get_imports()
        
        for dangerous_func in self.dangerous_api_list:
            if dangerous_func in imports:
                # Find all references to this function
                refs = self.platform.get_function_references(dangerous_func)
                for ref in refs:
                    self.dangerous_functions.append((ref, dangerous_func))
                    self.platform.log(f"[!] Dangerous function {dangerous_func} called at {hex(ref)}")
    
    def _apply_analysis_results(self):
        """Apply comments, labels, and other analysis results to the binary"""
        # Label DriverEntry
        if self.driver_entry:
            self.platform.set_function_name(self.driver_entry, "DriverEntry")
            self.platform.add_comment(self.driver_entry, "☠ Driver Entry Point ☠")
        
        # Label dispatch functions
        for dispatch_name, func_addr in self.dispatch_functions.items():
            self.platform.set_function_name(func_addr, f"Dispatch_{dispatch_name.split('_')[-1]}")
            self.platform.add_comment(func_addr, f"☠ {dispatch_name} Handler ☠")
        
        # Comment IOCTLs
        for addr, ioctl_info in self.ioctls:
            comment = f"☠ IOCTL: 0x{ioctl_info.code:08X} ☠\n{str(ioctl_info)}"
            self.platform.add_comment(addr, comment)
        
        # Comment dangerous functions
        for addr, func_name in self.dangerous_functions:
            self.platform.add_comment(addr, f"☠ DANGEROUS: {func_name} ☠")
    
    def decode_ioctl(self, code: int) -> str:
        """Decode a specific IOCTL code"""
        ioctl_info = IOCTLInfo(code)
        return str(ioctl_info)
    
    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get a summary of the analysis results"""
        return {
            'driver_type': self.driver_type.value,
            'driver_entry': hex(self.driver_entry) if self.driver_entry else None,
            'dispatch_functions': {name: hex(addr) for name, addr in self.dispatch_functions.items()},
            'ioctl_count': len(self.ioctls),
            'dangerous_function_count': len(self.dangerous_functions)
        }