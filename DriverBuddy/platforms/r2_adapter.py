"""
Radare2 Platform Adapter

    ☠ ☠ ☠ RADARE2 INTEGRATION ☠ ☠ ☠

Radare2 adapter using r2pipe
"""

from typing import List, Tuple, Optional
from .base import PlatformAdapter
import json
import re

try:
    import r2pipe
    R2_AVAILABLE = True
except ImportError:
    R2_AVAILABLE = False


class Radare2Adapter(PlatformAdapter):
    """
    ☠ Radare2 platform adapter ☠
    
    Supports Radare2 5.x and later via r2pipe
    """
    
    def __init__(self, r2_instance=None):
        if not R2_AVAILABLE:
            raise RuntimeError("☠ Radare2/r2pipe not available! ☠")
        
        if r2_instance is None:
            # Try to connect to existing r2 instance
            try:
                self.r2 = r2pipe.open()
            except:
                raise RuntimeError("☠ Failed to connect to Radare2! ☠\n"
                                 "Make sure r2 is running and accessible.")
        else:
            self.r2 = r2_instance
        
        # Get basic info
        info = self.r2.cmdj("ij")
        if info:
            filename = info.get('core', {}).get('file', 'unknown')
            self.log(f"[+] Radare2 detected - File: {filename}")
    
    def get_platform_name(self) -> str:
        return "Radare2"
    
    def get_platform_version(self) -> str:
        try:
            version_info = self.r2.cmd("?V")
            return version_info.strip()
        except:
            return "Unknown"
    
    def log(self, message: str) -> None:
        print(message)
        # Also log to r2 console
        try:
            self.r2.cmd(f'echo "{message}"')
        except:
            pass
    
    def wait_for_analysis(self) -> None:
        # Run full analysis
        self.log("[+] Running Radare2 analysis...")
        self.r2.cmd("aaa")  # Analyze all
    
    def get_function_by_name(self, name: str) -> Optional[int]:
        try:
            result = self.r2.cmd(f"afl~{name}")
            if result:
                # Parse function list output
                lines = result.strip().split('\n')
                for line in lines:
                    if name in line:
                        parts = line.split()
                        if len(parts) >= 1:
                            addr_str = parts[0]
                            return int(addr_str, 16)
        except:
            pass
        return None
    
    def get_all_functions(self) -> List[int]:
        functions = []
        try:
            func_list = self.r2.cmdj("aflj")
            if func_list:
                for func in func_list:
                    functions.append(func.get('offset', 0))
        except:
            pass
        return functions
    
    def get_function_instructions(self, func_addr: int) -> List[str]:
        instructions = []
        try:
            # Disassemble function
            disasm = self.r2.cmd(f"pdf @ {func_addr:#x}")
            if disasm:
                lines = disasm.split('\n')
                for line in lines:
                    # Extract instruction part (skip addresses and bytes)
                    if '│' in line or '└' in line or '┌' in line:
                        # Parse r2 disassembly format
                        parts = line.split()
                        if len(parts) >= 3:
                            # Find the instruction mnemonic and operands
                            instr_start = -1
                            for i, part in enumerate(parts):
                                if not part.startswith('0x') and not part.startswith('│') and not part.startswith('└') and not part.startswith('┌'):
                                    instr_start = i
                                    break
                            if instr_start >= 0:
                                instructions.append(' '.join(parts[instr_start:]))
        except:
            pass
        return instructions
    
    def get_imports(self) -> List[str]:
        imports = []
        try:
            import_list = self.r2.cmdj("iij")
            if import_list:
                for imp in import_list:
                    name = imp.get('name', '')
                    if name:
                        imports.append(name)
        except:
            pass
        return imports
    
    def get_function_references(self, func_name: str) -> List[int]:
        refs = []
        func_addr = self.get_function_by_name(func_name)
        if func_addr:
            try:
                # Get cross-references to the function
                xrefs = self.r2.cmdj(f"axtj @ {func_addr:#x}")
                if xrefs:
                    for xref in xrefs:
                        refs.append(xref.get('from', 0))
            except:
                pass
        return refs
    
    def get_data_sections(self) -> List[Tuple[int, int]]:
        sections = []
        try:
            section_list = self.r2.cmdj("iSj")
            if section_list:
                for section in section_list:
                    # Check if it's a data section (not executable)
                    perm = section.get('perm', '')
                    if 'x' not in perm and ('r' in perm or 'w' in perm):
                        start = section.get('vaddr', 0)
                        size = section.get('vsize', 0)
                        if start and size:
                            sections.append((start, start + size))
        except:
            pass
        return sections
    
    def read_dword(self, addr: int) -> int:
        try:
            # Read 4 bytes as hex
            result = self.r2.cmd(f"p8 4 @ {addr:#x}")
            if result:
                hex_bytes = result.strip()
                # Convert hex string to int (little endian)
                if len(hex_bytes) == 8:  # 4 bytes = 8 hex chars
                    # Reverse byte order for little endian
                    bytes_le = ''.join(reversed([hex_bytes[i:i+2] for i in range(0, 8, 2)]))
                    return int(bytes_le, 16)
        except:
            pass
        return 0
    
    def get_pointer_size(self) -> int:
        try:
            info = self.r2.cmdj("ij")
            if info:
                bits = info.get('bin', {}).get('bits', 32)
                return bits // 8
        except:
            pass
        return 4  # Default to 32-bit
    
    def set_function_name(self, addr: int, name: str) -> None:
        try:
            self.r2.cmd(f"afn {name} @ {addr:#x}")
        except:
            pass
    
    def add_comment(self, addr: int, comment: str) -> None:
        try:
            # Escape comment for r2
            escaped_comment = comment.replace('"', '\\"')
            self.r2.cmd(f'CC "{escaped_comment}" @ {addr:#x}')
        except:
            pass
    
    def get_current_address(self) -> int:
        try:
            # Get current seek position
            result = self.r2.cmd("s")
            if result:
                return int(result.strip(), 16)
        except:
            pass
        return 0
    
    def get_operand_value(self, addr: int, operand_index: int) -> Optional[int]:
        try:
            # Get instruction at address
            instr = self.r2.cmd(f"pi 1 @ {addr:#x}")
            if instr:
                # Look for immediate values (hex numbers)
                hex_matches = re.findall(r'0x[0-9a-fA-F]+', instr)
                if operand_index < len(hex_matches):
                    return int(hex_matches[operand_index], 16)
        except:
            pass
        return None