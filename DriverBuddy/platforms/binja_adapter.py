"""
Binary Ninja Platform Adapter

    ☠ ☠ ☠ BINARY NINJA INTEGRATION ☠ ☠ ☠

Binary Ninja adapter using the Python API
"""

from typing import List, Tuple, Optional
from .base import PlatformAdapter

try:
    import binaryninja as binja
    from binaryninja import BinaryView, Function, log_info, log_warn
    BINJA_AVAILABLE = True
except ImportError:
    BINJA_AVAILABLE = False


class BinaryNinjaAdapter(PlatformAdapter):
    """
    ☠ Binary Ninja platform adapter ☠
    
    Supports Binary Ninja 3.x and later
    """
    
    def __init__(self, bv: BinaryView = None):
        if not BINJA_AVAILABLE:
            raise RuntimeError("☠ Binary Ninja not available! ☠")
        
        # Get current binary view
        if bv is None:
            # Try to get from current context
            try:
                import __main__
                if hasattr(__main__, 'current_view'):
                    self.bv = __main__.current_view
                elif hasattr(__main__, 'bv'):
                    self.bv = __main__.bv
                else:
                    raise RuntimeError("☠ No Binary Ninja BinaryView available! ☠")
            except:
                raise RuntimeError("☠ Failed to get Binary Ninja context! ☠")
        else:
            self.bv = bv
        
        self.log(f"[+] Binary Ninja detected - File: {self.bv.file.filename}")
    
    def get_platform_name(self) -> str:
        return "Binary Ninja"
    
    def get_platform_version(self) -> str:
        return binja.core_version()
    
    def log(self, message: str) -> None:
        log_info(message)
        print(message)  # Also print to console
    
    def wait_for_analysis(self) -> None:
        # Wait for analysis to complete
        self.bv.update_analysis_and_wait()
    
    def get_function_by_name(self, name: str) -> Optional[int]:
        symbols = self.bv.get_symbols_by_name(name)
        for symbol in symbols:
            if symbol.type == binja.SymbolType.FunctionSymbol:
                return symbol.address
        return None
    
    def get_all_functions(self) -> List[int]:
        return [func.start for func in self.bv.functions]
    
    def get_function_instructions(self, func_addr: int) -> List[str]:
        instructions = []
        func = self.bv.get_function_at(func_addr)
        if func:
            for block in func.basic_blocks:
                for instr in block:
                    instructions.append(f"{instr[0].mnemonic} {instr[0].operand_string}")
        return instructions
    
    def get_imports(self) -> List[str]:
        imports = []
        for symbol in self.bv.symbols.values():
            if symbol.type == binja.SymbolType.ImportedFunctionSymbol:
                imports.append(symbol.name)
        return imports
    
    def get_function_references(self, func_name: str) -> List[int]:
        refs = []
        func_addr = self.get_function_by_name(func_name)
        if func_addr:
            for ref in self.bv.get_code_refs(func_addr):
                refs.append(ref)
        return refs
    
    def get_data_sections(self) -> List[Tuple[int, int]]:
        sections = []
        for section in self.bv.sections.values():
            # Check if it's a data section (readable but not executable)
            if not (section.semantics & binja.SectionSemantics.ReadOnlyCodeSectionSemantics):
                if (section.semantics & binja.SectionSemantics.ReadOnlyDataSectionSemantics or
                    section.semantics & binja.SectionSemantics.ReadWriteDataSectionSemantics):
                    sections.append((section.start, section.end))
        return sections
    
    def read_dword(self, addr: int) -> int:
        try:
            data = self.bv.read(addr, 4)
            if len(data) == 4:
                return int.from_bytes(data, byteorder='little')
        except:
            pass
        return 0
    
    def get_pointer_size(self) -> int:
        return self.bv.address_size
    
    def set_function_name(self, addr: int, name: str) -> None:
        func = self.bv.get_function_at(addr)
        if func:
            func.name = name
    
    def add_comment(self, addr: int, comment: str) -> None:
        func = self.bv.get_function_at(addr)
        if func:
            func.set_comment_at(addr, comment)
        else:
            # Set a data comment if not in a function
            self.bv.set_comment_at(addr, comment)
    
    def get_current_address(self) -> int:
        # Binary Ninja doesn't have a direct "current address" concept
        # This would need to be provided by the UI context
        return 0
    
    def get_operand_value(self, addr: int, operand_index: int) -> Optional[int]:
        try:
            # Get instruction at address
            instructions = self.bv.get_disassembly(addr, 1)
            if instructions:
                # Parse instruction for immediate values
                # This is a simplified implementation
                instr_text = instructions[0].text
                # Look for hex values in the instruction
                import re
                hex_matches = re.findall(r'0x[0-9a-fA-F]+', instr_text)
                if operand_index < len(hex_matches):
                    return int(hex_matches[operand_index], 16)
        except:
            pass
        return None