"""
Ghidra Platform Adapter

    ☠ ☠ ☠ GHIDRA INTEGRATION ☠ ☠ ☠

Ghidra adapter using Jython/Python bridge
"""

from typing import List, Tuple, Optional
from .base import PlatformAdapter

try:
    # Ghidra imports (available when running in Ghidra)
    from ghidra.program.model.listing import CodeUnit
    from ghidra.program.model.symbol import SymbolType
    from ghidra.program.model.address import Address
    from ghidra.app.script import GhidraScript
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.app.services import DataTypeManagerService
    from ghidra.program.model.mem import MemoryAccessException
    import ghidra.program.model.listing.Function as GhidraFunction
    GHIDRA_AVAILABLE = True
except ImportError:
    GHIDRA_AVAILABLE = False


class GhidraAdapter(PlatformAdapter):
    """
    ☠ Ghidra platform adapter ☠
    
    Supports Ghidra 10.x and later
    """
    
    def __init__(self):
        if not GHIDRA_AVAILABLE:
            raise RuntimeError("☠ Ghidra not available! ☠")
        
        # Get current program and other Ghidra objects
        try:
            from __main__ import currentProgram, state
            self.program = currentProgram
            self.state = state
            self.listing = self.program.getListing()
            self.memory = self.program.getMemory()
            self.symbol_table = self.program.getSymbolTable()
            self.function_manager = self.program.getFunctionManager()
            self.address_factory = self.program.getAddressFactory()
            
            self.log(f"[+] Ghidra detected - Program: {self.program.getName()}")
        except:
            raise RuntimeError("☠ Failed to initialize Ghidra environment! ☠")
    
    def get_platform_name(self) -> str:
        return "Ghidra"
    
    def get_platform_version(self) -> str:
        try:
            from ghidra.framework import Application
            return Application.getApplicationVersion()
        except:
            return "Unknown"
    
    def log(self, message: str) -> None:
        print(message)
    
    def wait_for_analysis(self) -> None:
        # Ghidra auto-analysis is typically complete when script runs
        # But we can check if analysis is still running
        from ghidra.app.services import AnalyzerManager
        try:
            analyzer_mgr = self.state.getTool().getService(AnalyzerManager)
            if analyzer_mgr and analyzer_mgr.isAnalyzing():
                self.log("[+] Waiting for Ghidra analysis to complete...")
                # Note: In practice, scripts usually run after analysis
        except:
            pass
    
    def get_function_by_name(self, name: str) -> Optional[int]:
        symbols = self.symbol_table.getSymbols(name)
        for symbol in symbols:
            if symbol.getSymbolType() == SymbolType.FUNCTION:
                return int(symbol.getAddress().getOffset())
        return None
    
    def get_all_functions(self) -> List[int]:
        functions = []
        func_iter = self.function_manager.getFunctions(True)
        for func in func_iter:
            functions.append(int(func.getEntryPoint().getOffset()))
        return functions
    
    def get_function_instructions(self, func_addr: int) -> List[str]:
        instructions = []
        try:
            addr = self.address_factory.getDefaultAddressSpace().getAddress(func_addr)
            func = self.function_manager.getFunctionAt(addr)
            if func:
                body = func.getBody()
                instr_iter = self.listing.getInstructions(body, True)
                for instr in instr_iter:
                    instructions.append(str(instr))
        except:
            pass
        return instructions
    
    def get_imports(self) -> List[str]:
        imports = []
        # Get external symbols (imports)
        symbol_iter = self.symbol_table.getExternalSymbols()
        for symbol in symbol_iter:
            imports.append(symbol.getName())
        return imports
    
    def get_function_references(self, func_name: str) -> List[int]:
        refs = []
        func_addr = self.get_function_by_name(func_name)
        if func_addr:
            try:
                addr = self.address_factory.getDefaultAddressSpace().getAddress(func_addr)
                ref_iter = self.program.getReferenceManager().getReferencesTo(addr)
                for ref in ref_iter:
                    refs.append(int(ref.getFromAddress().getOffset()))
            except:
                pass
        return refs
    
    def get_data_sections(self) -> List[Tuple[int, int]]:
        sections = []
        memory_blocks = self.memory.getBlocks()
        for block in memory_blocks:
            # Check if it's a data block (not executable)
            if not block.isExecute() and (block.isRead() or block.isWrite()):
                start = int(block.getStart().getOffset())
                end = int(block.getEnd().getOffset())
                sections.append((start, end))
        return sections
    
    def read_dword(self, addr: int) -> int:
        try:
            address = self.address_factory.getDefaultAddressSpace().getAddress(addr)
            return self.memory.getInt(address) & 0xFFFFFFFF
        except MemoryAccessException:
            return 0
    
    def get_pointer_size(self) -> int:
        return self.program.getDefaultPointerSize()
    
    def set_function_name(self, addr: int, name: str) -> None:
        try:
            address = self.address_factory.getDefaultAddressSpace().getAddress(addr)
            func = self.function_manager.getFunctionAt(address)
            if func:
                func.setName(name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
        except:
            pass
    
    def add_comment(self, addr: int, comment: str) -> None:
        try:
            address = self.address_factory.getDefaultAddressSpace().getAddress(addr)
            self.listing.setComment(address, CodeUnit.PLATE_COMMENT, comment)
        except:
            pass
    
    def get_current_address(self) -> int:
        try:
            current_addr = self.state.getCurrentAddress()
            return int(current_addr.getOffset()) if current_addr else 0
        except:
            return 0
    
    def get_operand_value(self, addr: int, operand_index: int) -> Optional[int]:
        try:
            address = self.address_factory.getDefaultAddressSpace().getAddress(addr)
            instr = self.listing.getInstructionAt(address)
            if instr and operand_index < instr.getNumOperands():
                operand = instr.getOpObjects(operand_index)
                if operand and len(operand) > 0:
                    # Check if it's a scalar (immediate value)
                    if hasattr(operand[0], 'getValue'):
                        return int(operand[0].getValue())
        except:
            pass
        return None