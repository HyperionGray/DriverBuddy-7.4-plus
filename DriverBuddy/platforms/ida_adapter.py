"""
IDA Pro Platform Adapter

    ☠ ☠ ☠ IDA PRO INTEGRATION ☠ ☠ ☠

Modern IDA Pro adapter supporting IDA 7.x and 8.x
"""

from typing import List, Tuple, Optional
from .base import PlatformAdapter

try:
    import idaapi
    import idautils
    import idc
    from ida_auto import auto_wait
    from ida_funcs import get_func
    from ida_segment import get_segm_by_name, get_first_seg
    from ida_name import set_name
    from ida_bytes import get_dword
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False


class IDAAdapter(PlatformAdapter):
    """
    ☠ IDA Pro platform adapter ☠
    
    Supports IDA Pro 7.x and 8.x with modern Python 3 API
    """
    
    def __init__(self):
        if not IDA_AVAILABLE:
            raise RuntimeError("☠ IDA Pro not available! ☠")
        
        # Check IDA version compatibility
        ida_version = idaapi.get_kernel_version()
        if ida_version.startswith('7.') or ida_version.startswith('8.'):
            self.log(f"[+] IDA Pro {ida_version} detected")
        else:
            self.log(f"[!] Warning: Untested IDA version {ida_version}")
    
    def get_platform_name(self) -> str:
        return "IDA Pro"
    
    def get_platform_version(self) -> str:
        return idaapi.get_kernel_version()
    
    def log(self, message: str) -> None:
        print(message)
    
    def wait_for_analysis(self) -> None:
        auto_wait()
    
    def get_function_by_name(self, name: str) -> Optional[int]:
        addr = idc.get_name_ea_simple(name)
        return addr if addr != idc.BADADDR else None
    
    def get_all_functions(self) -> List[int]:
        return list(idautils.Functions())
    
    def get_function_instructions(self, func_addr: int) -> List[str]:
        instructions = []
        func = get_func(func_addr)
        if not func:
            return instructions
        
        addr = func.start_ea
        while addr < func.end_ea:
            disasm = idc.GetDisasm(addr)
            if disasm:
                instructions.append(disasm)
            addr = idc.next_head(addr)
        
        return instructions
    
    def get_imports(self) -> List[str]:
        imports = []
        
        # Get imports from import table
        for i in range(idaapi.get_import_module_qty()):
            module_name = idaapi.get_import_module_name(i)
            if module_name:
                def imp_cb(ea, name, ordinal):
                    if name:
                        imports.append(name)
                    return True
                
                idaapi.enum_import_names(i, imp_cb)
        
        return imports
    
    def get_function_references(self, func_name: str) -> List[int]:
        func_addr = self.get_function_by_name(func_name)
        if not func_addr:
            return []
        
        refs = []
        for ref in idautils.CodeRefsTo(func_addr, 0):
            refs.append(ref)
        
        return refs
    
    def get_data_sections(self) -> List[Tuple[int, int]]:
        sections = []
        
        # Iterate through all segments
        seg = get_first_seg()
        while seg:
            # Check if it's a data section (not code)
            if seg.type == idaapi.SEG_DATA or seg.type == idaapi.SEG_BSS:
                sections.append((seg.start_ea, seg.end_ea))
            seg = idaapi.get_next_seg(seg.start_ea)
        
        return sections
    
    def read_dword(self, addr: int) -> int:
        return get_dword(addr)
    
    def get_pointer_size(self) -> int:
        info = idaapi.get_inf_structure()
        return 8 if info.is_64bit() else 4
    
    def set_function_name(self, addr: int, name: str) -> None:
        set_name(addr, name, idaapi.SN_FORCE)
    
    def add_comment(self, addr: int, comment: str) -> None:
        idc.set_cmt(addr, comment, 1)  # 1 for repeatable comment
    
    def get_current_address(self) -> int:
        return idc.get_screen_ea()
    
    def get_operand_value(self, addr: int, operand_index: int) -> Optional[int]:
        op_type = idc.get_operand_type(addr, operand_index)
        if op_type == idc.o_imm:  # Immediate value
            return idc.get_operand_value(addr, operand_index)
        return None