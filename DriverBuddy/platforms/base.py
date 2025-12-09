"""
Base Platform Adapter

    ☠ ☠ ☠ ABSTRACT PLATFORM INTERFACE ☠ ☠ ☠

Defines the interface that all platform adapters must implement.
"""

from abc import ABC, abstractmethod
from typing import List, Tuple, Optional, Dict, Any


class PlatformAdapter(ABC):
    """
    ☠ Abstract base class for platform adapters ☠
    
    All reverse engineering platform adapters must implement these methods.
    """
    
    @abstractmethod
    def get_platform_name(self) -> str:
        """Get the name of the platform (IDA, Ghidra, etc.)"""
        pass
    
    @abstractmethod
    def get_platform_version(self) -> str:
        """Get the version of the platform"""
        pass
    
    @abstractmethod
    def log(self, message: str) -> None:
        """Log a message to the platform's output"""
        pass
    
    @abstractmethod
    def wait_for_analysis(self) -> None:
        """Wait for the platform's auto-analysis to complete"""
        pass
    
    @abstractmethod
    def get_function_by_name(self, name: str) -> Optional[int]:
        """Get function address by name"""
        pass
    
    @abstractmethod
    def get_all_functions(self) -> List[int]:
        """Get addresses of all functions"""
        pass
    
    @abstractmethod
    def get_function_instructions(self, func_addr: int) -> List[str]:
        """Get disassembly instructions for a function"""
        pass
    
    @abstractmethod
    def get_imports(self) -> List[str]:
        """Get list of imported function names"""
        pass
    
    @abstractmethod
    def get_function_references(self, func_name: str) -> List[int]:
        """Get addresses that reference a function"""
        pass
    
    @abstractmethod
    def get_data_sections(self) -> List[Tuple[int, int]]:
        """Get list of (start, end) addresses for data sections"""
        pass
    
    @abstractmethod
    def read_dword(self, addr: int) -> int:
        """Read a 4-byte value from memory"""
        pass
    
    @abstractmethod
    def get_pointer_size(self) -> int:
        """Get pointer size (4 for 32-bit, 8 for 64-bit)"""
        pass
    
    @abstractmethod
    def set_function_name(self, addr: int, name: str) -> None:
        """Set the name of a function"""
        pass
    
    @abstractmethod
    def add_comment(self, addr: int, comment: str) -> None:
        """Add a comment at an address"""
        pass
    
    @abstractmethod
    def get_current_address(self) -> int:
        """Get the currently selected/cursor address"""
        pass
    
    @abstractmethod
    def get_operand_value(self, addr: int, operand_index: int) -> Optional[int]:
        """Get the value of an instruction operand"""
        pass
    
    def get_capabilities(self) -> Dict[str, bool]:
        """
        ☠ Get platform capabilities ☠
        
        Returns a dictionary of supported features
        """
        return {
            'auto_analysis': True,
            'function_naming': True,
            'commenting': True,
            'cross_references': True,
            'data_sections': True,
            'imports': True,
            'disassembly': True
        }