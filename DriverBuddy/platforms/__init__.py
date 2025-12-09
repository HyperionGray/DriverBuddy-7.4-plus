"""
DriverBuddy Platform Adapters

    ☠ ☠ ☠ MULTI-PLATFORM SUPPORT ☠ ☠ ☠

Platform-specific adapters for different reverse engineering tools.
"""

from .base import PlatformAdapter
from .ida_adapter import IDAAdapter

def get_platform_adapter():
    """
    ☠ Auto-detect and return appropriate platform adapter ☠
    """
    # Try IDA first
    try:
        import idaapi
        return IDAAdapter()
    except ImportError:
        pass
    
    # Try Ghidra
    try:
        import ghidra
        from .ghidra_adapter import GhidraAdapter
        return GhidraAdapter()
    except ImportError:
        pass
    
    # Try Binary Ninja
    try:
        import binaryninja
        from .binja_adapter import BinaryNinjaAdapter
        return BinaryNinjaAdapter()
    except ImportError:
        pass
    
    # Try Radare2
    try:
        import r2pipe
        from .r2_adapter import Radare2Adapter
        return Radare2Adapter()
    except ImportError:
        pass
    
    raise RuntimeError("☠ No supported reverse engineering platform detected! ☠\n"
                      "Supported platforms: IDA Pro, Ghidra, Binary Ninja, Radare2")

__all__ = ['PlatformAdapter', 'IDAAdapter', 'get_platform_adapter']