"""
    ██████╗ ██████╗ ██╗██╗   ██╗███████╗██████╗ ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗   ██╗
    ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔══██╗╚██╗ ██╔╝
    ██║  ██║██████╔╝██║██║   ██║█████╗  ██████╔╝██████╔╝██║   ██║██║  ██║██║  ██║ ╚████╔╝ 
    ██║  ██║██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══██╗██║   ██║██║  ██║██║  ██║  ╚██╔╝  
    ██████╔╝██║  ██║██║ ╚████╔╝ ███████╗██║  ██║██████╔╝╚██████╔╝██████╔╝██████╔╝   ██║   
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝    ╚═╝   
                                                                                           
    Modern Multi-Platform Windows Driver Analysis Tool
    
    ☠ Supports: IDA Pro, Ghidra, Binary Ninja, Radare2 ☠
    
    Authors: NCC Group (Original), Modernized for 2024
    License: MIT
"""

__version__ = "2.0.0"
__author__ = "NCC Group (Modernized)"

from .core import DriverAnalyzer
from .platforms import get_platform_adapter

__all__ = ['DriverAnalyzer', 'get_platform_adapter']