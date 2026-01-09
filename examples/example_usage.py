#!/usr/bin/env python3
"""
DriverBuddy Usage Examples

    ☠ ☠ ☠ EXAMPLE USAGE SCENARIOS ☠ ☠ ☠

This file demonstrates various ways to use DriverBuddy programmatically.
"""

import sys
import os

# Add DriverBuddy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from DriverBuddy import DriverAnalyzer, get_platform_adapter
from DriverBuddy.core import IOCTLInfo


def example_basic_analysis():
    """
    ☠ Basic driver analysis example ☠
    """
    print("☠ ☠ ☠ BASIC ANALYSIS EXAMPLE ☠ ☠ ☠")
    
    try:
        # Get platform adapter (auto-detects current platform)
        platform = get_platform_adapter()
        print(f"Detected platform: {platform.get_platform_name()} {platform.get_platform_version()}")
        
        # Create analyzer
        analyzer = DriverAnalyzer(platform)
        
        # Run analysis
        success = analyzer.analyze_driver()
        
        if success:
            # Get results
            summary = analyzer.get_analysis_summary()
            print(f"Analysis successful!")
            print(f"Driver type: {summary['driver_type']}")
            print(f"Found {len(summary['dispatch_functions'])} dispatch functions")
            print(f"Found {summary['ioctl_count']} IOCTLs")
        else:
            print("Analysis failed!")
            
    except Exception as e:
        print(f"Error: {e}")


def example_ioctl_decoding():
    """
    ☠ IOCTL decoding examples ☠
    """
    print("\n☠ ☠ ☠ IOCTL DECODING EXAMPLES ☠ ☠ ☠")
    
    # Common IOCTL codes to decode
    ioctl_codes = [
        0x22E004,  # Example IOCTL
        0x70000,   # Another example
        0x9C402C,  # FILE_DEVICE_UNKNOWN with custom function
        0x2D1400,  # FILE_DEVICE_DISK with METHOD_BUFFERED
    ]
    
    for code in ioctl_codes:
        ioctl_info = IOCTLInfo(code)
        print(f"\n☠ IOCTL: 0x{code:08X} ☠")
        print(str(ioctl_info))


def example_platform_specific():
    """
    ☠ Platform-specific feature examples ☠
    """
    print("\n☠ ☠ ☠ PLATFORM-SPECIFIC EXAMPLES ☠ ☠ ☠")
    
    try:
        platform = get_platform_adapter()
        
        # Check platform capabilities
        capabilities = platform.get_capabilities()
        print(f"Platform capabilities:")
        for feature, supported in capabilities.items():
            status = "✅" if supported else "❌"
            print(f"  {feature}: {status}")
        
        # Get basic info
        functions = platform.get_all_functions()
        print(f"\nFound {len(functions)} functions in binary")
        
        imports = platform.get_imports()
        print(f"Found {len(imports)} imported functions")
        
        # Show some imports
        if imports:
            print("Sample imports:")
            for imp in imports[:5]:  # Show first 5
                print(f"  - {imp}")
                
    except Exception as e:
        print(f"Error: {e}")


def example_custom_analysis():
    """
    ☠ Custom analysis workflow example ☠
    """
    print("\n☠ ☠ ☠ CUSTOM ANALYSIS WORKFLOW ☠ ☠ ☠")
    
    try:
        platform = get_platform_adapter()
        
        # Manual driver entry detection
        driver_entry = platform.get_function_by_name("DriverEntry")
        if driver_entry:
            print(f"DriverEntry found at: 0x{driver_entry:x}")
            
            # Get function instructions
            instructions = platform.get_function_instructions(driver_entry)
            print(f"DriverEntry has {len(instructions)} instructions")
            
            # Look for interesting patterns
            interesting_patterns = ['IoCreateDevice', 'WdfDriverCreate', 'MajorFunction']
            for pattern in interesting_patterns:
                matches = [instr for instr in instructions if pattern in instr]
                if matches:
                    print(f"Found {len(matches)} references to {pattern}")
        else:
            print("DriverEntry not found")
            
        # Look for dangerous functions
        dangerous_funcs = ['strcpy', 'memcpy', 'ProbeForRead', 'ExAllocatePool']
        for func in dangerous_funcs:
            refs = platform.get_function_references(func)
            if refs:
                print(f"☠ Dangerous function {func} called {len(refs)} times")
                
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    print("""
    ██████╗ ██████╗ ██╗██╗   ██╗███████╗██████╗ ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗   ██╗
    ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔══██╗╚██╗ ██╔╝
    ██║  ██║██████╔╝██║██║   ██║█████╗  ██████╔╝██████╔╝██║   ██║██║  ██║██║  ██║ ╚████╔╝ 
    ██║  ██║██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══██╗██║   ██║██║  ██║██║  ██║  ╚██╔╝  
    ██████╔╝██║  ██║██║ ╚████╔╝ ███████╗██║  ██║██████╔╝╚██████╔╝██████╔╝██████╔╝   ██║   
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝    ╚═╝   
                                                                                           
                            ☠ DRIVERBUDDY USAGE EXAMPLES ☠
    """)
    
    # Run all examples
    example_basic_analysis()
    example_ioctl_decoding()
    example_platform_specific()
    example_custom_analysis()
    
    print("\n☠ ☠ ☠ EXAMPLES COMPLETE ☠ ☠ ☠")