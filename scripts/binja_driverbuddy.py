#!/usr/bin/env python3
"""
DriverBuddy for Binary Ninja

    ☠ ☠ ☠ BINARY NINJA PLUGIN ☠ ☠ ☠

Binary Ninja plugin for Windows driver analysis.

Installation:
1. Copy this file to your Binary Ninja plugins directory
2. Copy the DriverBuddy package to the same directory
3. Restart Binary Ninja
"""

import sys
import os

# Add DriverBuddy to path
plugin_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, plugin_dir)

try:
    import binaryninja as binja
    from binaryninja import PluginCommand, log_info, log_error
    from DriverBuddy import DriverAnalyzer
    from DriverBuddy.platforms.binja_adapter import BinaryNinjaAdapter
    
    def analyze_driver(bv):
        """
        ☠ Analyze Windows driver in Binary Ninja ☠
        """
        log_info("☠ ☠ ☠ DRIVERBUDDY FOR BINARY NINJA ☠ ☠ ☠")
        
        try:
            # Create Binary Ninja adapter
            platform = BinaryNinjaAdapter(bv)
            
            # Create and run analyzer
            analyzer = DriverAnalyzer(platform)
            
            log_info("☠ Starting driver analysis...")
            success = analyzer.analyze_driver()
            
            if success:
                # Print detailed summary
                summary = analyzer.get_analysis_summary()
                log_info("\n☠ ☠ ☠ ANALYSIS RESULTS ☠ ☠ ☠")
                log_info(f"Platform: {platform.get_platform_name()} {platform.get_platform_version()}")
                log_info(f"Driver Type: {summary['driver_type']}")
                log_info(f"DriverEntry: {summary['driver_entry']}")
                log_info(f"Dispatch Functions Found: {len(summary['dispatch_functions'])}")
                
                if summary['dispatch_functions']:
                    log_info("\nDispatch Functions:")
                    for name, addr in summary['dispatch_functions'].items():
                        log_info(f"  {name}: {addr}")
                
                log_info(f"\nIOCTLs Found: {summary['ioctl_count']}")
                log_info(f"Dangerous Functions Flagged: {summary['dangerous_function_count']}")
                log_info("\n☠ Analysis complete! Check function names and comments. ☠")
            else:
                log_error("☠ Analysis failed! Check if this is a valid Windows driver. ☠")
                
        except Exception as e:
            log_error(f"☠ Error during analysis: {e} ☠")
            import traceback
            traceback.print_exc()
    
    def decode_ioctl_at_cursor(bv):
        """
        ☠ Decode IOCTL at current cursor position ☠
        """
        try:
            # Get current address (this is simplified - Binary Ninja UI integration needed)
            current_addr = 0  # Would need UI integration to get actual cursor position
            
            # Read value at address
            data = bv.read(current_addr, 4)
            if len(data) == 4:
                value = int.from_bytes(data, byteorder='little')
                
                # Decode IOCTL
                from DriverBuddy.core import IOCTLInfo
                ioctl_info = IOCTLInfo(value)
                log_info(f"☠ IOCTL Decoded ☠\n{str(ioctl_info)}")
            else:
                log_error("☠ Could not read IOCTL value ☠")
                
        except Exception as e:
            log_error(f"☠ IOCTL decode error: {e} ☠")
    
    # Register plugin commands
    PluginCommand.register(
        "DriverBuddy\\Analyze Driver",
        "☠ Analyze Windows driver with DriverBuddy ☠",
        analyze_driver
    )
    
    PluginCommand.register(
        "DriverBuddy\\Decode IOCTL",
        "☠ Decode IOCTL at cursor ☠",
        decode_ioctl_at_cursor
    )
    
    log_info("☠ DriverBuddy for Binary Ninja loaded ☠")
    
except ImportError as e:
    print(f"☠ Failed to import DriverBuddy: {e} ☠")
    print("Make sure DriverBuddy package is in the plugins directory!")