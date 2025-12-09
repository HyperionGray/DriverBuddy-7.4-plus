#!/usr/bin/env python3
"""
DriverBuddy for Radare2

    ☠ ☠ ☠ RADARE2 SCRIPT ☠ ☠ ☠

Radare2 script for Windows driver analysis.

Usage:
1. Load your driver binary in r2: r2 driver.sys
2. Run this script: #!pipe python3 r2_driverbuddy.py
   Or: . r2_driverbuddy.py (if in r2 script path)
"""

import sys
import os

# Add DriverBuddy to path
script_dir = os.path.dirname(os.path.abspath(__file__))
driverbuddy_path = os.path.join(script_dir, '..')
sys.path.insert(0, driverbuddy_path)

try:
    import r2pipe
    from DriverBuddy import DriverAnalyzer
    from DriverBuddy.platforms.r2_adapter import Radare2Adapter
    
    def main():
        """
        ☠ Main Radare2 analysis function ☠
        """
        print("☠ ☠ ☠ DRIVERBUDDY FOR RADARE2 ☠ ☠ ☠")
        
        try:
            # Connect to current r2 instance
            r2 = r2pipe.open()
            
            # Create Radare2 adapter
            platform = Radare2Adapter(r2)
            
            # Create and run analyzer
            analyzer = DriverAnalyzer(platform)
            
            print("☠ Starting driver analysis...")
            success = analyzer.analyze_driver()
            
            if success:
                # Print detailed summary
                summary = analyzer.get_analysis_summary()
                print("\n☠ ☠ ☠ ANALYSIS RESULTS ☠ ☠ ☠")
                print(f"Platform: {platform.get_platform_name()} {platform.get_platform_version()}")
                print(f"Driver Type: {summary['driver_type']}")
                print(f"DriverEntry: {summary['driver_entry']}")
                print(f"Dispatch Functions Found: {len(summary['dispatch_functions'])}")
                
                if summary['dispatch_functions']:
                    print("\nDispatch Functions:")
                    for name, addr in summary['dispatch_functions'].items():
                        print(f"  {name}: {addr}")
                
                print(f"\nIOCTLs Found: {summary['ioctl_count']}")
                print(f"Dangerous Functions Flagged: {summary['dangerous_function_count']}")
                print("\n☠ Analysis complete! Check function names and comments. ☠")
                
                # Show some r2 commands for further analysis
                print("\n☠ Useful r2 commands:")
                print("  afl          - List all functions")
                print("  CC           - List all comments")
                print("  f~IOCTL      - Find IOCTL-related flags")
                print("  f~Dispatch   - Find dispatch functions")
                
            else:
                print("☠ Analysis failed! Check if this is a valid Windows driver. ☠")
                
        except Exception as e:
            print(f"☠ Error during analysis: {e} ☠")
            import traceback
            traceback.print_exc()
    
    def decode_ioctl(value_str):
        """
        ☠ Decode a specific IOCTL value ☠
        
        Usage: decode_ioctl("0x12345678")
        """
        try:
            value = int(value_str, 16) if value_str.startswith('0x') else int(value_str)
            
            from DriverBuddy.core import IOCTLInfo
            ioctl_info = IOCTLInfo(value)
            print(f"☠ IOCTL Decoded ☠\n{str(ioctl_info)}")
            
        except Exception as e:
            print(f"☠ IOCTL decode error: {e} ☠")
    
    # Run analysis if executed directly
    if __name__ == "__main__":
        main()
        
except ImportError as e:
    print(f"☠ Failed to import required modules: {e} ☠")
    print("Make sure r2pipe and DriverBuddy are installed!")
    print("Install with: pip install r2pipe")