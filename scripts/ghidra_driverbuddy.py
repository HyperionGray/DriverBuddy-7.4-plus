#!/usr/bin/env python3
"""
DriverBuddy for Ghidra

    ☠ ☠ ☠ GHIDRA SCRIPT ☠ ☠ ☠

Run this script in Ghidra to analyze Windows drivers.

Usage:
1. Load your driver binary in Ghidra
2. Run this script from the Script Manager
3. Check the console for analysis results
"""

# Ghidra script metadata
#@author DriverBuddy Team
#@category Analysis
#@keybinding ctrl alt d
#@menupath Tools.DriverBuddy.Analyze Driver
#@toolbar DriverBuddy.png

import sys
import os

# Add DriverBuddy to path (adjust as needed)
script_dir = os.path.dirname(os.path.abspath(__file__))
driverbuddy_path = os.path.join(script_dir, '..')
sys.path.insert(0, driverbuddy_path)

try:
    from DriverBuddy import DriverAnalyzer, get_platform_adapter
    
    def main():
        """
        ☠ Main Ghidra analysis function ☠
        """
        print("☠ ☠ ☠ DRIVERBUDDY FOR GHIDRA ☠ ☠ ☠")
        
        try:
            # Get Ghidra platform adapter
            platform = get_platform_adapter()
            
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
            else:
                print("☠ Analysis failed! Check if this is a valid Windows driver. ☠")
                
        except Exception as e:
            print(f"☠ Error during analysis: {e} ☠")
            import traceback
            traceback.print_exc()
    
    # Run the analysis
    if __name__ == "__main__":
        main()
        
except ImportError as e:
    print(f"☠ Failed to import DriverBuddy: {e} ☠")
    print("Make sure DriverBuddy is in your Python path!")