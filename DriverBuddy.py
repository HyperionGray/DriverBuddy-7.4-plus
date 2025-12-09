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

# Try to import platform-specific modules
try:
    # IDA Pro plugin interface
    from idaapi import plugin_t, PLUGIN_UNL, add_hotkey, PLUGIN_KEEP
    from idc import get_operand_type, get_screen_ea, get_operand_value, o_imm
    IDA_PLUGIN_MODE = True
except ImportError:
    IDA_PLUGIN_MODE = False

from DriverBuddy import DriverAnalyzer, get_platform_adapter


def PLUGIN_ENTRY():
    """IDA Pro plugin entry point"""
    if IDA_PLUGIN_MODE:
        return DriverBuddyPlugin()
    else:
        raise RuntimeError("☠ Not running in IDA Pro! ☠")


class DriverBuddyPlugin(plugin_t):
    """
    ☠ IDA Pro Plugin Interface ☠
    
    Modern IDA Pro plugin for DriverBuddy
    """
    flags = PLUGIN_UNL
    comment = ('☠ DriverBuddy ☠ Multi-platform Windows driver analysis tool. ' +
               'Automatically finds IOCTL handlers, decodes IOCTLs, ' +
               'flags dangerous functions, and identifies driver types.')
    help = 'DriverBuddy: Modern driver analysis for IDA Pro, Ghidra, Binary Ninja, and Radare2'
    wanted_name = 'DriverBuddy'
    wanted_hotkey = 'Ctrl-Alt-D'

    def init(self):
        """Initialize the plugin"""
        self.hotkeys = []
        self.analyzer = None
        
        # Add hotkey for IOCTL decoding
        self.hotkeys.append(add_hotkey("Ctrl+Alt+I", self.decode_ioctl))
        
        print("☠ DriverBuddy initialized ☠")
        return PLUGIN_KEEP

    def run(self, args):
        """Main plugin execution"""
        try:
            # Get platform adapter
            platform = get_platform_adapter()
            
            # Create analyzer
            self.analyzer = DriverAnalyzer(platform)
            
            # Run analysis
            platform.log("☠ ☠ ☠ DRIVERBUDDY ANALYSIS STARTING ☠ ☠ ☠")
            success = self.analyzer.analyze_driver()
            
            if success:
                # Print summary
                summary = self.analyzer.get_analysis_summary()
                platform.log("\n☠ ☠ ☠ ANALYSIS SUMMARY ☠ ☠ ☠")
                platform.log(f"Driver Type: {summary['driver_type']}")
                platform.log(f"DriverEntry: {summary['driver_entry']}")
                platform.log(f"Dispatch Functions: {len(summary['dispatch_functions'])}")
                platform.log(f"IOCTLs Found: {summary['ioctl_count']}")
                platform.log(f"Dangerous Functions: {summary['dangerous_function_count']}")
                platform.log("☠ ☠ ☠ ANALYSIS COMPLETE ☠ ☠ ☠")
            else:
                platform.log("☠ Analysis failed! ☠")
                
        except Exception as e:
            print(f"☠ DriverBuddy error: {e} ☠")

    def decode_ioctl(self, _=0):
        """Decode IOCTL at current cursor position"""
        try:
            # Check if current operand is an immediate value
            if get_operand_type(get_screen_ea(), 1) != o_imm:
                print("☠ No immediate value at cursor ☠")
                return
                
            # Get the value
            value = get_operand_value(get_screen_ea(), 1) & 0xffffffff
            
            # Decode it
            if self.analyzer:
                decoded = self.analyzer.decode_ioctl(value)
                print(f"☠ IOCTL Decoded ☠\n{decoded}")
            else:
                # Fallback decoding without full analyzer
                from DriverBuddy.core import IOCTLInfo
                ioctl_info = IOCTLInfo(value)
                print(f"☠ IOCTL Decoded ☠\n{str(ioctl_info)}")
                
        except Exception as e:
            print(f"☠ IOCTL decode error: {e} ☠")

    def term(self):
        """Plugin termination"""
        pass


def main():
    """
    ☠ Standalone execution for non-IDA platforms ☠
    
    This function can be called directly from other platforms
    """
    try:
        # Get platform adapter
        platform = get_platform_adapter()
        
        # Create and run analyzer
        analyzer = DriverAnalyzer(platform)
        
        platform.log("☠ ☠ ☠ DRIVERBUDDY STANDALONE ANALYSIS ☠ ☠ ☠")
        success = analyzer.analyze_driver()
        
        if success:
            # Print summary
            summary = analyzer.get_analysis_summary()
            platform.log("\n☠ ☠ ☠ ANALYSIS SUMMARY ☠ ☠ ☠")
            platform.log(f"Platform: {platform.get_platform_name()} {platform.get_platform_version()}")
            platform.log(f"Driver Type: {summary['driver_type']}")
            platform.log(f"DriverEntry: {summary['driver_entry']}")
            platform.log(f"Dispatch Functions: {len(summary['dispatch_functions'])}")
            platform.log(f"IOCTLs Found: {summary['ioctl_count']}")
            platform.log(f"Dangerous Functions: {summary['dangerous_function_count']}")
            platform.log("☠ ☠ ☠ ANALYSIS COMPLETE ☠ ☠ ☠")
        else:
            platform.log("☠ Analysis failed! ☠")
            
        return analyzer
        
    except Exception as e:
        print(f"☠ DriverBuddy error: {e} ☠")
        return None


# Allow direct execution for testing
if __name__ == "__main__":
    main()