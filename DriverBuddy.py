from idaapi import *
from idautils import *
from idc import *
from ida_auto import auto_wait
from DriverBuddy import data
from DriverBuddy import ioctl


'''#######################################################################################

DriverBuddy.py: Entry point for IDA Python plugin used in Windows driver
                vulnerability research.

Written by Braden Hollembaek and Adam Pond of NCC Group
Modernized for Python 3 and IDA Pro 7.x+
#######################################################################################'''

def print_header():
    """Print ASCII art header"""
    print("╔═══════════════════════════════════════════════════════════════╗")
    print("║              DriverBuddy for IDA Pro                          ║")
    print("║              Windows Kernel Driver Analysis                   ║")
    print("║                                                                ║")
    print("║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║")
    print("╚═══════════════════════════════════════════════════════════════╝")

def PLUGIN_ENTRY():
    return DriverBuddyPlugin()

class DriverBuddyPlugin(plugin_t):
    flags = PLUGIN_UNL
    comment = ('Plugin to aid in Windows driver vulnerability research. ' +
               'Automatically tries to find IOCTL handlers, decode IOCTLS, '+
               'flag dangerous C/C++ functions, find Windows imports for privesc, '+
               'and identify the type of Windows driver.')
    help = ''
    wanted_name = 'Driver Buddy'
    wanted_hotkey = 'Ctrl-Alt-D'

    def init(self):
        self.hotkeys = []
        self.hotkeys.append(add_hotkey("Ctrl+Alt+I", self.decode))
        return PLUGIN_KEEP

    def run(self, args):
        print_header()
        print("[+] Welcome to Driver Buddy")
        auto_wait()  # Wait for IDA autoanalysis to complete
        driver_entry = data.is_driver()
        if driver_entry == "" or driver_entry is None:
            print("[-] No DriverEntry stub found")
            print("[-] Exiting...")
            return
        print("[+] DriverEntry found")
        if data.populate_data_structures() == False:
            print("[-] Unable to load functions")
            print("[-] Exiting...")
            return
        driver_type = data.get_driver_id(driver_entry)
        if driver_type == "":
            print("[-] Unable to determine driver type assuming wdm")
        else:
            print("[+] Driver type detected: " + driver_type)
        if ioctl.find_ioctls() == False:
            print("[-] Unable to automatically find any IOCTLs")
        print("")
        print("╔═══════════════════════════════════════════════════════════════╗")
        print("║                    Analysis Complete                          ║")
        print("║              ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠ ☠                              ║")
        print("╚═══════════════════════════════════════════════════════════════╝")
        return

    def decode(self, _=0):
        if idc.get_operand_type(idc.get_screen_ea(), 1) != 5:   # Immediate
            return
        value = idc.get_operand_value(idc.get_screen_ea(), 1) & 0xffffffff
        ioctl.get_ioctl_code(value)

    def term(self):
        pass