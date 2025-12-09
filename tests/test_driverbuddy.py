#!/usr/bin/env python3
"""
DriverBuddy Test Suite

    ☠ ☠ ☠ COMPREHENSIVE TESTING ☠ ☠ ☠

Test suite for DriverBuddy functionality across all platforms.
"""

import unittest
import sys
import os
from unittest.mock import Mock, patch, MagicMock

# Add DriverBuddy to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from DriverBuddy.core import DriverAnalyzer, IOCTLInfo, DriverType
from DriverBuddy.platforms.base import PlatformAdapter


class MockPlatformAdapter(PlatformAdapter):
    """Mock platform adapter for testing"""
    
    def __init__(self):
        self.logs = []
        self.functions = {0x1000: "DriverEntry", 0x2000: "TestFunction"}
        self.imports = ["IoCreateDevice", "strcpy", "memcpy", "ExAllocatePool"]
        
    def get_platform_name(self) -> str:
        return "MockPlatform"
    
    def get_platform_version(self) -> str:
        return "1.0.0"
    
    def log(self, message: str) -> None:
        self.logs.append(message)
        print(message)
    
    def wait_for_analysis(self) -> None:
        pass
    
    def get_function_by_name(self, name: str):
        for addr, func_name in self.functions.items():
            if func_name == name:
                return addr
        return None
    
    def get_all_functions(self):
        return list(self.functions.keys())
    
    def get_function_instructions(self, func_addr: int):
        if func_addr == 0x1000:  # DriverEntry
            return [
                "mov rax, rcx",
                "mov [rax+0x70], 0x2000",  # MajorFunction[IRP_MJ_DEVICE_CONTROL]
                "call IoCreateDevice",
                "ret"
            ]
        return ["ret"]
    
    def get_imports(self):
        return self.imports
    
    def get_function_references(self, func_name: str):
        if func_name in self.imports:
            return [0x1500, 0x1600]  # Mock references
        return []
    
    def get_data_sections(self):
        return [(0x3000, 0x4000)]
    
    def read_dword(self, addr: int) -> int:
        # Mock IOCTL codes in data section
        ioctl_codes = {
            0x3000: 0x22E004,
            0x3004: 0x70000,
            0x3008: 0x9C402C
        }
        return ioctl_codes.get(addr, 0)
    
    def get_pointer_size(self) -> int:
        return 8
    
    def set_function_name(self, addr: int, name: str) -> None:
        self.functions[addr] = name
    
    def add_comment(self, addr: int, comment: str) -> None:
        pass
    
    def get_current_address(self) -> int:
        return 0x1000
    
    def get_operand_value(self, addr: int, operand_index: int):
        return 0x22E004  # Mock IOCTL code


class TestIOCTLInfo(unittest.TestCase):
    """Test IOCTL decoding functionality"""
    
    def test_ioctl_decoding_basic(self):
        """Test basic IOCTL decoding"""
        ioctl = IOCTLInfo(0x22E004)
        
        self.assertEqual(ioctl.code, 0x22E004)
        self.assertEqual(ioctl.device_type, 0x0022)
        self.assertEqual(ioctl.function, 0x801)
        self.assertEqual(ioctl.method, 0)
        self.assertEqual(ioctl.access, 0)
    
    def test_ioctl_string_representation(self):
        """Test IOCTL string formatting"""
        ioctl = IOCTLInfo(0x22E004)
        ioctl_str = str(ioctl)
        
        self.assertIn("IOCTL Code: 0x0022E004", ioctl_str)
        self.assertIn("Device Type: 0x0022", ioctl_str)
        self.assertIn("METHOD_BUFFERED", ioctl_str)
        self.assertIn("FILE_ANY_ACCESS", ioctl_str)
    
    def test_ioctl_method_types(self):
        """Test different IOCTL method types"""
        # METHOD_BUFFERED (0)
        ioctl0 = IOCTLInfo(0x22E000)
        self.assertEqual(ioctl0.method, 0)
        
        # METHOD_IN_DIRECT (1)
        ioctl1 = IOCTLInfo(0x22E001)
        self.assertEqual(ioctl1.method, 1)
        
        # METHOD_OUT_DIRECT (2)
        ioctl2 = IOCTLInfo(0x22E002)
        self.assertEqual(ioctl2.method, 2)
        
        # METHOD_NEITHER (3)
        ioctl3 = IOCTLInfo(0x22E003)
        self.assertEqual(ioctl3.method, 3)


class TestDriverAnalyzer(unittest.TestCase):
    """Test core driver analysis functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.mock_platform = MockPlatformAdapter()
        self.analyzer = DriverAnalyzer(self.mock_platform)
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        self.assertEqual(self.analyzer.platform, self.mock_platform)
        self.assertEqual(self.analyzer.driver_type, DriverType.UNKNOWN)
        self.assertIsNone(self.analyzer.driver_entry)
        self.assertEqual(len(self.analyzer.dispatch_functions), 0)
    
    def test_driver_entry_detection(self):
        """Test DriverEntry function detection"""
        # This would normally be called by analyze_driver()
        success = self.analyzer._find_driver_entry()
        
        self.assertTrue(success)
        self.assertEqual(self.analyzer.driver_entry, 0x1000)
    
    def test_driver_type_identification(self):
        """Test driver type identification"""
        self.analyzer.driver_entry = 0x1000
        self.analyzer._identify_driver_type()
        
        # Should detect as WDM since no WDF imports
        self.assertEqual(self.analyzer.driver_type, DriverType.WDM)
    
    def test_dangerous_function_detection(self):
        """Test dangerous function flagging"""
        self.analyzer._flag_dangerous_functions()
        
        # Should find dangerous functions from mock imports
        dangerous_count = len(self.analyzer.dangerous_functions)
        self.assertGreater(dangerous_count, 0)
    
    def test_ioctl_detection(self):
        """Test IOCTL detection in data sections"""
        self.analyzer._find_ioctls()
        
        # Should find IOCTLs in mock data section
        self.assertGreater(len(self.analyzer.ioctls), 0)
        
        # Check first IOCTL
        addr, ioctl_info = self.analyzer.ioctls[0]
        self.assertEqual(addr, 0x3000)
        self.assertEqual(ioctl_info.code, 0x22E004)
    
    def test_full_analysis(self):
        """Test complete analysis workflow"""
        success = self.analyzer.analyze_driver()
        
        self.assertTrue(success)
        
        # Check analysis results
        summary = self.analyzer.get_analysis_summary()
        self.assertEqual(summary['driver_type'], 'WDM')
        self.assertEqual(summary['driver_entry'], '0x1000')
        self.assertGreater(summary['ioctl_count'], 0)
        self.assertGreater(summary['dangerous_function_count'], 0)
    
    def test_ioctl_decoding(self):
        """Test standalone IOCTL decoding"""
        decoded = self.analyzer.decode_ioctl(0x22E004)
        
        self.assertIn("IOCTL Code: 0x0022E004", decoded)
        self.assertIn("METHOD_BUFFERED", decoded)


class TestPlatformDetection(unittest.TestCase):
    """Test platform detection and loading"""
    
    @patch('DriverBuddy.platforms.idaapi')
    def test_ida_detection(self, mock_idaapi):
        """Test IDA Pro platform detection"""
        from DriverBuddy.platforms import get_platform_adapter
        
        # Mock IDA availability
        mock_idaapi.get_kernel_version.return_value = "8.0"
        
        with patch('DriverBuddy.platforms.IDAAdapter') as mock_adapter:
            mock_instance = Mock()
            mock_adapter.return_value = mock_instance
            
            # This would detect IDA if imports succeed
            # In real test, we'd need to mock the imports properly
            pass
    
    def test_platform_not_found(self):
        """Test behavior when no platform is detected"""
        from DriverBuddy.platforms import get_platform_adapter
        
        # Mock all platform imports to fail
        with patch.dict('sys.modules', {
            'idaapi': None,
            'ghidra': None,
            'binaryninja': None,
            'r2pipe': None
        }):
            with self.assertRaises(RuntimeError) as context:
                get_platform_adapter()
            
            self.assertIn("No supported reverse engineering platform detected", str(context.exception))


class TestUtilityFunctions(unittest.TestCase):
    """Test utility and helper functions"""
    
    def test_ioctl_validation(self):
        """Test IOCTL code validation"""
        analyzer = DriverAnalyzer(MockPlatformAdapter())
        
        # Valid IOCTL codes
        self.assertTrue(analyzer._is_potential_ioctl(0x22E004))
        self.assertTrue(analyzer._is_potential_ioctl(0x70000))
        
        # Invalid IOCTL codes
        self.assertFalse(analyzer._is_potential_ioctl(0))
        self.assertFalse(analyzer._is_potential_ioctl(0xFFFFFFFF))
        self.assertFalse(analyzer._is_potential_ioctl(0x80000004))  # Invalid device type
    
    def test_driver_entry_candidate_detection(self):
        """Test DriverEntry candidate detection"""
        analyzer = DriverAnalyzer(MockPlatformAdapter())
        
        # Mock function should be detected as DriverEntry candidate
        is_candidate = analyzer._is_driver_entry_candidate(0x1000)
        self.assertTrue(is_candidate)
        
        # Non-existent function should not be candidate
        is_candidate = analyzer._is_driver_entry_candidate(0x9999)
        self.assertFalse(is_candidate)


if __name__ == '__main__':
    print("""
    ██████╗ ██████╗ ██╗██╗   ██╗███████╗██████╗ ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗   ██╗
    ██╔══██╗██╔══██╗██║██║   ██║██╔════╝██╔══██╗██╔══██╗██║   ██║██╔══██╗██╔══██╗╚██╗ ██╔╝
    ██║  ██║██████╔╝██║██║   ██║█████╗  ██████╔╝██████╔╝██║   ██║██║  ██║██║  ██║ ╚████╔╝ 
    ██║  ██║██╔══██╗██║╚██╗ ██╔╝██╔══╝  ██╔══██╗██╔══██╗██║   ██║██║  ██║██║  ██║  ╚██╔╝  
    ██████╔╝██║  ██║██║ ╚████╔╝ ███████╗██║  ██║██████╔╝╚██████╔╝██████╔╝██████╔╝   ██║   
    ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝    ╚═╝   
                                                                                           
                            ☠ DRIVERBUDDY TEST SUITE ☠
    """)
    
    unittest.main(verbosity=2)