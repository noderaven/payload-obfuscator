"""
Virtualization and sandbox detection techniques.

This module implements various methods to detect virtualized environments,
sandboxes, and analysis platforms.
"""

import os
import sys
import ctypes
import socket
import platform
import subprocess
from typing import List, Dict, Set, Optional
from ctypes import windll, byref, c_ulong, c_char_p, create_string_buffer
from loguru import logger

class VirtualizationDetector:
    """
    Implements various virtualization detection techniques.
    
    Features:
    - Hardware fingerprinting
    - Process enumeration
    - Registry analysis
    - Network checks
    - File system analysis
    """
    
    def __init__(self):
        """Initialize virtualization detector."""
        self.known_vm_processes = {
            "vboxservice.exe", "vboxtray.exe",  # VirtualBox
            "vmtoolsd.exe", "vmwaretray.exe",   # VMware
            "vmusrvc.exe", "vmsrvc.exe",        # Virtual PC
            "sandboxiedcomlaunch.exe",          # Sandboxie
            "procmon.exe", "wireshark.exe"      # Analysis tools
        }
        
        self.known_vm_files = {
            r"C:\Windows\System32\Drivers\VBoxMouse.sys",
            r"C:\Windows\System32\Drivers\VMToolsHook.dll",
            r"C:\Windows\System32\Drivers\vmmouse.sys",
            r"C:\Windows\System32\Drivers\vmhgfs.sys"
        }
        
        self.known_vm_registry_keys = [
            r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
            r"HARDWARE\Description\System",
            r"SOFTWARE\Oracle\VirtualBox Guest Additions",
            r"SOFTWARE\VMware, Inc.\VMware Tools"
        ]
        
    def is_virtualized(self) -> bool:
        """
        Combine multiple detection methods to check for virtualization.
        
        Returns:
            bool: True if virtualization detected, False otherwise
        """
        checks = [
            self._check_processes,
            self._check_files,
            self._check_registry,
            self._check_hardware,
            self._check_mac_address,
            self._check_system_info
        ]
        
        for check in checks:
            try:
                if check():
                    logger.warning(f"Virtualization detected via {check.__name__}")
                    return True
            except Exception as e:
                logger.debug(f"Check {check.__name__} failed: {str(e)}")
                
        return False
        
    def _check_processes(self) -> bool:
        """
        Check for known VM-related processes.
        
        Returns:
            bool: True if VM processes found
        """
        try:
            # Use WMI to enumerate processes
            import wmi
            c = wmi.WMI()
            
            running_processes = {process.Name.lower() for process in c.Win32_Process()}
            vm_processes = running_processes.intersection(self.known_vm_processes)
            
            if vm_processes:
                logger.debug(f"Found VM processes: {vm_processes}")
                return True
                
            return False
            
        except Exception as e:
            logger.debug(f"Process check failed: {str(e)}")
            return False
            
    def _check_files(self) -> bool:
        """
        Check for known VM-related files.
        
        Returns:
            bool: True if VM files found
        """
        for file_path in self.known_vm_files:
            if os.path.exists(file_path):
                logger.debug(f"Found VM file: {file_path}")
                return True
                
        return False
        
    def _check_registry(self) -> bool:
        """
        Check registry for VM artifacts.
        
        Returns:
            bool: True if VM registry keys found
        """
        try:
            import winreg
            
            for key_path in self.known_vm_registry_keys:
                try:
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        key_path,
                        0,
                        winreg.KEY_READ
                    )
                    winreg.CloseKey(key)
                    logger.debug(f"Found VM registry key: {key_path}")
                    return True
                except WindowsError:
                    continue
                    
            return False
            
        except Exception as e:
            logger.debug(f"Registry check failed: {str(e)}")
            return False
            
    def _check_hardware(self) -> bool:
        """
        Check hardware characteristics for virtualization.
        
        Returns:
            bool: True if virtual hardware detected
        """
        try:
            import wmi
            c = wmi.WMI()
            
            # Check system manufacturer
            for system in c.Win32_ComputerSystem():
                manufacturer = system.Manufacturer.lower()
                if any(vm in manufacturer for vm in ["vmware", "virtualbox", "qemu", "kvm"]):
                    logger.debug(f"Found VM manufacturer: {manufacturer}")
                    return True
                    
            # Check BIOS
            for bios in c.Win32_BIOS():
                if any(vm in bios.Version.lower() for vm in ["vmware", "virtualbox", "qemu"]):
                    logger.debug(f"Found VM BIOS: {bios.Version}")
                    return True
                    
            return False
            
        except Exception as e:
            logger.debug(f"Hardware check failed: {str(e)}")
            return False
            
    def _check_mac_address(self) -> bool:
        """
        Check for known VM MAC address prefixes.
        
        Returns:
            bool: True if VM MAC address detected
        """
        try:
            vm_mac_prefixes = {
                "00:05:69",  # VMware
                "00:0C:29",  # VMware
                "00:1C:14",  # VMware
                "00:50:56",  # VMware
                "08:00:27",  # VirtualBox
                "00:03:FF",  # Microsoft Virtual PC
                "00:0D:3A"   # Microsoft Virtual PC
            }
            
            import netifaces
            for interface in netifaces.interfaces():
                try:
                    mac = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']
                    prefix = mac[:8].replace("-", ":").upper()
                    if prefix in vm_mac_prefixes:
                        logger.debug(f"Found VM MAC prefix: {prefix}")
                        return True
                except:
                    continue
                    
            return False
            
        except Exception as e:
            logger.debug(f"MAC address check failed: {str(e)}")
            return False
            
    def _check_system_info(self) -> bool:
        """
        Check system information for virtualization indicators.
        
        Returns:
            bool: True if virtual system detected
        """
        try:
            # Check CPU info
            cpu_info = platform.processor()
            if "hypervisor" in cpu_info.lower():
                logger.debug("Hypervisor detected in CPU info")
                return True
                
            # Check environment variables
            vm_env_vars = ["VBOX_", "VMWARE_", "VIRTUAL_"]
            for var in os.environ:
                if any(v in var.upper() for v in vm_env_vars):
                    logger.debug(f"Found VM environment variable: {var}")
                    return True
                    
            return False
            
        except Exception as e:
            logger.debug(f"System info check failed: {str(e)}")
            return False
            
    def apply_vm_evasion(self) -> None:
        """
        Apply various VM evasion techniques.
        
        This includes:
        - Sleep padding
        - Process name checks
        - Network activity simulation
        - File system activity
        """
        try:
            # Add random delays
            import random
            import time
            time.sleep(random.uniform(1, 3))
            
            # Check parent process
            self._check_parent_process()
            
            # Simulate normal system activity
            self._simulate_activity()
            
            logger.success("Applied VM evasion techniques")
            
        except Exception as e:
            logger.error(f"Failed to apply VM evasion: {str(e)}")
            
    def _check_parent_process(self) -> None:
        """Check parent process for analysis tools."""
        try:
            import psutil
            current_process = psutil.Process()
            parent = current_process.parent()
            
            if parent.name().lower() in self.known_vm_processes:
                sys.exit(1)
                
        except Exception as e:
            logger.debug(f"Parent process check failed: {str(e)}")
            
    def _simulate_activity(self) -> None:
        """Simulate normal system activity to appear legitimate."""
        try:
            # Create temporary files
            temp_file = os.path.join(os.environ["TEMP"], "temp.txt")
            with open(temp_file, "w") as f:
                f.write("test")
            os.remove(temp_file)
            
            # DNS lookup
            try:
                socket.gethostbyname("www.google.com")
            except:
                pass
                
        except Exception as e:
            logger.debug(f"Activity simulation failed: {str(e)}") 