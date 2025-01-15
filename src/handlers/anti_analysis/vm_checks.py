"""
Virtualization detection functionality.

This module provides virtualization detection capabilities.
Supports both Windows and Unix-based systems with platform-specific implementations.
"""

import os
import sys
import platform
import subprocess
from typing import Dict, List, Optional
from loguru import logger

# Platform-specific imports
if platform.system() == 'Windows':
    from ctypes import windll, byref, c_ulong, c_char_p, create_string_buffer
else:
    # Stub implementations for non-Windows platforms
    def create_string_buffer(*args): return None
    c_ulong = int
    c_char_p = str

class VirtualizationDetector:
    """Handles virtualization environment detection."""
    
    def __init__(self):
        """Initialize virtualization detector."""
        self.logger = logger.bind(handler="vm")
        self.platform = platform.system()
        
    def check_virtualization(self) -> Dict[str, bool]:
        """
        Check for signs of virtualization.
        
        Returns:
            Dict[str, bool]: Results of virtualization checks
        """
        results = {
            "is_virtual": False,
            "hypervisor_present": False,
            "vm_artifacts": False,
            "hardware_signs": False
        }
        
        try:
            if self.platform == "Windows":
                results.update(self._check_windows_vm())
            else:
                results.update(self._check_linux_vm())
                
        except Exception as e:
            self.logger.error(f"Error during virtualization checks: {str(e)}")
            
        return results
        
    def _check_linux_vm(self) -> Dict[str, bool]:
        """Perform Linux-specific virtualization checks."""
        results = {
            "is_virtual": False,
            "hypervisor_present": False,
            "vm_artifacts": False,
            "hardware_signs": False
        }
        
        try:
            # Check systemd-detect-virt if available
            try:
                output = subprocess.check_output(
                    ["systemd-detect-virt"],
                    stderr=subprocess.DEVNULL
                ).decode().strip()
                results["is_virtual"] = output != "none"
            except (subprocess.CalledProcessError, FileNotFoundError):
                pass
                
            # Check /proc/cpuinfo for hypervisor flags
            try:
                with open("/proc/cpuinfo", "r") as f:
                    cpuinfo = f.read().lower()
                    if "hypervisor" in cpuinfo or "vmware" in cpuinfo:
                        results["hypervisor_present"] = True
            except IOError:
                pass
                
            # Check common VM-related files and directories
            vm_artifacts = [
                "/sys/class/dmi/id/product_name",
                "/sys/class/dmi/id/sys_vendor",
                "/proc/scsi/scsi"
            ]
            
            for artifact in vm_artifacts:
                if os.path.exists(artifact):
                    try:
                        with open(artifact, "r") as f:
                            content = f.read().lower()
                            if any(x in content for x in ["vmware", "virtualbox", "qemu", "xen"]):
                                results["vm_artifacts"] = True
                                break
                    except IOError:
                        continue
                        
        except Exception as e:
            self.logger.error(f"Linux VM check error: {str(e)}")
            
        return results
        
    def _check_windows_vm(self) -> Dict[str, bool]:
        """Perform Windows-specific virtualization checks."""
        # Stub for Windows-specific checks
        return {
            "is_virtual": False,
            "hypervisor_present": False,
            "vm_artifacts": False,
            "hardware_signs": False
        }
        
    def get_vm_info(self) -> Dict[str, str]:
        """
        Get detailed information about virtualization environment.
        
        Returns:
            Dict[str, str]: Virtualization environment details
        """
        info = {
            "platform": self.platform,
            "vm_type": "unknown",
            "hypervisor": "unknown"
        }
        
        try:
            if self.platform == "Linux":
                # Try to determine VM type on Linux
                try:
                    vm_type = subprocess.check_output(
                        ["systemd-detect-virt"],
                        stderr=subprocess.DEVNULL
                    ).decode().strip()
                    if vm_type and vm_type != "none":
                        info["vm_type"] = vm_type
                except (subprocess.CalledProcessError, FileNotFoundError):
                    pass
                    
            # Add more platform-specific info gathering as needed
            
        except Exception as e:
            self.logger.error(f"Error getting VM info: {str(e)}")
            
        return info 