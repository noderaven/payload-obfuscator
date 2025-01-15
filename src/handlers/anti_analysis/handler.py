"""
Main handler for anti-analysis features.

This module orchestrates all anti-analysis capabilities including:
- Debugger detection and evasion
- Virtualization detection
- Timing checks
- Integrity verification
"""

from typing import Dict, Any, Optional
from loguru import logger

from .debugger_checks import DebuggerDetector
from .vm_checks import VirtualizationDetector
from ...base_handler import BaseHandler

class AntiAnalysisHandler(BaseHandler):
    """
    Main handler for anti-analysis features.
    
    This class orchestrates all anti-analysis operations and provides
    a unified interface for the obfuscator.
    """
    
    def __init__(self):
        """Initialize anti-analysis components."""
        super().__init__()
        self.debugger_detector = DebuggerDetector()
        self.vm_detector = VirtualizationDetector()
        
    def check_environment(self) -> Dict[str, bool]:
        """
        Perform comprehensive environment analysis.
        
        Returns:
            Dict containing detection results for each category
        """
        try:
            results = {
                "debugger_detected": False,
                "virtualization_detected": False,
                "timing_anomalies": False
            }
            
            # Check for debuggers
            if self.debugger_detector.is_being_debugged():
                results["debugger_detected"] = True
                logger.warning("Debugger detected")
                
            # Check for virtualization
            if self.vm_detector.is_virtualized():
                results["virtualization_detected"] = True
                logger.warning("Virtualization detected")
                
            return results
            
        except Exception as e:
            logger.error(f"Environment check failed: {str(e)}")
            return results
            
    def apply_evasion_techniques(self, 
                               skip_debugger: bool = False,
                               skip_vm: bool = False) -> bool:
        """
        Apply all evasion techniques.
        
        Args:
            skip_debugger: Skip debugger evasion
            skip_vm: Skip VM evasion
            
        Returns:
            bool: True if all selected techniques applied successfully
        """
        try:
            success = True
            
            if not skip_debugger:
                try:
                    self.debugger_detector.apply_anti_debug_techniques()
                except Exception as e:
                    logger.error(f"Debugger evasion failed: {str(e)}")
                    success = False
                    
            if not skip_vm:
                try:
                    self.vm_detector.apply_vm_evasion()
                except Exception as e:
                    logger.error(f"VM evasion failed: {str(e)}")
                    success = False
                    
            return success
            
        except Exception as e:
            logger.error(f"Evasion application failed: {str(e)}")
            return False
            
    def get_environment_info(self) -> Dict[str, Any]:
        """
        Get detailed information about the execution environment.
        
        Returns:
            Dict containing environment details
        """
        try:
            import platform
            import psutil
            
            info = {
                "platform": platform.platform(),
                "processor": platform.processor(),
                "python_version": platform.python_version(),
                "memory": psutil.virtual_memory()._asdict(),
                "cpu_count": psutil.cpu_count(),
                "network": len(psutil.net_if_addrs()),
                "analysis_indicators": self.check_environment()
            }
            
            return info
            
        except Exception as e:
            logger.error(f"Failed to get environment info: {str(e)}")
            return {} 