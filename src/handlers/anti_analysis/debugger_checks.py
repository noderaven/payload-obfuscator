"""
Debugger detection and anti-debugging techniques.

This module implements various methods to detect debuggers and analysis tools,
including both user-mode and kernel-mode debuggers.
"""

import ctypes
import sys
import time
import os
from typing import List, Dict, Optional, Tuple
from ctypes import windll, c_bool, c_uint32, byref, sizeof, Structure, Union
from ctypes.wintypes import DWORD, HANDLE, BOOL, LPVOID
from loguru import logger

class SYSTEM_KERNEL_DEBUGGER_INFORMATION(Structure):
    _fields_ = [
        ("KernelDebuggerEnabled", BOOL),
        ("KernelDebuggerNotPresent", BOOL),
    ]

class DebuggerDetector:
    """
    Implements various debugger detection techniques.
    
    Features:
    - Process environment checks
    - Timing checks
    - API hooking detection
    - Hardware breakpoint detection
    - Anti-step techniques
    """
    
    def __init__(self):
        """Initialize debugger detector with required DLL imports."""
        self.kernel32 = windll.kernel32
        self.ntdll = windll.ntdll
        
    def is_being_debugged(self) -> bool:
        """
        Combine multiple detection methods to check for debugger presence.
        
        Returns:
            bool: True if debugger detected, False otherwise
        """
        checks = [
            self._check_remote_debugger,
            self._check_debug_flags,
            self._check_debug_object,
            self._check_debug_port,
            self._check_hardware_breakpoints,
            self._check_timing_anomalies
        ]
        
        for check in checks:
            try:
                if check():
                    logger.warning(f"Debugger detected via {check.__name__}")
                    return True
            except Exception as e:
                logger.debug(f"Check {check.__name__} failed: {str(e)}")
                
        return False
        
    def _check_remote_debugger(self) -> bool:
        """
        Check if process is being debugged using IsDebuggerPresent.
        
        Returns:
            bool: True if debugger detected
        """
        return bool(self.kernel32.IsDebuggerPresent())
        
    def _check_debug_flags(self) -> bool:
        """
        Check process debug flags in PEB.
        
        Returns:
            bool: True if debug flags detected
        """
        try:
            class PROCESS_BASIC_INFORMATION(Structure):
                _fields_ = [
                    ("Reserved1", LPVOID),
                    ("PebBaseAddress", LPVOID),
                    ("Reserved2", LPVOID * 2),
                    ("UniqueProcessId", LPVOID),
                    ("Reserved3", LPVOID),
                ]
                
            process = self.kernel32.GetCurrentProcess()
            info = PROCESS_BASIC_INFORMATION()
            size = c_uint32()
            
            status = self.ntdll.NtQueryInformationProcess(
                process,
                0,  # ProcessBasicInformation
                byref(info),
                sizeof(info),
                byref(size)
            )
            
            if status == 0:  # STATUS_SUCCESS
                return bool(info.Reserved1)  # BeingDebugged flag
                
            return False
            
        except Exception as e:
            logger.debug(f"Debug flags check failed: {str(e)}")
            return False
            
    def _check_debug_object(self) -> bool:
        """
        Check for debug object handle.
        
        Returns:
            bool: True if debug object detected
        """
        try:
            debug_object = c_uint32()
            status = self.ntdll.NtQueryInformationProcess(
                self.kernel32.GetCurrentProcess(),
                0x1E,  # ProcessDebugObjectHandle
                byref(debug_object),
                sizeof(debug_object),
                None
            )
            
            return status == 0  # STATUS_SUCCESS means debugger present
            
        except Exception as e:
            logger.debug(f"Debug object check failed: {str(e)}")
            return False
            
    def _check_debug_port(self) -> bool:
        """
        Check for debug port.
        
        Returns:
            bool: True if debug port detected
        """
        try:
            debug_port = c_uint32()
            status = self.ntdll.NtQueryInformationProcess(
                self.kernel32.GetCurrentProcess(),
                7,  # ProcessDebugPort
                byref(debug_port),
                sizeof(debug_port),
                None
            )
            
            return status == 0 and debug_port.value != 0
            
        except Exception as e:
            logger.debug(f"Debug port check failed: {str(e)}")
            return False
            
    def _check_hardware_breakpoints(self) -> bool:
        """
        Check for hardware breakpoints in thread context.
        
        Returns:
            bool: True if hardware breakpoints detected
        """
        try:
            class CONTEXT(Structure):
                _fields_ = [
                    ("ContextFlags", DWORD),
                    ("Dr0", LPVOID),
                    ("Dr1", LPVOID),
                    ("Dr2", LPVOID),
                    ("Dr3", LPVOID),
                    ("Dr6", LPVOID),
                    ("Dr7", LPVOID)
                ]
                
            thread = self.kernel32.GetCurrentThread()
            context = CONTEXT()
            context.ContextFlags = 0x00100010  # CONTEXT_DEBUG_REGISTERS
            
            if self.kernel32.GetThreadContext(thread, byref(context)):
                # Check debug registers
                return any([
                    context.Dr0, context.Dr1,
                    context.Dr2, context.Dr3
                ])
                
            return False
            
        except Exception as e:
            logger.debug(f"Hardware breakpoint check failed: {str(e)}")
            return False
            
    def _check_timing_anomalies(self) -> bool:
        """
        Check for timing anomalies that might indicate stepping/debugging.
        
        Returns:
            bool: True if timing anomalies detected
        """
        try:
            start_ticks = self.kernel32.GetTickCount()
            
            # Execute some simple operations
            for _ in range(1000):
                pass
                
            end_ticks = self.kernel32.GetTickCount()
            elapsed = end_ticks - start_ticks
            
            # If execution took too long, might be debugger
            return elapsed > 100  # milliseconds
            
        except Exception as e:
            logger.debug(f"Timing check failed: {str(e)}")
            return False
            
    def apply_anti_debug_techniques(self) -> None:
        """
        Apply various anti-debugging techniques.
        
        This includes:
        - Setting hardware breakpoints
        - Modifying thread context
        - Adding timing checks
        - Implementing anti-step measures
        """
        try:
            # Set trap flag in EFLAGS
            self._set_trap_flag()
            
            # Modify thread context
            self._modify_thread_context()
            
            # Add timing checks
            self._insert_timing_checks()
            
            logger.success("Applied anti-debugging techniques")
            
        except Exception as e:
            logger.error(f"Failed to apply anti-debugging: {str(e)}")
            
    def _set_trap_flag(self) -> None:
        """Set trap flag in EFLAGS register."""
        try:
            thread = self.kernel32.GetCurrentThread()
            context = CONTEXT()
            context.ContextFlags = 0x00100000  # CONTEXT_EXTENDED_REGISTERS
            
            if self.kernel32.GetThreadContext(thread, byref(context)):
                # Set trap flag (bit 8)
                context.Dr7 |= 0x100
                self.kernel32.SetThreadContext(thread, byref(context))
                
        except Exception as e:
            logger.debug(f"Failed to set trap flag: {str(e)}")
            
    def _modify_thread_context(self) -> None:
        """Modify thread context to interfere with debugging."""
        try:
            thread = self.kernel32.GetCurrentThread()
            context = CONTEXT()
            context.ContextFlags = 0x00100010  # CONTEXT_DEBUG_REGISTERS
            
            if self.kernel32.GetThreadContext(thread, byref(context)):
                # Set debug registers to invalid values
                context.Dr0 = 0xFFFFFFFF
                context.Dr1 = 0xFFFFFFFF
                context.Dr2 = 0xFFFFFFFF
                context.Dr3 = 0xFFFFFFFF
                
                self.kernel32.SetThreadContext(thread, byref(context))
                
        except Exception as e:
            logger.debug(f"Failed to modify thread context: {str(e)}")
            
    def _insert_timing_checks(self) -> None:
        """Insert timing checks throughout the code."""
        try:
            # Record initial timing
            self._timing_check_points = {
                "start": self.kernel32.GetTickCount()
            }
            
            # Set up timing verification points
            def timing_check():
                current = self.kernel32.GetTickCount()
                if current - self._timing_check_points["start"] > 5000:
                    sys.exit(1)
                    
            # Register timing check
            import atexit
            atexit.register(timing_check)
            
        except Exception as e:
            logger.debug(f"Failed to insert timing checks: {str(e)}") 