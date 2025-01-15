"""
Anti-analysis techniques for PE files.

This module provides various anti-analysis features to help evade detection
and make reverse engineering more difficult.
"""

from .debugger_checks import DebuggerDetector
from .timing_checks import TimingChecker
from .vm_checks import VirtualizationDetector
from .integrity_checks import IntegrityChecker

__all__ = [
    'DebuggerDetector',
    'TimingChecker',
    'VirtualizationDetector',
    'IntegrityChecker'
] 