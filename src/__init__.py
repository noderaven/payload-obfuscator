"""
Payload Obfuscator package.

This package provides functionality for Windows PE binary obfuscation,
designed for studying and practicing techniques in authorized lab environments.
"""

from .obfuscator import PayloadObfuscator
from .errors import HandlerError

__version__ = "1.0.0"
__author__ = "Your Name"

__all__ = [
    'PayloadObfuscator',
    'HandlerError'
] 