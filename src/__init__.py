"""
Payload Obfuscator package.

This package provides functionality for Windows PE binary obfuscation,
designed for studying and practicing techniques in authorized lab environments.
"""

__version__ = "1.0.0"
__author__ = "rileymxyz"

# Import after defining package metadata
from .obfuscator import PayloadObfuscator
from .handlers.base_handler import HandlerError

__all__ = [
    'PayloadObfuscator',
    'HandlerError'
]