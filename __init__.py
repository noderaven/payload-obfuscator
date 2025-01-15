"""
Windows Binary Payload Obfuscator Package

A tool for studying and practicing binary obfuscation techniques in the context
of the OSEP (PEN-300) exam. This package provides functionality for obfuscating
Windows PE files using various techniques.

Note:
    This tool is intended for educational purposes only, specifically for practicing
    techniques covered in the OSEP exam within authorized lab environments.
"""

from payload_obfuscator.src.obfuscator import PayloadObfuscator

__version__ = "1.0.0"
__author__ = "OSEP Student"
__license__ = "MIT"

__all__ = ['PayloadObfuscator'] 