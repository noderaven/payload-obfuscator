"""
PE file handling module.

This module provides functionality for PE file manipulation:
- Section handling (creation, modification, transformation)
- Import table manipulation
- Resource manipulation
- Checksum handling
"""

from .section.section_handler import SectionHandler
from .section.errors import SectionError
from .import_handler import ImportHandler
from .resource_handler import ResourceHandler
from .checksum_handler import ChecksumHandler, ChecksumError

__all__ = [
    # Main handlers
    'PEHandler',
    'SectionHandler',
    'ImportHandler',
    'ResourceHandler',
    'ChecksumHandler',
    
    # Error classes
    'SectionError',
    'ChecksumError'
] 