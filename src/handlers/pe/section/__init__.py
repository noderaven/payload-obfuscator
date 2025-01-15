"""
PE section handling module.

This module provides functionality for PE section manipulation:
- Section creation and modification
- Content transformation (encryption, encoding, compression)
- Section splitting and merging
- Space validation and alignment
"""

from .section_handler import SectionHandler
from .errors import (
    SectionError,
    ValidationError,
    TransformError,
    AlignmentError
)
from .constants import (
    SECTION_CHARACTERISTICS,
    MUTABLE_CHARACTERISTICS,
    REQUIRED_CHARACTERISTICS,
    CRITICAL_SECTIONS,
    TRANSFORM_TYPES
)
from .section_transform import CharacteristicsSnapshot

__all__ = [
    # Main handler
    'SectionHandler',
    
    # Error classes
    'SectionError',
    'ValidationError',
    'TransformError',
    'AlignmentError',
    
    # Constants
    'SECTION_CHARACTERISTICS',
    'MUTABLE_CHARACTERISTICS',
    'REQUIRED_CHARACTERISTICS',
    'CRITICAL_SECTIONS',
    'TRANSFORM_TYPES',
    
    # Data classes
    'CharacteristicsSnapshot'
] 