"""
Section transformation functionality.

This module provides functionality for:
- Section content encryption
- Base64 encoding
- Compression
- Polymorphic characteristics
"""

import base64
import zlib
import time
import random
from dataclasses import dataclass
from typing import Dict, Optional, Set
import pefile
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util.Padding import pad, unpad
from loguru import logger

from .errors import TransformError
from .constants import (
    SECTION_CHARACTERISTICS,
    MUTABLE_CHARACTERISTICS,
    REQUIRED_CHARACTERISTICS,
    CRITICAL_SECTIONS,
    AES_BLOCK_SIZE,
    AES_KEY_SIZE,
    DEFAULT_COMPRESSION_LEVEL,
    DEFAULT_MUTATION_RATE,
    TRANSFORM_TYPES
)
from .helpers import get_characteristic_names, is_code_section

@dataclass
class CharacteristicsSnapshot:
    """
    Stores section characteristics for potential reversion.
    
    Attributes:
        section_name: Name of the section
        original_chars: Original characteristics flags
        modified_chars: Modified characteristics flags
        timestamp: When the snapshot was taken
        modifications: Which flags were changed
    """
    section_name: str
    original_chars: int
    modified_chars: int
    timestamp: float
    modifications: Dict[str, bool]  # Which flags were changed

class SectionTransformer:
    """
    Handles section content transformations.
    
    Features:
    - Content encryption (AES-256)
    - Base64 encoding
    - Zlib compression
    - Polymorphic characteristics
    """
    
    def transform_section_content(
        self,
        pe: pefile.PE,
        section: pefile.SectionStructure,
        transform_type: TRANSFORM_TYPES,
        encryption_key: Optional[bytes] = None
    ) -> bool:
        """
        Transform section content using encryption, encoding, or compression.
        
        Args:
            pe: PE file object
            section: Section to transform
            transform_type: Type of transformation ("encrypt", "encode", "compress")
            encryption_key: Optional key for encryption (required if transform_type is "encrypt")
            
        Returns:
            bool: True if successful
            
        Raises:
            TransformError: If transformation fails
            
        Note:
            - Encryption uses AES-256 in CBC mode
            - Encoding uses standard Base64
            - Compression uses zlib
            - Transformed sections are marked as initialized data
        """
        try:
            section_name = section.Name.decode().strip('\x00')
            
            # Verify section is not critical
            if section_name in CRITICAL_SECTIONS:
                raise TransformError(
                    message="Cannot transform critical section",
                    details={"section": section_name},
                    remediation="Choose a non-critical section"
                )
            
            # Get original section data
            original_data = section.get_data()
            original_size = len(original_data)
            
            logger.debug(
                f"Transforming section: {section_name}",
                details={
                    "type": transform_type,
                    "original_size": original_size
                }
            )
            
            # Apply transformation
            if transform_type == "encrypt":
                if not encryption_key:
                    encryption_key = get_random_bytes(AES_KEY_SIZE)
                
                # Initialize AES cipher
                iv = get_random_bytes(AES_BLOCK_SIZE)
                cipher = AES.new(encryption_key, AES.MODE_CBC, iv)
                
                # Encrypt data
                padded_data = pad(original_data, AES_BLOCK_SIZE)
                encrypted_data = cipher.encrypt(padded_data)
                transformed_data = iv + encrypted_data  # Prepend IV
                
                # Log encryption details (excluding key)
                logger.debug(
                    "Encryption details",
                    details={
                        "iv_size": len(iv),
                        "key_size": len(encryption_key) * 8,
                        "mode": "AES-CBC"
                    }
                )
                
            elif transform_type == "encode":
                # Base64 encode
                transformed_data = base64.b64encode(original_data)
                
            elif transform_type == "compress":
                # Compress with zlib
                transformed_data = zlib.compress(
                    original_data,
                    level=DEFAULT_COMPRESSION_LEVEL
                )
                
            else:
                raise TransformError(
                    message="Invalid transformation type",
                    details={"type": transform_type},
                    remediation="Use 'encrypt', 'encode', or 'compress'"
                )
            
            # Update section data
            section.set_data(transformed_data)
            
            # Update section characteristics
            section.Characteristics = (
                section.Characteristics |
                SECTION_CHARACTERISTICS["IMAGE_SCN_CNT_INITIALIZED_DATA"]
            )
            
            logger.info(
                f"Successfully transformed section: {section_name}",
                details={
                    "transform_type": transform_type,
                    "original_size": original_size,
                    "transformed_size": len(transformed_data),
                    "size_delta": len(transformed_data) - original_size,
                    "ratio": round(len(transformed_data) / original_size, 2)
                }
            )
            
            return True
            
        except Exception as e:
            raise TransformError(
                message=f"Error transforming section content",
                details={
                    "section": section_name if 'section_name' in locals() else None,
                    "transform_type": transform_type
                },
                cause=e,
                remediation="Verify section data and transformation parameters"
            )
    
    def apply_polymorphic_characteristics(
        self,
        pe: pefile.PE,
        section: pefile.SectionStructure,
        mutation_rate: float = DEFAULT_MUTATION_RATE,
        save_snapshot: bool = True
    ) -> Optional[CharacteristicsSnapshot]:
        """
        Apply polymorphic changes to section characteristics.
        
        Args:
            pe: PE file object
            section: Section to modify
            mutation_rate: Probability of each mutable flag being changed (0.0-1.0)
            save_snapshot: Whether to save characteristics for potential reversion
            
        Returns:
            Optional[CharacteristicsSnapshot]: Snapshot of changes if save_snapshot=True
            
        Raises:
            TransformError: If characteristic modification fails
            
        Note:
            - Preserves critical functionality (code execution, data access)
            - Randomly toggles non-critical characteristics
            - Can revert changes using snapshot
            - Logs all modifications with reasoning
        """
        try:
            section_name = section.Name.decode().strip('\x00')
            original_chars = section.Characteristics
            
            # Verify section is not critical
            if section_name in CRITICAL_SECTIONS:
                raise TransformError(
                    message="Cannot modify critical section characteristics",
                    details={"section": section_name},
                    remediation="Choose a non-critical section"
                )
            
            logger.debug(
                "Analyzing section characteristics",
                details={
                    "section": section_name,
                    "original": hex(original_chars),
                    "flags": list(get_characteristic_names(original_chars))
                }
            )
            
            # Determine section type and required characteristics
            is_code = is_code_section(original_chars)
            required_flags = (
                REQUIRED_CHARACTERISTICS["code"] if is_code
                else REQUIRED_CHARACTERISTICS["data"]
            )
            
            # Track modifications for logging
            modifications = {}
            new_chars = original_chars
            
            # Apply random mutations to mutable characteristics
            for name, flag in MUTABLE_CHARACTERISTICS.items():
                # Skip if flag is part of required characteristics
                if name in required_flags:
                    continue
                
                # Randomly decide to toggle this flag
                if random.random() < mutation_rate:
                    current_state = bool(original_chars & flag)
                    new_state = not current_state
                    
                    if new_state:
                        new_chars |= flag  # Set flag
                    else:
                        new_chars &= ~flag  # Clear flag
                    
                    modifications[name] = new_state
            
            # Create snapshot if requested
            snapshot = None
            if save_snapshot:
                snapshot = CharacteristicsSnapshot(
                    section_name=section_name,
                    original_chars=original_chars,
                    modified_chars=new_chars,
                    timestamp=time.time(),
                    modifications=modifications
                )
            
            # Update section characteristics
            section.Characteristics = new_chars
            
            # Log changes
            logger.info(
                "Applied polymorphic characteristics",
                details={
                    "section": section_name,
                    "original": {
                        "value": hex(original_chars),
                        "flags": list(get_characteristic_names(original_chars))
                    },
                    "modified": {
                        "value": hex(new_chars),
                        "flags": list(get_characteristic_names(new_chars))
                    },
                    "changes": {
                        name: ("Set" if state else "Cleared")
                        for name, state in modifications.items()
                    },
                    "preserved": list(required_flags)
                }
            )
            
            return snapshot
            
        except Exception as e:
            raise TransformError(
                message="Error applying polymorphic characteristics",
                details={
                    "section": section_name if 'section_name' in locals() else None,
                    "original_chars": hex(original_chars) if 'original_chars' in locals() else None
                },
                cause=e,
                remediation="Verify section exists and characteristics can be modified"
            )
    
    def revert_characteristics(
        self,
        pe: pefile.PE,
        section: pefile.SectionStructure,
        snapshot: CharacteristicsSnapshot
    ) -> bool:
        """
        Revert section characteristics to their state in the snapshot.
        
        Args:
            pe: PE file object
            section: Section to revert
            snapshot: Previous characteristics snapshot
            
        Returns:
            bool: True if successfully reverted
            
        Raises:
            TransformError: If reversion fails
        """
        try:
            section_name = section.Name.decode().strip('\x00')
            
            # Verify snapshot matches section
            if section_name != snapshot.section_name:
                raise TransformError(
                    message="Snapshot does not match section",
                    details={
                        "section": section_name,
                        "snapshot_section": snapshot.section_name
                    },
                    remediation="Provide matching snapshot for section"
                )
            
            # Restore original characteristics
            section.Characteristics = snapshot.original_chars
            
            logger.info(
                "Reverted section characteristics",
                details={
                    "section": section_name,
                    "from": hex(snapshot.modified_chars),
                    "to": hex(snapshot.original_chars),
                    "reverted_changes": snapshot.modifications
                }
            )
            
            return True
            
        except Exception as e:
            raise TransformError(
                message="Error reverting characteristics",
                details={
                    "section": section_name if 'section_name' in locals() else None
                },
                cause=e,
                remediation="Verify snapshot is valid and section exists"
            ) 