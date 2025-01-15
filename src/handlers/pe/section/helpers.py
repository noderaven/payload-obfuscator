"""
Helper functions for PE section handling.

This module provides utility functions for:
- Section name validation and generation
- Characteristic management
- Space validation
- Section type checking
"""

import random
import pefile
from typing import Set, Dict, Any, Optional, Tuple
from loguru import logger

from .errors import ValidationError, AlignmentError
from .constants import (
    SECTION_CHARACTERISTICS,
    VALID_NAME_CHARS,
    MAX_NAME_LENGTH,
    DEFAULT_MAX_ATTEMPTS
)

def validate_section_name(name: str) -> bool:
    """
    Validate a section name.
    
    Args:
        name: Section name to validate
        
    Returns:
        bool: True if valid
        
    Raises:
        ValidationError: If name is invalid
        
    Note:
        - Must be 8 characters or less
        - Can only contain valid characters
        - Cannot be empty
    """
    try:
        if not name:
            raise ValidationError(
                message="Empty section name",
                remediation="Provide a non-empty name"
            )
            
        if len(name) > MAX_NAME_LENGTH:
            raise ValidationError(
                message="Section name too long",
                details={"name": name, "max_length": MAX_NAME_LENGTH},
                remediation="Use a name with 8 or fewer characters"
            )
            
        invalid_chars = set(name) - set(VALID_NAME_CHARS)
        if invalid_chars:
            raise ValidationError(
                message="Invalid characters in section name",
                details={
                    "name": name,
                    "invalid_chars": list(invalid_chars),
                    "valid_chars": VALID_NAME_CHARS
                },
                remediation="Use only alphanumeric characters and '_-'"
            )
            
        return True
        
    except ValidationError:
        raise
        
    except Exception as e:
        raise ValidationError(
            message="Error validating section name",
            details={"name": name},
            cause=e
        )

def get_existing_section_names(pe: pefile.PE) -> Set[str]:
    """
    Get set of existing section names.
    
    Args:
        pe: PE file object
        
    Returns:
        Set[str]: Set of section names
    """
    return {
        section.Name.decode().strip('\x00')
        for section in pe.sections
    }

def generate_random_name(
    existing_names: Set[str],
    max_attempts: int = DEFAULT_MAX_ATTEMPTS
) -> str:
    """
    Generate a unique random section name.
    
    Args:
        existing_names: Set of existing section names to avoid
        max_attempts: Maximum number of attempts to generate unique name
        
    Returns:
        str: Generated unique name
        
    Raises:
        ValidationError: If unable to generate unique name
    """
    for _ in range(max_attempts):
        # Generate 8-character random name
        name = ''.join(random.choices(VALID_NAME_CHARS, k=MAX_NAME_LENGTH))
        
        if name not in existing_names:
            return name
    
    raise ValidationError(
        message="Failed to generate unique section name",
        details={"attempts": max_attempts},
        remediation="Try increasing max_attempts or using different name pattern"
    )

def get_characteristic_names(characteristics: int) -> Set[str]:
    """
    Get set of characteristic names from flags.
    
    Args:
        characteristics: Section characteristics flags
        
    Returns:
        Set[str]: Set of characteristic names
    """
    return {
        name for name, value in SECTION_CHARACTERISTICS.items()
        if characteristics & value
    }

def is_code_section(characteristics: int) -> bool:
    """
    Check if section contains code based on characteristics.
    
    Args:
        characteristics: Section characteristics flags
        
    Returns:
        bool: True if section contains code
    """
    return bool(characteristics & SECTION_CHARACTERISTICS["IMAGE_SCN_CNT_CODE"])

def validate_space(
    pe: pefile.PE,
    section: pefile.SectionStructure,
    required_space: int,
    consider_alignment: bool = True
) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """
    Validate if a section has sufficient space for data injection.
    
    Args:
        pe: PE file object
        section: Section to validate
        required_space: Space needed in bytes
        consider_alignment: Whether to consider alignment requirements
        
    Returns:
        Tuple[bool, Optional[Dict[str, Any]]]: 
            - Success flag
            - Validation details if failed, None if successful
            
    Note:
        Validation includes:
        1. Raw data space
        2. Virtual space
        3. Alignment requirements
        4. Padding considerations
    """
    try:
        section_name = section.Name.decode().strip('\x00')
        
        # Calculate available spaces
        raw_available = section.SizeOfRawData - section.PointerToRawData
        virtual_available = section.Misc_VirtualSize - section.VirtualAddress
        
        # Consider alignment if requested
        if consider_alignment:
            # Calculate aligned sizes
            aligned_required = (
                (required_space + pe.OPTIONAL_HEADER.FileAlignment - 1)
                & ~(pe.OPTIONAL_HEADER.FileAlignment - 1)
            )
            
            # Account for potential padding
            padding_size = aligned_required - required_space
            total_required = aligned_required
        else:
            aligned_required = required_space
            padding_size = 0
            total_required = required_space
        
        # Perform validations
        validations = {
            "raw_space": raw_available >= total_required,
            "virtual_space": virtual_available >= total_required,
            "alignment_compatible": (
                not consider_alignment or
                section.PointerToRawData % pe.OPTIONAL_HEADER.FileAlignment == 0
            )
        }
        
        # If all validations pass
        if all(validations.values()):
            return True, None
        
        # Prepare detailed failure information
        failed_checks = {
            name: {
                "required": total_required,
                "available": raw_available if "raw" in name else virtual_available,
                "aligned_size": aligned_required if consider_alignment else None,
                "padding": padding_size if consider_alignment else None
            }
            for name, passed in validations.items()
            if not passed
        }
        
        return False, {
            "section": section_name,
            "failed_checks": failed_checks,
            "alignment": {
                "file_alignment": pe.OPTIONAL_HEADER.FileAlignment,
                "section_alignment": pe.OPTIONAL_HEADER.SectionAlignment
            } if consider_alignment else None
        }
        
    except Exception as e:
        logger.error(
            "Error validating section space",
            error=e,
            details={
                "section": section_name if 'section_name' in locals() else None,
                "required_space": required_space
            }
        )
        raise AlignmentError(
            message="Error validating section space",
            details={
                "section": section_name if 'section_name' in locals() else None,
                "required_space": required_space
            },
            cause=e,
            remediation="Verify section exists and space requirements"
        ) 