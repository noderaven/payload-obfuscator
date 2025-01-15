"""
Custom error classes for PE section handling.

This module defines specialized error classes for section-related operations:
- SectionError: Base error for section operations
- ValidationError: For section validation failures
- TransformError: For section transformation failures
- AlignmentError: For section alignment issues
"""

from typing import Optional, Dict, Any
from ....errors import HandlerError

class SectionError(HandlerError):
    """
    Exception for section-related errors.
    
    Attributes:
        message: Description of the error
        details: Additional context about the error
        cause: Original exception if any
        remediation: Suggested fix
        
    Example:
        ```python
        raise SectionError(
            message="Insufficient space in section",
            details={"section": ".text", "required": 1024},
            cause=space_error,
            remediation="Try creating a new section"
        )
        ```
    """
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        remediation: Optional[str] = None
    ):
        super().__init__(message, details, cause, remediation)

class ValidationError(SectionError):
    """
    Exception for section validation failures.
    
    Example:
        ```python
        raise ValidationError(
            message="Invalid section name",
            details={"name": name, "max_length": 8},
            remediation="Use a name with 8 or fewer characters"
        )
        ```
    """
    pass

class TransformError(SectionError):
    """
    Exception for section transformation failures.
    
    Example:
        ```python
        raise TransformError(
            message="Encryption failed",
            details={"section": name, "transform_type": "encrypt"},
            cause=crypto_error,
            remediation="Verify encryption parameters"
        )
        ```
    """
    pass

class AlignmentError(SectionError):
    """
    Exception for section alignment issues.
    
    Example:
        ```python
        raise AlignmentError(
            message="Section misaligned",
            details={
                "section": name,
                "offset": offset,
                "alignment": alignment
            },
            remediation="Adjust section to match file alignment"
        )
        ```
    """
    pass 