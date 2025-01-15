"""
Validation Handler Module
=====================

This module provides comprehensive validation of PE files, including:
- File existence and permission checks
- PE structure validation
- Header validation
- Machine type verification
- Subsystem validation
"""

import os
from typing import Optional, Dict, Any, Tuple
import pefile
from loguru import logger

from ..base_handler import BaseHandler, HandlerError

class ValidationError(HandlerError):
    """
    Exception for PE validation errors.
    
    Attributes:
        message: Description of the error
        details: Additional context about the error
        cause: Original exception if any
        remediation: Suggested fix
        
    Example:
        ```python
        raise ValidationError(
            message="Invalid PE format",
            details={"error": "Missing DOS header"},
            cause=pe_error,
            remediation="Verify file is a valid PE"
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

class ValidationHandler(BaseHandler):
    """
    Handles PE file validation operations.
    
    Features:
    - File existence and permission checks
    - PE structure validation
    - Header validation
    - Machine type verification
    - Subsystem validation
    """
    
    # Valid machine types
    VALID_MACHINE_TYPES = {
        0x014c: 'x86',
        0x0200: 'IA64',
        0x8664: 'x64',
    }
    
    # Size thresholds (in bytes)
    MIN_PE_SIZE = 1024  # 1KB
    MAX_PE_SIZE = 100 * 1024 * 1024  # 100MB
    
    def validate_pe(self, filepath: str) -> Optional[pefile.PE]:
        """
        Validate PE file and return loaded PE object if valid.
        
        Args:
            filepath: Path to PE file
            
        Returns:
            Optional[pefile.PE]: Loaded PE object if valid, None otherwise
            
        Raises:
            ValidationError: If validation fails
            
        Note:
            Validation steps:
            1. Check file existence and permissions
            2. Verify file size
            3. Parse PE structure
            4. Validate headers
            5. Check machine type
            6. Verify sections
        """
        try:
            # Check file existence and permissions
            if not os.path.exists(filepath):
                raise ValidationError(
                    message="File does not exist",
                    details={"path": filepath},
                    remediation="Verify file path is correct"
                )
            
            if not os.access(filepath, os.R_OK):
                raise ValidationError(
                    message="File not readable",
                    details={"path": filepath},
                    remediation="Check file permissions"
                )
            
            # Check file size
            file_size = os.path.getsize(filepath)
            if file_size < self.MIN_PE_SIZE:
                raise ValidationError(
                    message="File too small to be valid PE",
                    details={
                        "size": file_size,
                        "min_size": self.MIN_PE_SIZE
                    },
                    remediation="Verify file is complete"
                )
            
            if file_size > self.MAX_PE_SIZE:
                self.logger.warning(
                    "Large PE file detected",
                    details={
                        "size": file_size,
                        "threshold": self.MAX_PE_SIZE
                    }
                )
            
            # Load PE file
            try:
                pe = pefile.PE(filepath)
            except pefile.PEFormatError as e:
                raise ValidationError(
                    message="Invalid PE format",
                    details={"error": str(e)},
                    cause=e,
                    remediation="Verify file is a valid PE"
                )
            
            # Validate DOS header
            if pe.DOS_HEADER.e_magic != 0x5A4D:  # 'MZ'
                raise ValidationError(
                    message="Invalid DOS header",
                    details={"magic": hex(pe.DOS_HEADER.e_magic)},
                    remediation="File must start with valid MZ header"
                )
            
            # Validate PE header
            if pe.NT_HEADERS.Signature != 0x4550:  # 'PE\0\0'
                raise ValidationError(
                    message="Invalid PE signature",
                    details={"signature": hex(pe.NT_HEADERS.Signature)},
                    remediation="File must have valid PE signature"
                )
            
            # Check machine type
            machine_type = pe.FILE_HEADER.Machine
            if machine_type not in self.VALID_MACHINE_TYPES:
                self.logger.warning(
                    "Unusual machine type",
                    details={
                        "type": hex(machine_type),
                        "valid_types": [
                            hex(t) for t in self.VALID_MACHINE_TYPES.keys()
                        ]
                    }
                )
            
            # Verify sections
            if not pe.sections:
                raise ValidationError(
                    message="No sections found",
                    details={"file": filepath},
                    remediation="PE file must contain at least one section"
                )
            
            # Log validation success
            self._log_success(
                "PE validation successful",
                details={
                    "file": filepath,
                    "size": file_size,
                    "machine": self.VALID_MACHINE_TYPES.get(
                        machine_type,
                        f"Unknown ({hex(machine_type)})"
                    ),
                    "sections": len(pe.sections)
                }
            )
            
            return pe
            
        except ValidationError:
            raise
            
        except Exception as e:
            raise ValidationError(
                message="Unexpected error during validation",
                details={"file": filepath},
                cause=e,
                remediation="Check file integrity and permissions"
            )
    
    def verify_subsystem(
        self,
        pe: pefile.PE,
        expected_subsystem: Optional[int] = None
    ) -> bool:
        """
        Verify PE subsystem.
        
        Args:
            pe: PE file object
            expected_subsystem: Expected subsystem value (optional)
            
        Returns:
            bool: True if subsystem is valid
            
        Note:
            Common subsystems:
            - 1: Native
            - 2: Windows GUI
            - 3: Windows Console
            - 9: Windows CE GUI
        """
        try:
            subsystem = pe.OPTIONAL_HEADER.Subsystem
            
            if expected_subsystem and subsystem != expected_subsystem:
                self.logger.warning(
                    "Unexpected subsystem",
                    details={
                        "found": subsystem,
                        "expected": expected_subsystem
                    }
                )
                return False
            
            # Log subsystem info
            self.logger.debug(
                "Subsystem verification",
                details={"subsystem": subsystem}
            )
            
            return True
            
        except Exception as e:
            self.logger.error(
                "Error verifying subsystem",
                error=e
            )
            return False
    
    def verify_imports(
        self,
        pe: pefile.PE,
        required_dlls: Optional[list] = None
    ) -> Tuple[bool, list]:
        """
        Verify PE imports.
        
        Args:
            pe: PE file object
            required_dlls: List of required DLL names (optional)
            
        Returns:
            Tuple[bool, list]: (Success status, List of missing DLLs)
            
        Note:
            This method checks:
            1. Import directory exists
            2. Required DLLs are present
            3. Import table structure
        """
        try:
            if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                self.logger.warning("No import directory found")
                return False, []
            
            imported_dlls = {
                entry.dll.decode().lower()
                for entry in pe.DIRECTORY_ENTRY_IMPORT
            }
            
            # Check for required DLLs
            if required_dlls:
                missing_dlls = [
                    dll for dll in required_dlls
                    if dll.lower() not in imported_dlls
                ]
                
                if missing_dlls:
                    self.logger.warning(
                        "Missing required DLLs",
                        details={"missing": missing_dlls}
                    )
                    return False, missing_dlls
            
            # Log import information
            self.logger.debug(
                "Import verification successful",
                details={"dlls": list(imported_dlls)}
            )
            
            return True, []
            
        except Exception as e:
            self.logger.error(
                "Error verifying imports",
                error=e
            )
            return False, [] 