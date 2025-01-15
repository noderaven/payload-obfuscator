"""
Checksum Handler Module
====================

This module provides specialized handling of PE file checksums, including:
- Checksum calculation and verification
- Multiple verification attempts
- Flexible update policies
- Detailed error tracking
"""

import pefile
from typing import Optional, Dict, Any
from loguru import logger
from dataclasses import dataclass
from pathlib import Path

from ..base_handler import BaseHandler, HandlerError

@dataclass
class ChecksumContext:
    """
    Contains checksum-related values and context.
    """
    original: Optional[int] = None
    calculated: Optional[int] = None
    current: Optional[int] = None
    delta: Optional[int] = None
    attempt_count: Optional[int] = None

@dataclass
class PEMetadata:
    """
    Contains relevant PE file metadata.
    """
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    machine_type: Optional[str] = None
    characteristics: Optional[int] = None
    timestamp: Optional[int] = None

class ChecksumError(HandlerError):
    """
    Exception for checksum-related errors.
    
    Attributes:
        message: Description of the error
        details: Additional context about the error
        cause: Original exception if any
        remediation: Suggested fix
        pe_metadata: PE file metadata including path, size, and machine type
        checksum_context: Checksum-related values and verification context
        
    Example:
        ```python
        raise ChecksumError(
            message="Checksum verification failed",
            details={"verification_status": "failed"},
            pe_metadata=PEMetadata(file_path="/path/to/file.exe", file_size=1234),
            checksum_context=ChecksumContext(original=0x1234, calculated=0x5678),
            cause=verification_error,
            remediation="Try with force_update=True"
        )
        ```
    """
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        pe_metadata: Optional[PEMetadata] = None,
        checksum_context: Optional[ChecksumContext] = None,
        cause: Optional[Exception] = None,
        remediation: Optional[str] = None
    ):
        # Combine all metadata into a structured details dict
        enhanced_details = {
            **(details or {}),
            "pe_metadata": {
                "file_path": pe_metadata.file_path if pe_metadata else None,
                "file_size": pe_metadata.file_size if pe_metadata else None,
                "machine_type": pe_metadata.machine_type if pe_metadata else None,
                "characteristics": pe_metadata.characteristics if pe_metadata else None,
                "timestamp": pe_metadata.timestamp if pe_metadata else None
            },
            "checksum_context": {
                "original": hex(checksum_context.original) if checksum_context and checksum_context.original is not None else None,
                "calculated": hex(checksum_context.calculated) if checksum_context and checksum_context.calculated is not None else None,
                "current": hex(checksum_context.current) if checksum_context and checksum_context.current is not None else None,
                "delta": hex(checksum_context.delta) if checksum_context and checksum_context.delta is not None else None,
                "attempt_count": checksum_context.attempt_count if checksum_context else None
            }
        }
        super().__init__(message, enhanced_details, cause, remediation)

class ChecksumHandler(BaseHandler):
    """
    Handles PE file checksum operations.
    
    Features:
    - Checksum calculation and verification
    - Multiple verification attempts
    - Automatic rollback on failure
    - Detailed logging and error tracking
    """
    
    def update_checksum(
        self,
        pe: pefile.PE,
        force_update: bool = False,
        skip_verify: bool = False,
        retry_attempts: int = 3
    ) -> bool:
        """
        Update and verify the PE file checksum.
        
        Args:
            pe: PE file object to update
            force_update: Whether to keep new checksum even if verification fails
            skip_verify: Whether to skip checksum verification entirely
            retry_attempts: Number of verification retries before failing
            
        Returns:
            bool: True if checksum update successful
            
        Raises:
            ChecksumError: If checksum update or verification fails
            
        Note:
            Verification Strategy:
            1. Calculate and store original checksum
            2. Generate and apply new checksum
            3. Verify new checksum (if not skipped)
            4. Handle verification failure based on force_update:
               - If True: Keep new checksum but log warning
               - If False: Revert to original checksum
            
            Skip verification if:
            - skip_verify is True
            - File has extensive modifications
            - Previous verification attempts failed
        """
        try:
            # Store original checksum
            original_checksum = pe.OPTIONAL_HEADER.CheckSum
            self.logger.debug(
                "Original checksum",
                details={"checksum": hex(original_checksum)}
            )
            
            # Generate new checksum
            new_checksum = pe.generate_checksum()
            self.logger.debug(
                "Generated new checksum",
                details={
                    "checksum": hex(new_checksum),
                    "delta": hex(new_checksum - original_checksum)
                }
            )
            
            # Apply new checksum
            pe.OPTIONAL_HEADER.CheckSum = new_checksum
            
            # Skip verification if requested
            if skip_verify:
                self.logger.info(
                    "Skipping checksum verification",
                    details={"reason": "skip_verify=True"}
                )
                return True
            
            # Attempt verification
            verification_failed = False
            error_details = {}
            
            for attempt in range(retry_attempts):
                try:
                    if pe.verify_checksum():
                        self._log_success(
                            "Checksum verification successful",
                            details={
                                "original": hex(original_checksum),
                                "new": hex(new_checksum),
                                "attempts": attempt + 1
                            }
                        )
                        return True
                    else:
                        self.logger.warning(
                            f"Verification attempt {attempt + 1} failed",
                            details={"checksum": hex(new_checksum)}
                        )
                except Exception as e:
                    error_details = {
                        "error": str(e),
                        "attempt": attempt + 1,
                        "checksum": hex(new_checksum)
                    }
                    self.logger.warning(
                        "Verification error",
                        details=error_details
                    )
                
                verification_failed = True
            
            # Handle verification failure
            if verification_failed:
                if force_update:
                    self.logger.warning(
                        "Keeping unverified checksum",
                        details={
                            "reason": "force_update=True",
                            "checksum": hex(new_checksum)
                        }
                    )
                    return True
                else:
                    # Revert to original checksum
                    pe.OPTIONAL_HEADER.CheckSum = original_checksum
                    self.logger.warning(
                        "Reverted to original checksum",
                        details={
                            "original": hex(original_checksum),
                            "failed": hex(new_checksum)
                        }
                    )
                    raise ChecksumError(
                        message="Checksum verification failed",
                        details={"verification_status": "failed"},
                        pe_metadata=PEMetadata(
                            file_path=getattr(pe, 'path', None),
                            file_size=len(pe.__data__) if hasattr(pe, '__data__') else None,
                            machine_type=hex(pe.FILE_HEADER.Machine),
                            characteristics=pe.FILE_HEADER.Characteristics,
                            timestamp=pe.FILE_HEADER.TimeDateStamp
                        ),
                        checksum_context=ChecksumContext(
                            original=original_checksum,
                            calculated=new_checksum,
                            current=pe.OPTIONAL_HEADER.CheckSum,
                            delta=new_checksum - original_checksum,
                            attempt_count=retry_attempts
                        ),
                        remediation=(
                            "Try with force_update=True or skip_verify=True "
                            "if file has extensive modifications"
                        )
                    )
            
            return True
            
        except ChecksumError:
            raise
            
        except Exception as e:
            raise ChecksumError(
                message="Error updating checksum",
                details={"error_type": type(e).__name__},
                pe_metadata=PEMetadata(
                    file_path=getattr(pe, 'path', None),
                    file_size=len(pe.__data__) if hasattr(pe, '__data__') else None,
                    machine_type=hex(pe.FILE_HEADER.Machine),
                    characteristics=pe.FILE_HEADER.Characteristics,
                    timestamp=pe.FILE_HEADER.TimeDateStamp
                ),
                checksum_context=ChecksumContext(
                    current=pe.OPTIONAL_HEADER.CheckSum
                ),
                cause=e,
                remediation="Verify PE file structure is intact"
            )
    
    def verify_checksum(
        self,
        pe: pefile.PE,
        retry_attempts: int = 3
    ) -> bool:
        """
        Verify PE file checksum without updating.
        
        Args:
            pe: PE file object to verify
            retry_attempts: Number of verification attempts
            
        Returns:
            bool: True if checksum is valid
            
        Note:
            This method only verifies the existing checksum.
            It does not modify the PE file.
        """
        try:
            current_checksum = pe.OPTIONAL_HEADER.CheckSum
            calculated_checksum = pe.generate_checksum()
            
            checksum_context = ChecksumContext(
                current=current_checksum,
                calculated=calculated_checksum,
                delta=calculated_checksum - current_checksum
            )
            
            pe_metadata = PEMetadata(
                file_path=getattr(pe, 'path', None),
                file_size=len(pe.__data__) if hasattr(pe, '__data__') else None,
                machine_type=hex(pe.FILE_HEADER.Machine),
                characteristics=pe.FILE_HEADER.Characteristics,
                timestamp=pe.FILE_HEADER.TimeDateStamp
            )
            
            self.logger.debug(
                "Verifying checksum",
                details={
                    "pe_metadata": pe_metadata.__dict__,
                    "checksum_context": checksum_context.__dict__
                }
            )
            
            for attempt in range(retry_attempts):
                try:
                    if pe.verify_checksum():
                        self._log_success(
                            "Checksum verification successful",
                            details={
                                "pe_metadata": pe_metadata.__dict__,
                                "checksum_context": {
                                    **checksum_context.__dict__,
                                    "attempt_count": attempt + 1
                                }
                            }
                        )
                        return True
                    else:
                        self.logger.warning(
                            f"Verification attempt {attempt + 1} failed",
                            details={
                                "pe_metadata": pe_metadata.__dict__,
                                "checksum_context": {
                                    **checksum_context.__dict__,
                                    "attempt_count": attempt + 1
                                }
                            }
                        )
                except Exception as e:
                    self.logger.warning(
                        "Verification error",
                        details={
                            "error": str(e),
                            "pe_metadata": pe_metadata.__dict__,
                            "checksum_context": {
                                **checksum_context.__dict__,
                                "attempt_count": attempt + 1
                            }
                        }
                    )
            
            return False
            
        except Exception as e:
            self.logger.error(
                "Error during checksum verification",
                error=e,
                details={
                    "pe_metadata": pe_metadata.__dict__ if 'pe_metadata' in locals() else None,
                    "checksum_context": checksum_context.__dict__ if 'checksum_context' in locals() else None
                }
            )
            return False
    
    def calculate_checksum(self, pe: pefile.PE) -> Optional[int]:
        """
        Calculate PE file checksum without applying it.
        
        Args:
            pe: PE file object to calculate checksum for
            
        Returns:
            Optional[int]: Calculated checksum or None if calculation fails
            
        Note:
            This method does not modify the PE file.
            It only calculates what the checksum should be.
        """
        try:
            current_checksum = pe.OPTIONAL_HEADER.CheckSum
            calculated = pe.generate_checksum()
            
            self.logger.debug(
                "Checksum calculation",
                details={
                    "current": hex(current_checksum),
                    "calculated": hex(calculated),
                    "delta": hex(calculated - current_checksum)
                }
            )
            
            return calculated
            
        except Exception as e:
            self.logger.error(
                "Error calculating checksum",
                error=e
            )
            return None 