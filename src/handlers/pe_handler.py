"""
PE Handler Module
===============

⚠️ EDUCATIONAL PURPOSE DISCLAIMER ⚠️
--------------------------------
This module is part of a project designed STRICTLY for:
- Studying binary manipulation techniques in the OSEP (PEN-300) course
- Practicing in authorized lab environments only
- Educational research in controlled settings

Features
--------
* **PE File Operations**
  - Load and validate PE files
  - Manage sections and imports
  - Handle checksums and verification
  - Coordinate between specialized handlers

* **Specialized Handlers**
  - ValidationHandler: PE structure validation
  - SectionHandler: Section manipulation
  - ChecksumHandler: PE checksum operations
  - ImportHandler: Import table modifications

* **Error Handling**
  - Comprehensive error propagation
  - Detailed error messages
  - Suggested remediation steps
  - Debug logging support

Dependencies
-----------
Core Libraries:
* `pefile` >= 2023.2.7
  - PE file parsing and manipulation
  - Section and import table handling
  - Checksum calculation

* `loguru` >= 0.7.2
  - Structured logging
  - Error tracking
  - Debug information

Standard Libraries:
* `os`: File system operations
* `typing`: Type hints and annotations

Project Components
----------------
* **Handler Classes**
  - `PEHandler`: Main coordinator
  - `ValidationHandler`: PE validation
  - `SectionHandler`: Section operations
  - `ChecksumHandler`: Checksum management
  - `ImportHandler`: Import modifications

* **Error Types**
  - `PEHandlerError`: High-level operations
  - `ValidationError`: PE validation
  - `SectionError`: Section operations
  - `ChecksumError`: Checksum operations
  - `ImportError`: Import modifications

Usage Examples
------------
```python
# Basic PE file handling
handler = PEHandler()
try:
    # Load and validate PE file
    if pe := handler.load_pe("target.exe"):
        # Add new section
        section = handler.add_section(
            name=".newdata",
            data=b"Hello World",
            characteristics=["IMAGE_SCN_MEM_READ"]
        )
        
        # Update checksum and save
        handler.update_checksum()
        handler.save_pe("output/modified.exe")
finally:
    handler.close()

# Error handling example
try:
    handler = PEHandler()
    pe = handler.load_pe("target.exe")
    
    # Find suitable section
    if section := handler.find_section(
        required_space=1024,
        characteristics=["IMAGE_SCN_MEM_EXECUTE"],
        exclude_names=[".rsrc", ".reloc"]
    ):
        # Perform operations
        pass
        
except PEHandlerError as e:
    logger.error(f"Operation failed: {e.message}")
    if e.remediation:
        logger.info(f"Suggested fix: {e.remediation}")
```

Best Practices
------------
1. Always use in controlled lab environments
2. Handle resources properly with try/finally
3. Check return values for None/False
4. Implement proper error handling
5. Close PE objects when done

Note
----
This module coordinates operations between specialized handlers:
- Validates and loads PE files
- Manages sections and imports
- Handles checksums and verification
- Provides consistent error handling

Author: Anonymous
Version: 1.0.0
License: MIT
"""

import os
from typing import Optional, Dict, Any, List, Tuple, TypedDict
import pefile
from loguru import logger

from .base_handler import BaseHandler, HandlerError
from .pe.validation_handler import ValidationHandler, ValidationError
from .pe.checksum_handler import ChecksumHandler, ChecksumError
from .pe.section_handler import SectionHandler, SectionError
from .pe.import_handler import ImportHandler, ImportError

class PEHandlerError(HandlerError):
    """Exception for high-level PE operations."""
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        cause: Optional[Exception] = None,
        remediation: Optional[str] = None
    ):
        super().__init__(message, details, cause, remediation)

class SectionMetadata(TypedDict):
    """Metadata for PE section operations."""
    name: str
    raw_size: int
    virtual_size: int
    rva: int
    physical_offset: int
    characteristics: List[str]
    is_executable: bool
    is_writable: bool
    is_readable: bool

class PEHandler(BaseHandler):
    """
    Coordinates high-level PE file operations.
    
    This class orchestrates the interactions between specialized handlers:
    - ValidationHandler: PE file validation
    - ChecksumHandler: Checksum operations
    - SectionHandler: Section manipulation
    - ImportHandler: Import table modifications
    """
    
    def __init__(self):
        """Initialize specialized handlers."""
        super().__init__()
        self.validation_handler = ValidationHandler()
        self.checksum_handler = ChecksumHandler()
        self.section_handler = SectionHandler()
        self.import_handler = ImportHandler()
        self._pe = None  # Current PE object
    
    def load_pe(self, filepath: str) -> Optional[pefile.PE]:
        """
        Load and validate PE file.
        
        Args:
            filepath: Path to PE file
            
        Returns:
            Optional[pefile.PE]: Loaded PE object if valid
            
        Raises:
            PEHandlerError: If loading or validation fails
            
        Note:
            If a PE file is already loaded, it will be closed automatically
            before loading the new file.
        """
        try:
            # Close any previously loaded PE file
            if self._pe:
                self.logger.debug(
                    "Closing previously loaded PE file before loading new one",
                    details={"new_file": filepath}
                )
                self.close()
            
            # Validate and load PE file using ValidationHandler
            self._pe = self.validation_handler.validate_pe(filepath)
            if not self._pe:
                raise PEHandlerError(
                    message="Failed to load PE file",
                    details={"path": filepath},
                    remediation="Verify file is a valid PE"
                )
            
            return self._pe
            
        except ValidationError as e:
            raise PEHandlerError(
                message="PE validation failed",
                details=e.details,
                cause=e,
                remediation=e.remediation
            )
            
        except Exception as e:
            raise PEHandlerError(
                message="Unexpected error loading PE",
                details={"path": filepath},
                cause=e
            )
    
    def add_section(
        self,
        name: str,
        data: bytes,
        characteristics: List[str]
    ) -> Optional[Tuple[pefile.SectionStructure, SectionMetadata]]:
        """
        Add new section to PE file.
        
        Args:
            name: Section name
            data: Section data
            characteristics: Section characteristics
            
        Returns:
            Optional[Tuple[pefile.SectionStructure, SectionMetadata]]: 
                Tuple containing:
                - SectionStructure: New section if successful
                - SectionMetadata: Additional section information including:
                  * name: Section name
                  * raw_size: Size of section in file
                  * virtual_size: Size of section in memory
                  * rva: Relative Virtual Address
                  * physical_offset: File offset
                  * characteristics: List of section flags
                  * is_executable: Whether section is executable
                  * is_writable: Whether section is writable
                  * is_readable: Whether section is readable
            
        Raises:
            PEHandlerError: If section creation fails
        """
        if not self._pe:
            raise PEHandlerError(
                message="No PE file loaded",
                remediation="Call load_pe first"
            )
        
        try:
            # Create new section using SectionHandler
            section = self.section_handler.add_new_section(
                self._pe,
                name,
                len(data),  # virtual_size
                len(data),  # raw_size
                characteristics
            )
            
            if not section:
                raise PEHandlerError(
                    message="Failed to create section",
                    details={"name": name},
                    remediation="Verify section parameters"
                )
            
            # Write data to section
            self._pe.set_bytes_at_offset(
                section.PointerToRawData,
                data
            )
            
            # Create metadata
            metadata = SectionMetadata(
                name=section.Name.decode().rstrip('\x00'),
                raw_size=section.SizeOfRawData,
                virtual_size=section.Misc_VirtualSize,
                rva=section.VirtualAddress,
                physical_offset=section.PointerToRawData,
                characteristics=[
                    flag for flag in [
                        "IMAGE_SCN_MEM_EXECUTE",
                        "IMAGE_SCN_MEM_WRITE",
                        "IMAGE_SCN_MEM_READ",
                        "IMAGE_SCN_CNT_CODE",
                        "IMAGE_SCN_CNT_INITIALIZED_DATA",
                        "IMAGE_SCN_CNT_UNINITIALIZED_DATA"
                    ] if section.Characteristics & getattr(pefile, flag)
                ],
                is_executable=bool(section.Characteristics & pefile.IMAGE_SCN_MEM_EXECUTE),
                is_writable=bool(section.Characteristics & pefile.IMAGE_SCN_MEM_WRITE),
                is_readable=bool(section.Characteristics & pefile.IMAGE_SCN_MEM_READ)
            )
            
            self._log_success(
                "Section created successfully",
                details={
                    "name": metadata["name"],
                    "rva": hex(metadata["rva"]),
                    "size": metadata["raw_size"],
                    "characteristics": metadata["characteristics"]
                }
            )
            
            return section, metadata
            
        except SectionError as e:
            raise PEHandlerError(
                message="Section creation failed",
                details=e.details,
                cause=e,
                remediation=e.remediation
            )
    
    def find_section(
        self,
        required_space: int,
        characteristics: List[str],
        exclude_names: Optional[List[str]] = None
    ) -> Optional[Tuple[pefile.SectionStructure, SectionMetadata]]:
        """
        Find suitable section for injection.
        
        Args:
            required_space: Space needed in bytes
            characteristics: Required characteristics
            exclude_names: Section names to exclude
            
        Returns:
            Optional[Tuple[pefile.SectionStructure, SectionMetadata]]:
                Tuple containing:
                - SectionStructure: Suitable section if found
                - SectionMetadata: Additional section information including:
                  * name: Section name
                  * raw_size: Size of section in file
                  * virtual_size: Size of section in memory
                  * rva: Relative Virtual Address
                  * physical_offset: File offset
                  * characteristics: List of section flags
                  * is_executable: Whether section is executable
                  * is_writable: Whether section is writable
                  * is_readable: Whether section is readable
            
        Raises:
            PEHandlerError: If PE file not loaded
        """
        if not self._pe:
            raise PEHandlerError(
                message="No PE file loaded",
                remediation="Call load_pe first"
            )
        
        section = self.section_handler.find_suitable_section(
            self._pe,
            required_space,
            characteristics,
            exclude_names
        )
        
        if not section:
            return None
            
        # Create metadata
        metadata = SectionMetadata(
            name=section.Name.decode().rstrip('\x00'),
            raw_size=section.SizeOfRawData,
            virtual_size=section.Misc_VirtualSize,
            rva=section.VirtualAddress,
            physical_offset=section.PointerToRawData,
            characteristics=[
                flag for flag in [
                    "IMAGE_SCN_MEM_EXECUTE",
                    "IMAGE_SCN_MEM_WRITE",
                    "IMAGE_SCN_MEM_READ",
                    "IMAGE_SCN_CNT_CODE",
                    "IMAGE_SCN_CNT_INITIALIZED_DATA",
                    "IMAGE_SCN_CNT_UNINITIALIZED_DATA"
                ] if section.Characteristics & getattr(pefile, flag)
            ],
            is_executable=bool(section.Characteristics & pefile.IMAGE_SCN_MEM_EXECUTE),
            is_writable=bool(section.Characteristics & pefile.IMAGE_SCN_MEM_WRITE),
            is_readable=bool(section.Characteristics & pefile.IMAGE_SCN_MEM_READ)
        )
        
        self.logger.debug(
            "Found suitable section",
            details={
                "name": metadata["name"],
                "rva": hex(metadata["rva"]),
                "available_space": metadata["raw_size"],
                "characteristics": metadata["characteristics"]
            }
        )
        
        return section, metadata
    
    def update_checksum(
        self,
        force_update: bool = False,
        skip_verify: bool = False
    ) -> bool:
        """
        Update PE file checksum.
        
        Args:
            force_update: Keep new checksum even if verification fails
            skip_verify: Skip checksum verification
            
        Returns:
            bool: True if successful
            
        Raises:
            PEHandlerError: If checksum update fails
        """
        if not self._pe:
            raise PEHandlerError(
                message="No PE file loaded",
                remediation="Call load_pe first"
            )
        
        try:
            return self.checksum_handler.update_checksum(
                self._pe,
                force_update,
                skip_verify
            )
        except ChecksumError as e:
            raise PEHandlerError(
                message="Checksum update failed",
                details=e.details,
                cause=e,
                remediation=e.remediation
            )
    
    def save_pe(self, output_path: str) -> bool:
        """
        Save modified PE file.
        
        Args:
            output_path: Path to save file
            
        Returns:
            bool: True if successful
            
        Raises:
            PEHandlerError: If save fails
        """
        if not self._pe:
            raise PEHandlerError(
                message="No PE file loaded",
                remediation="Call load_pe first"
            )
        
        try:
            # Create output directory if needed
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            
            # Save PE file
            self._pe.write(filename=output_path)
            
            self._log_success(
                "PE file saved successfully",
                details={"path": output_path}
            )
            return True
            
        except Exception as e:
            raise PEHandlerError(
                message="Failed to save PE file",
                details={"path": output_path},
                cause=e,
                remediation="Check write permissions and disk space"
            )
    
    def close(self):
        """Close PE file and cleanup."""
        if self._pe:
            self._pe.close()
            self._pe = None 