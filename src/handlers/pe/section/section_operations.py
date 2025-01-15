"""
Section manipulation operations.

This module provides functionality for:
- Section creation and modification
- Section splitting and merging
- Space validation and alignment
- Section table updates
"""

import math
import pefile
from typing import List, Optional, Dict, Any, Set
from loguru import logger

from .errors import SectionError, ValidationError, AlignmentError
from .constants import (
    SECTION_CHARACTERISTICS,
    CRITICAL_SECTIONS,
    DEFAULT_MAX_ATTEMPTS
)
from .helpers import (
    validate_section_name,
    get_existing_section_names,
    generate_random_name,
    validate_space,
    get_characteristic_names
)

class SectionOperator:
    """
    Handles PE section manipulation operations.
    
    Features:
    - Section creation and modification
    - Section splitting and merging
    - Space validation and alignment
    - Section table updates
    """
    
    def find_suitable_section(
        self,
        pe: pefile.PE,
        required_space: int,
        characteristics: List[str],
        exclude_names: Optional[List[str]] = None
    ) -> Optional[pefile.SectionStructure]:
        """
        Find a suitable section for code/data injection.
        
        Args:
            pe: PE file object
            required_space: Space needed in bytes
            characteristics: Required section characteristics
            exclude_names: Section names to exclude
            
        Returns:
            Optional[pefile.SectionStructure]: Suitable section or None
            
        Note:
            Selection criteria:
            1. Has required characteristics
            2. Has sufficient space
            3. Not in excluded or critical sections
            4. Properly aligned
        """
        try:
            exclude_names = set(exclude_names or []) | CRITICAL_SECTIONS
            required_chars = sum(
                SECTION_CHARACTERISTICS[char]
                for char in characteristics
                if char in SECTION_CHARACTERISTICS
            )
            
            logger.debug(
                "Finding suitable section",
                details={
                    "required_space": required_space,
                    "characteristics": characteristics,
                    "excluded": list(exclude_names)
                }
            )
            
            for section in pe.sections:
                section_name = section.Name.decode().strip('\x00')
                
                # Skip excluded sections
                if section_name in exclude_names:
                    logger.debug(f"Skipping excluded section: {section_name}")
                    continue
                
                # Check characteristics
                if (section.Characteristics & required_chars) != required_chars:
                    logger.debug(
                        f"Section {section_name} lacks required characteristics",
                        details={
                            "required": hex(required_chars),
                            "actual": hex(section.Characteristics)
                        }
                    )
                    continue
                
                # Validate space requirements
                is_valid, validation_details = validate_space(
                    pe, section, required_space, consider_alignment=True
                )
                
                if not is_valid:
                    logger.debug(
                        f"Section {section_name} failed space validation",
                        details=validation_details
                    )
                    continue
                
                logger.info(
                    f"Found suitable section: {section_name}",
                    details={
                        "characteristics": hex(section.Characteristics),
                        "raw_size": section.SizeOfRawData,
                        "virtual_size": section.Misc_VirtualSize
                    }
                )
                return section
            
            logger.info(
                "No suitable section found",
                details={
                    "required_space": required_space,
                    "required_chars": hex(required_chars)
                }
            )
            return None
            
        except Exception as e:
            logger.error(
                "Error finding suitable section",
                error=e
            )
            return None
    
    def add_new_section(
        self,
        pe: pefile.PE,
        name: str,
        virtual_size: int,
        raw_size: int,
        characteristics: List[str]
    ) -> Optional[pefile.SectionStructure]:
        """
        Add a new section to the PE file.
        
        Args:
            pe: PE file object
            name: Section name (max 8 chars)
            virtual_size: Size in memory
            raw_size: Size in file
            characteristics: Section characteristics
            
        Returns:
            Optional[pefile.SectionStructure]: New section or None
            
        Raises:
            SectionError: If section creation fails
            
        Note:
            Alignment requirements:
            - Virtual addresses align to SectionAlignment
            - Raw data aligns to FileAlignment
            - Section name must be 8 chars or less
        """
        try:
            # Validate section name
            validate_section_name(name)
            
            # Calculate characteristics
            section_chars = sum(
                SECTION_CHARACTERISTICS[char]
                for char in characteristics
                if char in SECTION_CHARACTERISTICS
            )
            
            logger.debug(
                "Creating new section",
                details={
                    "name": name,
                    "virtual_size": virtual_size,
                    "raw_size": raw_size,
                    "characteristics": hex(section_chars)
                }
            )
            
            # Get last section
            last_section = pe.sections[-1]
            
            # Calculate aligned addresses
            new_section_offset = (
                (last_section.VirtualAddress + last_section.Misc_VirtualSize + 
                pe.OPTIONAL_HEADER.SectionAlignment - 1)
                & ~(pe.OPTIONAL_HEADER.SectionAlignment - 1)
            )
            
            raw_offset = (
                (last_section.PointerToRawData + last_section.SizeOfRawData + 
                pe.OPTIONAL_HEADER.FileAlignment - 1)
                & ~(pe.OPTIONAL_HEADER.FileAlignment - 1)
            )
            
            # Create new section
            new_section = pefile.SectionStructure(pe.__IMAGE_SECTION_HEADER_format__)
            new_section.set_file_offset(pe.sections[-1].get_file_offset() + 40)
            
            # Set section properties
            new_section.Name = name.encode().ljust(8, b'\x00')
            new_section.Misc_VirtualSize = virtual_size
            new_section.VirtualAddress = new_section_offset
            new_section.SizeOfRawData = raw_size
            new_section.PointerToRawData = raw_offset
            new_section.PointerToRelocations = 0
            new_section.PointerToLinenumbers = 0
            new_section.NumberOfRelocations = 0
            new_section.NumberOfLinenumbers = 0
            new_section.Characteristics = section_chars
            
            # Update PE header
            pe.FILE_HEADER.NumberOfSections += 1
            pe.OPTIONAL_HEADER.SizeOfImage = (
                new_section_offset + virtual_size + 
                pe.OPTIONAL_HEADER.SectionAlignment - 1
            ) & ~(pe.OPTIONAL_HEADER.SectionAlignment - 1)
            
            # Add section to PE
            pe.sections.append(new_section)
            
            logger.info(
                f"Created new section: {name}",
                details={
                    "virtual_address": hex(new_section_offset),
                    "raw_offset": hex(raw_offset),
                    "characteristics": hex(section_chars)
                }
            )
            
            return new_section
            
        except ValidationError:
            raise
            
        except Exception as e:
            raise SectionError(
                message="Error creating new section",
                details={"name": name},
                cause=e,
                remediation="Verify PE file structure and permissions"
            )
    
    def update_section(
        self,
        pe: pefile.PE,
        section: pefile.SectionStructure,
        characteristics: Optional[List[str]] = None,
        virtual_size: Optional[int] = None,
        raw_size: Optional[int] = None
    ) -> bool:
        """
        Update section properties.
        
        Args:
            pe: PE file object
            section: Section to update
            characteristics: New characteristics (optional)
            virtual_size: New virtual size (optional)
            raw_size: New raw size (optional)
            
        Returns:
            bool: True if successful
            
        Raises:
            SectionError: If update fails
        """
        try:
            section_name = section.Name.decode().strip('\x00')
            logger.debug(
                f"Updating section: {section_name}",
                details={
                    "characteristics": characteristics,
                    "virtual_size": virtual_size,
                    "raw_size": raw_size
                }
            )
            
            # Update characteristics if provided
            if characteristics:
                new_chars = sum(
                    SECTION_CHARACTERISTICS[char]
                    for char in characteristics
                    if char in SECTION_CHARACTERISTICS
                )
                section.Characteristics = new_chars
            
            # Update sizes if provided
            if virtual_size is not None:
                aligned_vsize = (
                    (virtual_size + pe.OPTIONAL_HEADER.SectionAlignment - 1)
                    & ~(pe.OPTIONAL_HEADER.SectionAlignment - 1)
                )
                section.Misc_VirtualSize = aligned_vsize
            
            if raw_size is not None:
                aligned_rsize = (
                    (raw_size + pe.OPTIONAL_HEADER.FileAlignment - 1)
                    & ~(pe.OPTIONAL_HEADER.FileAlignment - 1)
                )
                section.SizeOfRawData = aligned_rsize
            
            logger.info(
                f"Updated section: {section_name}",
                details={
                    "characteristics": hex(section.Characteristics),
                    "virtual_size": hex(section.Misc_VirtualSize),
                    "raw_size": hex(section.SizeOfRawData)
                }
            )
            
            return True
            
        except Exception as e:
            raise SectionError(
                message="Error updating section",
                details={"section": section_name},
                cause=e,
                remediation="Verify section properties and alignment"
            )
    
    def split_section(
        self,
        pe: pefile.PE,
        section: pefile.SectionStructure,
        split_size: int
    ) -> List[pefile.SectionStructure]:
        """
        Split a section's content into multiple sections.
        
        Args:
            pe: PE file object
            section: Section to split
            split_size: Maximum size for each split section
            
        Returns:
            List[pefile.SectionStructure]: List of resulting sections
            
        Raises:
            SectionError: If section splitting fails
            
        Note:
            - Creates new sections for split content
            - Maintains section characteristics
            - Ensures proper alignment
            - Original section becomes first part
        """
        try:
            original_name = section.Name.decode().strip('\x00')
            
            # Verify section is not critical
            if original_name in CRITICAL_SECTIONS:
                raise SectionError(
                    message="Cannot split critical section",
                    details={"section": original_name},
                    remediation="Choose a non-critical section"
                )
            
            # Get section data
            data = section.get_data()
            total_size = len(data)
            
            # Calculate number of needed sections
            num_sections = math.ceil(total_size / split_size)
            
            if num_sections <= 1:
                logger.info(
                    "Section size smaller than split size",
                    details={
                        "section": original_name,
                        "size": total_size,
                        "split_size": split_size
                    }
                )
                return [section]
            
            logger.debug(
                "Splitting section",
                details={
                    "original_name": original_name,
                    "total_size": total_size,
                    "split_size": split_size,
                    "num_sections": num_sections
                }
            )
            
            # List to track all sections (including original)
            result_sections = []
            
            # Update original section with first chunk
            first_chunk = data[:split_size]
            section.set_data(first_chunk)
            
            # Update size and characteristics
            self.update_section(
                pe,
                section,
                virtual_size=len(first_chunk),
                raw_size=len(first_chunk)
            )
            
            result_sections.append(section)
            
            # Create new sections for remaining chunks
            existing_names = get_existing_section_names(pe)
            
            for i in range(1, num_sections):
                chunk_start = i * split_size
                chunk_end = min(chunk_start + split_size, total_size)
                chunk = data[chunk_start:chunk_end]
                
                # Generate unique name for new section
                new_name = generate_random_name(existing_names)
                existing_names.add(new_name)
                
                # Create new section with same characteristics
                new_section = self.add_new_section(
                    pe,
                    name=new_name,
                    virtual_size=len(chunk),
                    raw_size=len(chunk),
                    characteristics=[
                        name
                        for name, value in SECTION_CHARACTERISTICS.items()
                        if section.Characteristics & value
                    ]
                )
                
                if not new_section:
                    raise SectionError(
                        message="Failed to create new section for split",
                        details={
                            "original": original_name,
                            "chunk": i,
                            "size": len(chunk)
                        }
                    )
                
                # Set chunk data
                new_section.set_data(chunk)
                result_sections.append(new_section)
                
                logger.debug(
                    f"Created split section {i + 1}/{num_sections}",
                    details={
                        "name": new_name,
                        "size": len(chunk),
                        "offset": hex(new_section.get_file_offset())
                    }
                )
            
            logger.info(
                "Successfully split section",
                details={
                    "original_name": original_name,
                    "total_size": total_size,
                    "num_sections": num_sections,
                    "sections": [
                        {
                            "name": s.Name.decode().strip('\x00'),
                            "size": len(s.get_data())
                        }
                        for s in result_sections
                    ]
                }
            )
            
            return result_sections
            
        except Exception as e:
            raise SectionError(
                message="Error splitting section",
                details={
                    "section": original_name if 'original_name' in locals() else None,
                    "split_size": split_size
                },
                cause=e,
                remediation="Verify section exists and split size is appropriate"
            )
    
    def merge_sections(
        self,
        pe: pefile.PE,
        sections: List[pefile.SectionStructure],
        merged_name: Optional[str] = None
    ) -> Optional[pefile.SectionStructure]:
        """
        Merge multiple sections into a single section.
        
        Args:
            pe: PE file object
            sections: List of sections to merge
            merged_name: Optional name for merged section (random if not provided)
            
        Returns:
            Optional[pefile.SectionStructure]: Merged section if successful
            
        Raises:
            SectionError: If merging fails
            
        Note:
            - Combines section contents sequentially
            - Preserves alignment requirements
            - Updates PE header and section table
            - Removes original sections after merging
        """
        try:
            if not sections:
                raise SectionError(
                    message="No sections provided for merging",
                    remediation="Provide at least one section to merge"
                )
            
            # Check for critical sections
            section_names = [s.Name.decode().strip('\x00') for s in sections]
            critical_sections = [name for name in section_names if name in CRITICAL_SECTIONS]
            
            if critical_sections:
                raise SectionError(
                    message="Cannot merge critical sections",
                    details={"critical_sections": critical_sections},
                    remediation="Remove critical sections from merge list"
                )
            
            logger.debug(
                "Preparing to merge sections",
                details={
                    "sections": section_names,
                    "count": len(sections)
                }
            )
            
            # Calculate total size and collect characteristics
            total_raw_size = sum(len(s.get_data()) for s in sections)
            total_virtual_size = sum(s.Misc_VirtualSize for s in sections)
            
            # Combine characteristics (union of all section characteristics)
            merged_chars = 0
            for section in sections:
                merged_chars |= section.Characteristics
            
            # Generate or validate merged section name
            if merged_name:
                validate_section_name(merged_name)
            else:
                existing_names = get_existing_section_names(pe)
                merged_name = generate_random_name(existing_names)
            
            # Create new section for merged content
            merged_section = self.add_new_section(
                pe,
                name=merged_name,
                virtual_size=total_virtual_size,
                raw_size=total_raw_size,
                characteristics=[
                    name
                    for name, value in SECTION_CHARACTERISTICS.items()
                    if merged_chars & value
                ]
            )
            
            if not merged_section:
                raise SectionError(
                    message="Failed to create merged section",
                    details={"name": merged_name, "size": total_raw_size}
                )
            
            # Combine section contents
            merged_data = bytearray()
            for section in sections:
                merged_data.extend(section.get_data())
            
            # Set merged section data
            merged_section.set_data(bytes(merged_data))
            
            # Store original section info for logging
            original_sections_info = [
                {
                    "name": s.Name.decode().strip('\x00'),
                    "virtual_address": hex(s.VirtualAddress),
                    "raw_size": len(s.get_data()),
                    "characteristics": hex(s.Characteristics)
                }
                for s in sections
            ]
            
            # Remove original sections (in reverse order to maintain indices)
            for section in reversed(sections):
                section_index = pe.sections.index(section)
                pe.sections.pop(section_index)
                pe.FILE_HEADER.NumberOfSections -= 1
            
            # Update SizeOfImage in PE header
            last_section = pe.sections[-1]
            pe.OPTIONAL_HEADER.SizeOfImage = (
                last_section.VirtualAddress +
                last_section.Misc_VirtualSize +
                pe.OPTIONAL_HEADER.SectionAlignment - 1
            ) & ~(pe.OPTIONAL_HEADER.SectionAlignment - 1)
            
            logger.info(
                "Successfully merged sections",
                details={
                    "original_sections": original_sections_info,
                    "merged_section": {
                        "name": merged_name,
                        "virtual_address": hex(merged_section.VirtualAddress),
                        "raw_size": len(merged_data),
                        "characteristics": hex(merged_section.Characteristics)
                    },
                    "size_info": {
                        "total_raw_size": total_raw_size,
                        "total_virtual_size": total_virtual_size,
                        "final_raw_size": len(merged_section.get_data()),
                        "final_image_size": hex(pe.OPTIONAL_HEADER.SizeOfImage)
                    }
                }
            )
            
            return merged_section
            
        except Exception as e:
            raise SectionError(
                message="Error merging sections",
                details={
                    "sections": section_names if 'section_names' in locals() else None
                },
                cause=e,
                remediation="Verify sections exist and can be merged"
            )
    
    def rename_section(self, pe: pefile.PE, section: pefile.SectionStructure, 
                      new_name: str) -> bool:
        """
        Rename a PE section.
        
        Args:
            pe: PE file object
            section: Section to rename
            new_name: New name for the section
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Validate new name
            if not validate_section_name(new_name):
                logger.error(f"Invalid section name: {new_name}")
                return False
                
            # Pad name to 8 bytes as required by PE format
            padded_name = new_name.ljust(8, '\x00').encode()
            
            # Update section name
            section.Name = padded_name
            
            # Force PE to recompute section information
            pe.full_load()
            
            logger.success(f"Successfully renamed section to: {new_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rename section: {str(e)}")
            return False 