"""
Main section handler for PE file operations.

This module orchestrates all section-related operations including:
- Section creation and modification
- Content transformation
- Section splitting and merging
- Characteristic management
"""

import pefile
from typing import List, Optional, Dict, Any
from loguru import logger

from .errors import SectionError
from .section_transform import SectionTransformer, CharacteristicsSnapshot
from .section_operations import SectionOperator
from .helpers import validate_section_name
from ...base_handler import BaseHandler
from .name_generator import NameGenerator

class SectionHandler(BaseHandler):
    """
    Main handler for PE section operations.
    
    This class orchestrates operations between specialized handlers:
    - SectionOperator: Core section operations
    - SectionTransformer: Section content transformations
    
    Example:
        ```python
        handler = SectionHandler()
        
        # Find and transform a section
        if section := handler.find_suitable_section(pe, size, chars):
            handler.transform_section_content(pe, section, "encrypt")
            
        # Split a large section
        sections = handler.split_section(pe, section, 4096)
        
        # Merge sections
        merged = handler.merge_sections(pe, sections)
        ```
    """
    
    def __init__(self):
        """Initialize specialized handlers."""
        super().__init__()
        self.operator = SectionOperator()
        self.transformer = SectionTransformer()
        self.name_generator = NameGenerator()
    
    def find_suitable_section(
        self,
        pe: pefile.PE,
        required_space: int,
        characteristics: List[str],
        exclude_names: Optional[List[str]] = None
    ) -> Optional[pefile.SectionStructure]:
        """Find suitable section for injection."""
        return self.operator.find_suitable_section(
            pe, required_space, characteristics, exclude_names
        )
    
    def add_new_section(
        self,
        pe: pefile.PE,
        name: str,
        virtual_size: int,
        raw_size: int,
        characteristics: List[str]
    ) -> Optional[pefile.SectionStructure]:
        """Add new section to PE file."""
        return self.operator.add_new_section(
            pe, name, virtual_size, raw_size, characteristics
        )
    
    def split_section(
        self,
        pe: pefile.PE,
        section: pefile.SectionStructure,
        split_size: int
    ) -> List[pefile.SectionStructure]:
        """Split section into multiple sections."""
        return self.operator.split_section(pe, section, split_size)
    
    def merge_sections(
        self,
        pe: pefile.PE,
        sections: List[pefile.SectionStructure],
        merged_name: Optional[str] = None
    ) -> Optional[pefile.SectionStructure]:
        """Merge multiple sections into one."""
        return self.operator.merge_sections(pe, sections, merged_name)
    
    def update_section(
        self,
        pe: pefile.PE,
        section: pefile.SectionStructure,
        characteristics: Optional[List[str]] = None,
        virtual_size: Optional[int] = None,
        raw_size: Optional[int] = None
    ) -> bool:
        """Update section properties."""
        return self.operator.update_section(
            pe, section, characteristics, virtual_size, raw_size
        )
    
    def transform_section_content(
        self,
        pe: pefile.PE,
        section: pefile.SectionStructure,
        transform_type: str,
        encryption_key: Optional[bytes] = None
    ) -> bool:
        """Transform section content."""
        return self.transformer.transform_section_content(
            pe, section, transform_type, encryption_key
        )
    
    def apply_polymorphic_characteristics(
        self,
        pe: pefile.PE,
        section: pefile.SectionStructure,
        mutation_rate: float = 0.5,
        save_snapshot: bool = True
    ) -> Optional[CharacteristicsSnapshot]:
        """Apply polymorphic changes to section characteristics."""
        return self.transformer.apply_polymorphic_characteristics(
            pe, section, mutation_rate, save_snapshot
        )
    
    def revert_characteristics(
        self,
        pe: pefile.PE,
        section: pefile.SectionStructure,
        snapshot: CharacteristicsSnapshot
    ) -> bool:
        """Revert section characteristics to snapshot state."""
        return self.transformer.revert_characteristics(pe, section, snapshot)
    
    def get_section_by_name(
        self,
        pe: pefile.PE,
        name: str
    ) -> Optional[pefile.SectionStructure]:
        """
        Get section by name.
        
        Args:
            pe: PE file object
            name: Section name to find
            
        Returns:
            Optional[pefile.SectionStructure]: Found section or None
        """
        try:
            validate_section_name(name)
            
            for section in pe.sections:
                if section.Name.decode().strip('\x00') == name:
                    return section
                    
            self.logger.debug(f"Section not found: {name}")
            return None
            
        except Exception as e:
            self.logger.error(
                f"Error finding section: {name}",
                error=e
            )
            return None 
    
    def randomize_section_name(self, pe: pefile.PE, section: pefile.SectionStructure,
                             strategy: str = "random") -> bool:
        """
        Randomize the name of a PE section.
        
        Args:
            pe: PE file object
            section: Section to rename
            strategy: Naming strategy ("random", "mimic", or "mutate")
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Generate new name based on strategy
            if strategy == "mimic":
                new_name = self.name_generator.mimic_common_name()
            elif strategy == "mutate":
                current_name = section.Name.decode().rstrip('\x00')
                new_name = self.name_generator.mutate_name(current_name)
            else:  # random
                new_name = self.name_generator.generate_random_name()
                
            # Validate the generated name
            if not self.name_generator.is_valid_name(new_name):
                logger.error(f"Generated name '{new_name}' is invalid")
                return False
                
            # Update section name
            return self.operator.rename_section(pe, section, new_name)
            
        except Exception as e:
            logger.error(f"Failed to randomize section name: {str(e)}")
            return False
            
    def randomize_all_section_names(self, pe: pefile.PE, 
                                  skip_critical: bool = True,
                                  strategy: str = "random") -> bool:
        """
        Randomize names of all suitable sections in the PE file.
        
        Args:
            pe: PE file object
            skip_critical: Whether to skip critical sections
            strategy: Naming strategy ("random", "mimic", or "mutate")
            
        Returns:
            bool: True if all operations successful, False otherwise
        """
        try:
            success = True
            for section in pe.sections:
                # Skip critical sections if requested
                if skip_critical:
                    current_name = section.Name.decode().rstrip('\x00')
                    if current_name in CRITICAL_SECTIONS:
                        logger.info(f"Skipping critical section: {current_name}")
                        continue
                        
                # Randomize section name
                if not self.randomize_section_name(pe, section, strategy):
                    success = False
                    
            return success
            
        except Exception as e:
            logger.error(f"Failed to randomize section names: {str(e)}")
            return False 