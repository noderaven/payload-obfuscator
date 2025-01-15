"""
String table manipulation and management.

This module handles PE file string table operations including:
- String resource manipulation
- String table parsing
- String reference management
"""

import pefile
from typing import List, Dict, Optional, Set
from loguru import logger

from ...base_handler import BaseHandler

class StringTableHandler(BaseHandler):
    """
    Handles PE file string table operations.
    
    Features:
    - String resource extraction
    - String table modification
    - Reference tracking
    - Table rebuilding
    """
    
    def __init__(self):
        """Initialize string table handler."""
        super().__init__()
        
    def get_string_resources(self, pe: pefile.PE) -> Dict[int, bytes]:
        """
        Extract string resources from PE file.
        
        Args:
            pe: PE file object
            
        Returns:
            Dict mapping resource IDs to string data
        """
        try:
            strings = {}
            
            # Check for resource directory
            if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                return strings
                
            # Process string resources
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.id == pefile.RESOURCE_TYPE['RT_STRING']:
                    for resource_id in resource_type.directory.entries:
                        try:
                            # Get string data
                            data = self._get_resource_data(pe, resource_id)
                            if data:
                                strings[resource_id.id] = data
                        except Exception as e:
                            logger.debug(f"Failed to extract string resource {resource_id.id}: {str(e)}")
                            
            return strings
            
        except Exception as e:
            logger.error(f"Failed to get string resources: {str(e)}")
            return {}
            
    def _get_resource_data(self, pe: pefile.PE, resource_id) -> Optional[bytes]:
        """Extract data from a resource entry."""
        try:
            # Get resource data entry
            resource_data = resource_id.directory.entries[0]
            
            # Get offset to data
            offset = resource_data.data.struct.OffsetToData
            size = resource_data.data.struct.Size
            
            # Read data
            return pe.get_data(offset, size)
            
        except Exception as e:
            logger.debug(f"Resource data extraction failed: {str(e)}")
            return None
            
    def update_string_table(self, 
                          pe: pefile.PE,
                          strings: Dict[int, bytes]) -> bool:
        """
        Update PE file string table.
        
        Args:
            pe: PE file object
            strings: Dict of string ID to data mappings
            
        Returns:
            bool: True if successful
        """
        try:
            # Check for resource directory
            if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                logger.warning("No resource directory found")
                return False
                
            # Update string resources
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.id == pefile.RESOURCE_TYPE['RT_STRING']:
                    for resource_id in resource_type.directory.entries:
                        if resource_id.id in strings:
                            try:
                                # Update string data
                                self._update_resource_data(
                                    pe,
                                    resource_id,
                                    strings[resource_id.id]
                                )
                            except Exception as e:
                                logger.error(f"Failed to update string {resource_id.id}: {str(e)}")
                                return False
                                
            return True
            
        except Exception as e:
            logger.error(f"String table update failed: {str(e)}")
            return False
            
    def _update_resource_data(self, 
                            pe: pefile.PE,
                            resource_id,
                            data: bytes) -> None:
        """Update data in a resource entry."""
        try:
            # Get resource data entry
            resource_data = resource_id.directory.entries[0]
            
            # Get offset to data
            offset = resource_data.data.struct.OffsetToData
            
            # Update size
            resource_data.data.struct.Size = len(data)
            
            # Write new data
            pe.set_bytes_at_offset(offset, data)
            
        except Exception as e:
            raise RuntimeError(f"Resource data update failed: {str(e)}")
            
    def find_string_references(self, 
                             pe: pefile.PE,
                             section_names: Optional[List[str]] = None) -> Dict[int, List[int]]:
        """
        Find references to string resources.
        
        Args:
            pe: PE file object
            section_names: Sections to search (None for all)
            
        Returns:
            Dict mapping string IDs to lists of reference offsets
        """
        try:
            references = {}
            
            # Process each section
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                
                if section_names and section_name not in section_names:
                    continue
                    
                # Search for references
                data = section.get_data()
                for i in range(len(data) - 4):
                    # Look for potential resource IDs
                    resource_id = int.from_bytes(data[i:i+4], byteorder='little')
                    
                    # Validate as possible string resource
                    if self._is_valid_string_id(resource_id):
                        if resource_id not in references:
                            references[resource_id] = []
                        references[resource_id].append(
                            section.VirtualAddress + i
                        )
                        
            return references
            
        except Exception as e:
            logger.error(f"Failed to find string references: {str(e)}")
            return {}
            
    def _is_valid_string_id(self, resource_id: int) -> bool:
        """Check if a resource ID could be a valid string resource."""
        # Implement validation logic based on your PE file structure
        # This is a basic example
        return 1 <= resource_id <= 65535
        
    def get_string_table_info(self, pe: pefile.PE) -> Dict[str, Any]:
        """
        Get information about the string table.
        
        Args:
            pe: PE file object
            
        Returns:
            Dict with string table information
        """
        try:
            info = {
                "has_resources": hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'),
                "string_count": 0,
                "total_size": 0,
                "sections": set()
            }
            
            if info["has_resources"]:
                strings = self.get_string_resources(pe)
                info["string_count"] = len(strings)
                info["total_size"] = sum(len(s) for s in strings.values())
                
                # Find string locations
                references = self.find_string_references(pe)
                for ref_list in references.values():
                    for ref in ref_list:
                        section = self._find_section_by_rva(pe, ref)
                        if section:
                            info["sections"].add(
                                section.Name.decode().rstrip('\x00')
                            )
                            
            return info
            
        except Exception as e:
            logger.error(f"Failed to get string table info: {str(e)}")
            return {}
            
    def _find_section_by_rva(self, pe: pefile.PE, rva: int) -> Optional[pefile.SectionStructure]:
        """Find section containing an RVA."""
        for section in pe.sections:
            if section.VirtualAddress <= rva < section.VirtualAddress + section.Misc_VirtualSize:
                return section
        return None 