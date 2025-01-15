"""
PE Import Handler Module
======================

This module provides functionality for handling PE file import tables, including
import resolution, modification, and API resolver injection.
"""

import struct
import pefile
from typing import Optional, Dict, Any
from ..base_handler import BaseHandler, HandlerError
from ...utils.import_obfuscation import ImportObfuscation

class ImportError(HandlerError):
    """Exception for import-related errors."""
    pass

class ImportHandler(BaseHandler):
    """Handles PE file import table operations."""
    
    def inject_resolver(
        self,
        pe: pefile.PE,
        section: pefile.SectionStructure,
        resolver_code: bytes
    ) -> bool:
        """
        Inject API resolver code into a PE section.
        
        Args:
            pe: PE file object to modify
            section: Target section for injection
            resolver_code: API resolver code to inject
            
        Returns:
            bool: True if successful
            
        Note:
            This method:
            1. Saves the original entry point
            2. Creates architecture-specific jump-back code
            3. Combines resolver with jump-back code
            4. Injects the combined code into the section
            5. Updates the entry point
        """
        try:
            # Save original entry point
            original_entry_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            original_entry_va = pe.OPTIONAL_HEADER.ImageBase + original_entry_rva
            
            self.logger.debug(
                "[cyan]Entry point details:[/cyan]\n"
                f"  RVA: {self._format_hex(original_entry_rva)}\n"
                f"  VA:  {self._format_hex(original_entry_va)}"
            )
            
            # Create jump back to original entry point
            try:
                if pe.OPTIONAL_HEADER.Magic == 0x20b:  # PE32+ (64-bit)
                    jump_back = (
                        b"\x48\xB8" +  # mov rax
                        struct.pack("<Q", original_entry_va) +  # 64-bit address
                        b"\xFF\xE0"  # jmp rax
                    )
                else:  # PE32 (32-bit)
                    jump_back = (
                        b"\x68" +  # push
                        struct.pack("<I", original_entry_va) +  # 32-bit address
                        b"\xC3"  # ret
                    )
            except struct.error as e:
                self._log_error(
                    "Failed to create jump-back code",
                    error=e,
                    details={"cause": "Invalid entry point address"}
                )
                return False
            
            # Combine resolver code with jump back
            full_code = resolver_code + jump_back
            
            # Get current section data
            section_data = section.get_data()
            resolver_offset = len(section_data)
            new_entry_rva = section.VirtualAddress + resolver_offset
            
            # Check available space
            available_space = section.SizeOfRawData - len(section_data)
            if len(full_code) > available_space:
                self._log_error(
                    "Insufficient space in section",
                    details={
                        "required": len(full_code),
                        "available": available_space,
                        "section": section.Name.decode().strip('\x00')
                    }
                )
                return False
            
            # Update section data
            new_data = section_data + full_code
            section.set_data(new_data)
            
            # Update entry point
            pe.OPTIONAL_HEADER.AddressOfEntryPoint = new_entry_rva
            
            self._log_success(
                "Successfully injected resolver code",
                details={
                    "section": section.Name.decode().strip('\x00'),
                    "offset": self._format_hex(resolver_offset),
                    "size": len(full_code)
                }
            )
            
            return True
            
        except Exception as e:
            self._log_error("Failed to inject resolver code", error=e)
            return False
    
    def generate_resolver(self) -> Optional[bytes]:
        """
        Generate API resolver shellcode.
        
        Returns:
            Optional[bytes]: Generated resolver code if successful
            
        Note:
            Uses the ImportObfuscation utility to generate position-independent
            shellcode that can resolve API addresses at runtime.
        """
        try:
            resolver_code = ImportObfuscation.generate_api_resolver()
            if not resolver_code:
                self._log_error("Failed to generate API resolver code")
                return None
            
            self._log_success(
                "Generated API resolver code",
                details={"size": len(resolver_code)}
            )
            return resolver_code
            
        except Exception as e:
            self._log_error("Error generating resolver code", error=e)
            return None 