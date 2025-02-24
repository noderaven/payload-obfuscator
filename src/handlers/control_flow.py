"""
Control flow obfuscation handler for Windows PE binaries.
"""

from loguru import logger
import pefile

class ControlFlowObfuscator:
    """Handler for adding control flow obfuscation to PE files."""
    
    def add_dummy_section(self, pe: pefile.PE) -> bool:
        """
        Add a new section with dummy code to obfuscate control flow.
        
        Args:
            pe: PE file object
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            # Get original entry point
            original_entry_rva = pe.OPTIONAL_HEADER.AddressOfEntrypoint
            section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
            file_alignment = pe.OPTIONAL_HEADER.FileAlignment
            
            # Define dummy code (loop 10 times then jump to original entry)
            # For simplicity, using 32-bit compatible code; adjust for 64-bit as needed
            dummy_code = (
                b"\xB9\x0A\x00\x00\x00"  # mov ecx, 10
                b"\x90"                  # nop
                b"\xE2\xFD"              # loop $-3 (back to nop)
            )
            jmp_size = 5  # Size of jmp rel32 instruction
            dummy_code_size = len(dummy_code)
            
            # Calculate new section size (aligned)
            total_code_size = dummy_code_size + jmp_size
            new_section_size = ((total_code_size + file_alignment - 1) // file_alignment) * file_alignment
            
            # Add new section
            number_of_sections = len(pe.sections)
            new_section = pefile.SectionStructure(
                pe.__structures__,
                Name=b".obf_dum",
                Characteristics=(pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE'] |
                                pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_READ'])
            )
            new_section.SizeOfRawData = new_section_size
            new_section.PointerToRawData = pe.sections[-1].PointerToRawData + pe.sections[-1].SizeOfRawData
            new_section.VirtualAddress = pe.sections[-1].VirtualAddress + ((pe.sections[-1].Misc_VirtualSize + section_alignment - 1) // section_alignment) * section_alignment
            new_section.Misc_VirtualSize = total_code_size
            
            # Append new section
            pe.sections.append(new_section)
            pe.FILE_HEADER.NumberOfSections = number_of_sections + 1
            
            # Calculate jump offset (relative from end of dummy code to original entry)
            new_entry_va = new_section.VirtualAddress
            jmp_offset = original_entry_rva - (new_entry_va + dummy_code_size + jmp_size)
            jmp_instruction = b"\xE9" + jmp_offset.to_bytes(4, byteorder='little', signed=True)
            
            # Combine dummy code and jump
            section_data = dummy_code + jmp_instruction + b"\x00" * (new_section_size - total_code_size)
            pe.__data__ = pe.__data__[:new_section.PointerToRawData] + section_data + pe.__data__[new_section.PointerToRawData:]
            
            # Update entry point and image size
            pe.OPTIONAL_HEADER.AddressOfEntrypoint = new_section.VirtualAddress
            pe.OPTIONAL_HEADER.SizeOfImage = new_section.VirtualAddress + new_section.Misc_VirtualSize
            
            logger.debug(f"Added dummy section at RVA: {new_section.VirtualAddress:x}")
            return True
            
        except Exception as e:
            logger.error(f"[red]Failed to add dummy section: {str(e)}[/red]")
            return False
