"""
String encryption implementation.

This module provides various string encryption techniques and
dynamic decryption stub generation.
"""

import os
import struct
from typing import List, Dict, Optional, Tuple, Union
from Crypto.Cipher import AES, XOR
from Crypto.Util.Padding import pad, unpad
from loguru import logger

from ...base_handler import BaseHandler
from ..pe_handler import PEHandler

class StringEncryptor(BaseHandler):
    """
    Implements string encryption techniques.
    
    Features:
    - Multiple encryption algorithms
    - Dynamic key generation
    - Decryption stub injection
    - String table manipulation
    """
    
    def __init__(self):
        """Initialize string encryptor."""
        super().__init__()
        self.pe_handler = PEHandler()
        self.encryption_methods = {
            "xor": self._encrypt_xor,
            "aes": self._encrypt_aes,
            "rc4": self._encrypt_rc4,
            "custom": self._encrypt_custom
        }
        
    def encrypt_strings(self, 
                       pe,
                       method: str = "xor",
                       section_names: Optional[List[str]] = None) -> bool:
        """
        Encrypt strings in specified sections.
        
        Args:
            pe: PE file object
            method: Encryption method to use
            section_names: Sections to process (None for all)
            
        Returns:
            bool: True if successful
        """
        try:
            if method not in self.encryption_methods:
                raise ValueError(f"Unsupported encryption method: {method}")
                
            # Generate encryption key
            key = self._generate_key(method)
            
            # Process each section
            for section in pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                
                if section_names and section_name not in section_names:
                    continue
                    
                # Find strings in section
                strings = self._find_strings(section.get_data())
                if not strings:
                    continue
                    
                logger.debug(f"Found {len(strings)} strings in section {section_name}")
                
                # Encrypt strings
                encrypted_data = self._encrypt_section_strings(
                    section.get_data(),
                    strings,
                    method,
                    key
                )
                
                # Update section
                section.set_data(encrypted_data)
                
                # Add decryption stub
                self._add_decryption_stub(pe, method, key)
                
            return True
            
        except Exception as e:
            logger.error(f"String encryption failed: {str(e)}")
            return False
            
    def _generate_key(self, method: str) -> bytes:
        """Generate appropriate encryption key."""
        if method == "aes":
            return os.urandom(32)  # 256-bit key
        elif method == "xor":
            return os.urandom(4)   # 32-bit key
        elif method == "rc4":
            return os.urandom(16)  # 128-bit key
        else:
            return os.urandom(8)   # 64-bit key
            
    def _find_strings(self, data: bytes) -> List[Tuple[int, bytes]]:
        """
        Find ASCII and Unicode strings in binary data.
        
        Args:
            data: Binary data to search
            
        Returns:
            List of (offset, string) tuples
        """
        strings = []
        current_string = bytearray()
        string_start = 0
        
        for i, byte in enumerate(data):
            if 32 <= byte <= 126:  # Printable ASCII
                if not current_string:
                    string_start = i
                current_string.append(byte)
            else:
                if len(current_string) >= 4:  # Min string length
                    strings.append((string_start, bytes(current_string)))
                current_string = bytearray()
                
        # Check final string
        if len(current_string) >= 4:
            strings.append((string_start, bytes(current_string)))
            
        return strings
        
    def _encrypt_section_strings(self,
                               data: bytes,
                               strings: List[Tuple[int, bytes]],
                               method: str,
                               key: bytes) -> bytes:
        """
        Encrypt strings in section data.
        
        Args:
            data: Section data
            strings: List of (offset, string) tuples
            method: Encryption method
            key: Encryption key
            
        Returns:
            Modified section data
        """
        result = bytearray(data)
        
        for offset, string in strings:
            # Encrypt string
            encrypted = self.encryption_methods[method](string, key)
            
            # Replace original with encrypted
            result[offset:offset + len(string)] = encrypted
            
        return bytes(result)
        
    def _encrypt_xor(self, data: bytes, key: bytes) -> bytes:
        """XOR encryption implementation."""
        result = bytearray()
        for i, b in enumerate(data):
            result.append(b ^ key[i % len(key)])
        return bytes(result)
        
    def _encrypt_aes(self, data: bytes, key: bytes) -> bytes:
        """AES encryption implementation."""
        cipher = AES.new(key, AES.MODE_CBC)
        return cipher.encrypt(pad(data, AES.block_size))
        
    def _encrypt_rc4(self, data: bytes, key: bytes) -> bytes:
        """RC4 encryption implementation."""
        S = list(range(256))
        j = 0
        
        # KSA
        for i in range(256):
            j = (j + S[i] + key[i % len(key)]) % 256
            S[i], S[j] = S[j], S[i]
            
        # PRGA
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
        """Custom encryption implementation."""
        # Implement a custom encryption algorithm
        # This is where you can add your own algorithm
        result = bytearray()
        for i, b in enumerate(data):
            # Example: rolling XOR with key rotation
            k = key[(i + (b % len(key))) % len(key)]
            result.append((b + k) % 256 ^ key[i % len(key)])
        return bytes(result)
        
    def _add_decryption_stub(self, pe, method: str, key: bytes) -> bool:
        """
        Add decryption stub to the PE file.
        
        Args:
            pe: PE file object
            method: Encryption method used
            key: Encryption key
            
        Returns:
            bool: True if successful
        """
        try:
            # Generate decryption stub
            stub = self._generate_decryption_stub(method, key)
            
            # Find suitable section
            section = self.pe_handler.find_or_create_section(
                pe,
                ".text",
                len(stub),
                ["IMAGE_SCN_MEM_EXECUTE", "IMAGE_SCN_MEM_READ"]
            )
            
            if not section:
                raise RuntimeError("Failed to find/create section for decryption stub")
                
            # Add stub
            section.set_data(stub)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to add decryption stub: {str(e)}")
            return False
            
    def _generate_decryption_stub(self, method: str, key: bytes) -> bytes:
        """
        Generate assembly stub for runtime decryption.
        
        Args:
            method: Encryption method
            key: Encryption key
            
        Returns:
            Assembled machine code for decryption
        """
        # This is where you'd generate the appropriate assembly
        # for runtime string decryption. The exact implementation
        # depends on the target architecture and encryption method.
        
        # For now, return a placeholder
        return b"\x90" * 16  # NOPs
        
    def get_encryption_info(self) -> Dict[str, Any]:
        """
        Get information about available encryption methods.
        
        Returns:
            Dict with encryption capabilities
        """
        return {
            "methods": list(self.encryption_methods.keys()),
            "features": {
                "runtime_decryption": True,
                "key_generation": True,
                "custom_algorithms": True
            }
        } 