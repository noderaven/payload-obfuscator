#!/usr/bin/env python3

import random
from typing import List, Tuple, Dict
from loguru import logger

class StringObfuscation:
    """Handles string obfuscation using multiple techniques."""
    
    @staticmethod
    def xor_encrypt(data: bytes, key: bytes) -> bytes:
        """Simple XOR encryption for strings."""
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))
        
    @staticmethod
    def rotate_string(data: bytes, rotation: int) -> bytes:
        """Rotate string by specified amount."""
        return bytes(((b + rotation) & 0xFF) for b in data)
        
    @staticmethod
    def split_string(data: str) -> List[str]:
        """Split string into random chunks."""
        chunks = []
        while data:
            chunk_size = random.randint(1, min(len(data), 4))
            chunks.append(data[:chunk_size])
            data = data[chunk_size:]
        return chunks

    @staticmethod
    def combined_obfuscate(data: str, key: bytes = None, rotation: int = None) -> Tuple[List[bytes], Dict]:
        """
        Apply multiple layers of string obfuscation:
        1. XOR encryption with random or provided key
        2. Character rotation
        3. Random chunking
        4. Additional entropy layers
        
        Args:
            data: String to obfuscate
            key: Optional encryption key
            rotation: Optional rotation value
            
        Returns:
            Tuple containing list of obfuscated chunks and deobfuscation parameters
        """
        try:
            # Generate random parameters if not provided
            if key is None:
                key = bytes([random.randint(0x41, 0x5A) for _ in range(4)])  # Random 4-byte key
            if rotation is None:
                rotation = random.randint(1, 255)  # Random rotation value

            # Convert string to bytes if needed
            data_bytes = data.encode() if isinstance(data, str) else data
            
            # Layer 1: XOR Encryption
            xor_data = StringObfuscation.xor_encrypt(data_bytes, key)
            
            # Layer 2: Rotation
            rotated_data = StringObfuscation.rotate_string(xor_data, rotation)
            
            # Layer 3: Add random padding between chunks
            padded_data = bytearray()
            for b in rotated_data:
                padded_data.append(b)
                # 20% chance to add random padding byte
                if random.random() < 0.2:
                    padded_data.append(random.randint(0x41, 0x5A))  # Random ASCII letter
            
            # Layer 4: Split into random-sized chunks
            chunks = []
            temp_data = bytes(padded_data)
            while temp_data:
                chunk_size = random.randint(2, min(len(temp_data), 8))
                chunks.append(temp_data[:chunk_size])
                temp_data = temp_data[chunk_size:]
            
            # Layer 5: Additional entropy - prepend chunk index as encrypted byte
            final_chunks = []
            for i, chunk in enumerate(chunks):
                # Encrypt chunk index
                index_byte = (i ^ key[0]).to_bytes(1, 'little')
                final_chunks.append(index_byte + chunk)
            
            # Store deobfuscation parameters
            params = {
                'key': key,
                'rotation': rotation,
                'chunk_count': len(chunks),
                'has_padding': True,
                'original_length': len(data_bytes)
            }
            
            return final_chunks, params

        except Exception as e:
            logger.error(f"Error in combined_obfuscate: {e}")
            # If anything fails, return data in a simple obfuscated form
            return [StringObfuscation.xor_encrypt(data.encode(), b'K')], {'key': b'K', 'rotation': 0}

    @staticmethod
    def deobfuscate(chunks: List[bytes], params: Dict) -> str:
        """
        Reverse the combined obfuscation process.
        
        Args:
            chunks: List of obfuscated chunks
            params: Dictionary containing deobfuscation parameters
            
        Returns:
            Original string
        """
        try:
            # Extract parameters
            key = params['key']
            rotation = params['rotation']
            original_length = params.get('original_length', 0)
            
            # Remove chunk index bytes and sort chunks
            sorted_chunks = []
            for chunk in chunks:
                index = chunk[0] ^ key[0]
                sorted_chunks.append((index, chunk[1:]))
            sorted_chunks.sort(key=lambda x: x[0])
            
            # Combine chunks
            combined_data = b''.join(chunk for _, chunk in sorted_chunks)
            
            # Remove padding (every third byte if padding exists)
            if params.get('has_padding', False):
                cleaned_data = bytearray()
                padding_positions = set()
                i = 0
                while len(cleaned_data) < original_length and i < len(combined_data):
                    if i not in padding_positions:
                        cleaned_data.append(combined_data[i])
                    i += 1
                combined_data = bytes(cleaned_data)
            
            # Reverse rotation
            unrotated_data = StringObfuscation.rotate_string(combined_data, -rotation)
            
            # Reverse XOR encryption
            decrypted_data = StringObfuscation.xor_encrypt(unrotated_data, key)
            
            return decrypted_data.decode()

        except Exception as e:
            logger.error(f"Error in deobfuscate: {e}")
            # If deobfuscation fails, attempt simple XOR decryption
            return StringObfuscation.xor_encrypt(b''.join(chunks), b'K').decode() 