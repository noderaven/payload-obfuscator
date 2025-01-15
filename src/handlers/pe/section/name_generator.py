"""
Section name generation and randomization.

This module provides functionality for generating and randomizing PE section names
while maintaining compatibility with PE file format requirements.
"""

import random
import string
from typing import List, Optional
from .constants import COMMON_SECTION_NAMES, MAX_SECTION_NAME_LENGTH
from .errors import SectionError

class NameGenerator:
    """
    Generates and randomizes PE section names.
    
    Features:
    - Random name generation
    - Common section name mimicry
    - Length-preserving mutations
    - PE format compatibility validation
    """
    
    @staticmethod
    def generate_random_name(length: Optional[int] = None) -> str:
        """
        Generate a random section name.
        
        Args:
            length: Optional specific length (default: random between 1-8)
            
        Returns:
            A valid random section name
        """
        if not length:
            length = random.randint(1, MAX_SECTION_NAME_LENGTH)
        elif length > MAX_SECTION_NAME_LENGTH:
            raise SectionError(f"Section name length {length} exceeds maximum {MAX_SECTION_NAME_LENGTH}")
            
        # Use both letters and digits, but ensure starts with a letter
        first_char = random.choice(string.ascii_letters)
        remaining = ''.join(random.choices(
            string.ascii_letters + string.digits,
            k=length - 1
        ))
        return first_char + remaining
    
    @staticmethod
    def mimic_common_name() -> str:
        """
        Generate a name that mimics common PE section names.
        
        Returns:
            A modified version of a common section name
        """
        base_name = random.choice(COMMON_SECTION_NAMES)
        
        # Apply one of several mutation strategies
        strategy = random.randint(1, 3)
        
        if strategy == 1:
            # Add random suffix
            suffix = ''.join(random.choices(string.digits, k=1))
            return f"{base_name}{suffix}"
            
        elif strategy == 2:
            # Character substitution (maintain visual similarity)
            substitutions = {
                'o': '0', 'l': '1', 'e': '3',
                'a': '4', 's': '5', 'b': '6',
                't': '7', 'g': '9'
            }
            if any(c in substitutions for c in base_name.lower()):
                char_to_replace = random.choice([c for c in base_name.lower() if c in substitutions])
                return base_name.replace(char_to_replace, substitutions[char_to_replace])
            return base_name
            
        else:
            # Case mutation
            return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in base_name)
    
    @staticmethod
    def mutate_name(original_name: str) -> str:
        """
        Mutate an existing section name while preserving length.
        
        Args:
            original_name: The original section name to mutate
            
        Returns:
            A mutated version of the original name
        """
        if not original_name:
            raise SectionError("Cannot mutate empty section name")
            
        # Convert to list for mutation
        name_chars = list(original_name)
        
        # Randomly select mutation points
        num_mutations = random.randint(1, max(1, len(name_chars) // 2))
        mutation_indices = random.sample(range(len(name_chars)), num_mutations)
        
        for idx in mutation_indices:
            if idx == 0:
                # First character must be a letter
                name_chars[idx] = random.choice(string.ascii_letters)
            else:
                # Other positions can be letters or digits
                name_chars[idx] = random.choice(string.ascii_letters + string.digits)
                
        return ''.join(name_chars)
    
    @staticmethod
    def is_valid_name(name: str) -> bool:
        """
        Validate if a section name is PE-compatible.
        
        Args:
            name: The section name to validate
            
        Returns:
            bool: True if valid, False otherwise
        """
        if not name or len(name) > MAX_SECTION_NAME_LENGTH:
            return False
            
        # First character must be a letter
        if not name[0].isalpha():
            return False
            
        # Other characters must be alphanumeric
        if not all(c.isalnum() for c in name[1:]):
            return False
            
        return True 