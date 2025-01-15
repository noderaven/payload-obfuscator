"""
Constants for PE section handling.

This module defines constants used across section handling operations:
- Section characteristics and flags
- Critical section names
- Valid name characters
- Transformation types
"""

import string
from typing import Dict, Set, List, Literal

# Section characteristics flags
SECTION_CHARACTERISTICS: Dict[str, int] = {
    "IMAGE_SCN_MEM_EXECUTE": 0x20000000,  # Section is executable
    "IMAGE_SCN_MEM_READ": 0x40000000,     # Section is readable
    "IMAGE_SCN_MEM_WRITE": 0x80000000,    # Section is writable
    "IMAGE_SCN_CNT_CODE": 0x00000020,     # Section contains code
    "IMAGE_SCN_CNT_INITIALIZED_DATA": 0x00000040,  # Section contains initialized data
    "IMAGE_SCN_CNT_UNINITIALIZED_DATA": 0x00000080,  # Section contains uninitialized data
    "IMAGE_SCN_LNK_INFO": 0x00000200,     # Section contains comments or other information
    "IMAGE_SCN_LNK_REMOVE": 0x00000800,   # Section will not become part of the image
    "IMAGE_SCN_LNK_COMDAT": 0x00001000,   # Section contains COMDAT data
    "IMAGE_SCN_NO_DEFER_SPEC_EXC": 0x00004000,  # Reset speculative exceptions handling bits
    "IMAGE_SCN_GPREL": 0x00008000,        # Section contains data referenced through global pointer
    "IMAGE_SCN_MEM_PURGEABLE": 0x00020000,  # Reserved for future use
    "IMAGE_SCN_MEM_LOCKED": 0x00040000,   # Reserved for future use
    "IMAGE_SCN_MEM_PRELOAD": 0x00080000,  # Reserved for future use
    "IMAGE_SCN_ALIGN_1BYTES": 0x00100000,    # Align data on 1-byte boundary
    "IMAGE_SCN_ALIGN_2BYTES": 0x00200000,    # Align data on 2-byte boundary
    "IMAGE_SCN_ALIGN_4BYTES": 0x00300000,    # Align data on 4-byte boundary
    "IMAGE_SCN_ALIGN_8BYTES": 0x00400000,    # Align data on 8-byte boundary
    "IMAGE_SCN_ALIGN_16BYTES": 0x00500000,   # Align data on 16-byte boundary
    "IMAGE_SCN_ALIGN_32BYTES": 0x00600000,   # Align data on 32-byte boundary
    "IMAGE_SCN_ALIGN_64BYTES": 0x00700000,   # Align data on 64-byte boundary
    "IMAGE_SCN_ALIGN_128BYTES": 0x00800000,  # Align data on 128-byte boundary
    "IMAGE_SCN_ALIGN_256BYTES": 0x00900000,  # Align data on 256-byte boundary
    "IMAGE_SCN_ALIGN_512BYTES": 0x00A00000,  # Align data on 512-byte boundary
    "IMAGE_SCN_ALIGN_1024BYTES": 0x00B00000, # Align data on 1024-byte boundary
    "IMAGE_SCN_ALIGN_2048BYTES": 0x00C00000, # Align data on 2048-byte boundary
    "IMAGE_SCN_ALIGN_4096BYTES": 0x00D00000, # Align data on 4096-byte boundary
    "IMAGE_SCN_ALIGN_8192BYTES": 0x00E00000, # Align data on 8192-byte boundary
    "IMAGE_SCN_LNK_NRELOC_OVFL": 0x01000000,  # Section contains extended relocations
    "IMAGE_SCN_MEM_DISCARDABLE": 0x02000000,  # Section can be discarded
    "IMAGE_SCN_MEM_NOT_CACHED": 0x04000000,   # Section cannot be cached
    "IMAGE_SCN_MEM_NOT_PAGED": 0x08000000,    # Section is not pageable
    "IMAGE_SCN_MEM_SHARED": 0x10000000,       # Section can be shared in memory
}

# Characteristics that can be safely modified
MUTABLE_CHARACTERISTICS: Dict[str, int] = {
    "IMAGE_SCN_MEM_WRITE": 0x80000000,    # Can toggle writable
    "IMAGE_SCN_CNT_INITIALIZED_DATA": 0x00000040,   # Can change data type
    "IMAGE_SCN_CNT_UNINITIALIZED_DATA": 0x00000080,  # Can change data type
    "IMAGE_SCN_MEM_NOT_CACHED": 0x04000000,   # Can toggle caching
    "IMAGE_SCN_MEM_SHARED": 0x10000000,       # Can toggle sharing
    "IMAGE_SCN_MEM_DISCARDABLE": 0x02000000,  # Can toggle discardable
}

# Required characteristics for specific content types
REQUIRED_CHARACTERISTICS: Dict[str, Set[str]] = {
    "code": {
        "IMAGE_SCN_MEM_EXECUTE",  # Code must be executable
        "IMAGE_SCN_MEM_READ",     # Code must be readable
        "IMAGE_SCN_CNT_CODE"      # Must be marked as code
    },
    "data": {
        "IMAGE_SCN_MEM_READ"      # Data must be readable
    }
}

# Critical sections that should not be modified
CRITICAL_SECTIONS: Set[str] = {
    ".text",    # Main code section
    ".rsrc",    # Resources
    ".reloc",   # Relocations
    ".tls",     # Thread Local Storage
    ".rdata",   # Read-only data
    ".pdata",   # Exception handling data
    ".edata",   # Export data
    ".idata"    # Import data
}

# Valid characters for section names (alphanumeric and some special chars)
VALID_NAME_CHARS: str = string.ascii_letters + string.digits + "_-"

# Maximum length for section names
MAX_NAME_LENGTH: int = 8

# Supported transformation types
TRANSFORM_TYPES = Literal["encrypt", "encode", "compress"]

# Default values
DEFAULT_MUTATION_RATE: float = 0.5
DEFAULT_MAX_ATTEMPTS: int = 100
DEFAULT_COMPRESSION_LEVEL: int = 9

# Encryption constants
AES_BLOCK_SIZE: int = 16
AES_KEY_SIZE: int = 32  # 256-bit key 

# Section Name Constants
MAX_SECTION_NAME_LENGTH = 8

# Common PE Section Names
COMMON_SECTION_NAMES = [
    ".text",
    ".data",
    ".rdata",
    ".idata",
    ".edata",
    ".pdata",
    ".rsrc",
    ".reloc",
    ".bss",
    ".tls",
    ".debug",
    "CODE",
    "DATA",
    "BSS",
    "PAGE",
    "INIT"
] 