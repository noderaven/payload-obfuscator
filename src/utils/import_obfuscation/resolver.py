#!/usr/bin/env python3

from typing import Optional
from keystone import *
from loguru import logger

class ImportObfuscation:
    """Handles import table obfuscation and dynamic API resolution."""
    
    @staticmethod
    def hash_api_name(api_name: str) -> int:
        """
        Create a hash of the API name for dynamic resolution.
        
        Args:
            api_name: Name of the API function
            
        Returns:
            32-bit hash of the API name
        """
        hash_val = 0
        for char in api_name:
            hash_val = ((hash_val << 5) + hash_val) + ord(char)
        return hash_val & 0xFFFFFFFF

    @staticmethod
    def generate_api_resolver() -> bytes:
        """
        Generate shellcode for dynamic API resolution through PEB walking.
        The shellcode will initialize API resolution and return to the original entry point.
        
        Returns:
            Bytes containing the shellcode for API resolution
        """
        try:
            # x86 shellcode for PEB walking and API resolution
            shellcode = [
                # Save registers and flags
                "pushad",
                "pushfd",
                
                # Get PEB address (fs:[0x30])
                "mov eax, fs:[0x30]",             # PEB address
                "mov eax, [eax + 0x0C]",          # PEB_LDR_DATA
                "mov eax, [eax + 0x14]",          # InMemoryOrderModuleList
                
                # Find kernel32.dll base
                "find_kernel32:",
                "mov esi, [eax + 0x28]",          # Get module base address
                "mov edi, [eax + 0x10]",          # Get module name pointer
                "mov eax, [eax]",                 # Get next module
                "cmp word [edi + 12*2], 0x32",    # Compare with "2" in "kernel32.dll"
                "jne find_kernel32",
                
                # ESI now contains kernel32.dll base address
                "mov ebp, esi",                   # Save kernel32 base in ebp
                
                # Parse kernel32 PE header
                "mov eax, [ebp + 0x3C]",         # e_lfanew offset
                "mov edx, [ebp + eax + 0x78]",   # Export table RVA
                "add edx, ebp",                   # Export table VA
                "mov ecx, [edx + 0x18]",         # Number of names
                "mov ebx, [edx + 0x20]",         # Names table RVA
                "add ebx, ebp",                   # Names table VA
                
                # Find GetProcAddress
                "find_getprocaddr:",
                "dec ecx",                        # Decrement counter
                "mov esi, [ebx + ecx*4]",        # Get name RVA
                "add esi, ebp",                   # Get name VA
                "mov edi, 0x50746547",           # "GetP"
                "cmp dword [esi], edi",
                "jne find_getprocaddr",
                
                # Found GetProcAddress, get its ordinal
                "mov ebx, [edx + 0x24]",         # Ordinals table RVA
                "add ebx, ebp",                   # Ordinals table VA
                "mov cx, [ebx + ecx*2]",         # Get ordinal
                "mov ebx, [edx + 0x1C]",         # Address table RVA
                "add ebx, ebp",                   # Address table VA
                "mov eax, [ebx + ecx*4]",        # Get function RVA
                "add eax, ebp",                   # Get function VA
                
                # Store GetProcAddress for later use
                "mov [esp - 4], eax",            # Save GetProcAddress VA
                
                # Restore registers and flags
                "popfd",
                "popad",
                
                # Get current address (for position-independent code)
                "call get_eip",
                "get_eip:",
                "pop ebx",                       # EBX now contains current address
                
                # Calculate original entry point address
                # Original entry point RVA is stored at the end of our code
                "mov eax, [ebx + (original_entry_offset - get_eip)]",
                
                # Jump to original entry point
                "jmp eax",
                
                # Label for original entry point value
                "original_entry_offset:"
                # Original entry point RVA will be appended here
            ]
            
            # Helper function to resolve APIs (optional for later use)
            resolve_api = """
                ; Input: Stack contains function hash
                resolve_api:
                    push ebp
                    mov ebp, esp
                    pushad
                    
                    mov ebx, [ebp + 8]            ; Get function hash
                    mov esi, [esp - 4]            ; GetProcAddress VA
                    
                    ; Walk export table again
                    mov eax, [ebp + 0x3C]         ; e_lfanew
                    mov edx, [ebp + eax + 0x78]   ; Export table RVA
                    add edx, ebp                   ; Export table VA
                    mov ecx, [edx + 0x18]         ; Number of names
                    mov edi, [edx + 0x20]         ; Names table RVA
                    add edi, ebp                   ; Names table VA
                    
                check_next_func:
                    dec ecx
                    mov eax, [edi + ecx*4]        ; Get name RVA
                    add eax, ebp                   ; Get name VA
                    
                    ; Calculate hash of name
                    push ecx
                    xor ecx, ecx
                    xor edx, edx
                    
                calc_hash:
                    movzx edx, byte [eax]
                    test dl, dl
                    jz hash_done
                    mov cl, 5
                    shl edx, cl
                    add edx, [esp + 4]            ; Add to running hash
                    inc eax
                    jmp calc_hash
                    
                hash_done:
                    pop ecx
                    
                    ; Compare with target hash
                    cmp edx, ebx
                    jne check_next_func
                    
                    ; Found matching function, get its address
                    mov ebx, [edx + 0x24]         ; Ordinals table RVA
                    add ebx, ebp
                    mov cx, [ebx + ecx*2]         ; Get ordinal
                    mov ebx, [edx + 0x1C]         ; Address table RVA
                    add ebx, ebp
                    mov eax, [ebx + ecx*4]        ; Get function RVA
                    add eax, ebp                   ; Get function VA
                    
                    mov [ebp - 8], eax            ; Save resolved address
                    
                    popad
                    mov eax, [ebp - 8]            ; Return resolved address
                    mov esp, ebp
                    pop ebp
                    ret 4
            """
            
            # Combine main shellcode and API resolver
            full_shellcode = "\n".join(shellcode) + resolve_api
            
            try:
                # Initialize Keystone engine
                ks = Ks(KS_ARCH_X86, KS_MODE_32)
                encoded, _ = ks.asm(full_shellcode)
                if encoded:
                    return bytes(encoded)
            except KsError as e:
                logger.error(f"Failed to assemble API resolver shellcode: {e}")
                
            return b""
            
        except Exception as e:
            logger.error(f"Error in generate_api_resolver: {e}")
            return b"" 