#!/usr/bin/env python3
"""
Dev tool: assemble stub sources with keystone and print STUB_BYTES constants.
Run once after changing asm source, then paste output into the stub files.
Requires: pip install keystone-engine (included in requirements-dev.txt)
"""

XOR_DECRYPTOR_ASM = """
    ; xor_decryptor(image_base: rcx, table_rva: rdx, entry_count: r8d)
    ; Table entry layout (12 bytes each): string_rva:u32, length:u32, key:u8, pad:u8[3]
    push rbx
    push rdi
    push rsi
    push r12
    push r13
    sub rsp, 0x28
    mov r12, rcx
    lea rbx, [r12 + rdx]
    mov r13d, r8d
_loop:
    test r13d, r13d
    jz _done
    mov esi, dword ptr [rbx]
    mov edi, dword ptr [rbx + 4]
    movzx eax, byte ptr [rbx + 8]
    lea rsi, [r12 + rsi]
_xor:
    test edi, edi
    jz _next
    xor byte ptr [rsi], al
    inc rsi
    dec edi
    jmp _xor
_next:
    add rbx, 12
    dec r13d
    jmp _loop
_done:
    add rsp, 0x28
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbx
    ret
"""

API_HASHER_ASM = """
    ; api_hasher(hash_value: ecx) -> function_ptr: rax
    ; Walks PEB InMemoryOrderModuleList, hashes export names with ROR-13.
    ; Returns 0 in rax on failure.
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    sub rsp, 0x28
    mov r12d, ecx
    mov rax, qword ptr gs:[0x60]
    mov rax, qword ptr [rax + 0x18]
    mov rax, qword ptr [rax + 0x20]
    mov r13, rax
_mod_loop:
    lea rbx, [r13 - 0x10]
    mov rdi, qword ptr [rbx + 0x30]
    test rdi, rdi
    jz _mod_next
    mov eax, dword ptr [rdi + 0x3C]
    mov rbp, rdi
    add rbp, rax
    cmp dword ptr [rbp], 0x00004550
    jne _mod_next
    mov ebx, dword ptr [rbp + 0x88]
    test ebx, ebx
    jz _mod_next
    lea rbp, [rdi + rbx]
    mov r14d, dword ptr [rbp + 0x18]
    test r14d, r14d
    jz _mod_next
    mov ebx, dword ptr [rbp + 0x20]
    lea r9, [rdi + rbx]
    xor r10d, r10d
_name_loop:
    cmp r10d, r14d
    jge _mod_next
    mov ebx, dword ptr [r9 + r10*4]
    lea rsi, [rdi + rbx]
    xor ecx, ecx
_hash_loop:
    movzx eax, byte ptr [rsi]
    test al, al
    jz _hash_done
    cmp al, 0x61
    jb _no_lower
    cmp al, 0x7A
    ja _no_lower
    sub al, 0x20
_no_lower:
    ror ecx, 13
    add ecx, eax
    inc rsi
    jmp _hash_loop
_hash_done:
    cmp ecx, r12d
    jne _name_next
    mov ebx, dword ptr [rbp + 0x24]
    lea rbx, [rdi + rbx]
    movzx eax, word ptr [rbx + r10*2]
    mov ebx, dword ptr [rbp + 0x1C]
    lea rbx, [rdi + rbx]
    mov eax, dword ptr [rbx + rax*4]
    lea rax, [rdi + rax]
    jmp _found
_name_next:
    inc r10d
    jmp _name_loop
_mod_next:
    mov r13, qword ptr [r13]
    jmp _mod_loop
_found:
    add rsp, 0x28
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    ret
"""


def _strip_comments(asm: str) -> str:
    """Strip ; line comments from ASM source (keystone does not handle them)."""
    lines = []
    for line in asm.splitlines():
        idx = line.find(';')
        if idx >= 0:
            line = line[:idx]
        lines.append(line)
    return '\n'.join(lines)


def assemble(name: str, asm: str) -> None:
    try:
        from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KsError
    except ImportError:
        print(f"keystone-engine not installed; skipping {name}")
        return
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    try:
        encoding, count = ks.asm(_strip_comments(asm), as_bytes=True)
    except Exception as e:
        print(f"ERROR assembling {name}: {e}")
        return
    print(f"\n# {name}: {count} instructions, {len(encoding)} bytes")
    print(f"STUB_BYTES: bytes = bytes([")
    for i, b in enumerate(encoding):
        if i % 16 == 0:
            print("    ", end="")
        print(f"0x{b:02X}", end="")
        print(", " if i < len(encoding) - 1 else "", end="")
        if (i + 1) % 16 == 0 or i == len(encoding) - 1:
            print()
    print("])")


if __name__ == "__main__":
    assemble("xor_decryptor_x64", XOR_DECRYPTOR_ASM)
    assemble("api_hasher_x64", API_HASHER_ASM)
