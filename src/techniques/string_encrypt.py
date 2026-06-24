"""
XOR-encrypt printable strings in .rdata/.data and inject a decryption table.

Phase 1 approach: encrypt strings in-place in section content, and write
a decryption table that the runtime stub (TLS callback) will process.
The stub itself is injected into slack space of the first code section.
If no suitable slack exists for the stub, the technique falls back to a new section.
If STUB_BYTES is empty (generate.py not yet run), raises TechniqueError.
"""
from __future__ import annotations
import os
import struct
from typing import Optional
import pefile

from src.techniques.base import BaseTechnique, TechniqueError
from src.core.pe_loader import safe_write, append_new_section
from src.utils import pe_math, constants
from src.stubs.xor_decryptor_x64 import STUB_BYTES, ENTRY_SIZE


_MIN_STRING = 8
_PRINTABLE = set(range(0x20, 0x7F))


def _find_strings(data: bytes, min_len: int = _MIN_STRING) -> list[tuple[int, int]]:
    """Return (offset, length) pairs for printable ASCII runs in data."""
    results = []
    start = None
    for i, b in enumerate(data):
        if b in _PRINTABLE:
            if start is None:
                start = i
        else:
            if start is not None and (i - start) >= min_len:
                results.append((start, i - start))
            start = None
    if start is not None and (len(data) - start) >= min_len:
        results.append((start, len(data) - start))
    return results


def xor_decrypt_table(
    data: bytes,
    entries: list[tuple[int, int, int]],
) -> list[bytes]:
    """Python-side round-trip verification of the stub's XOR logic."""
    out = []
    for offset, length, key in entries:
        chunk = bytearray(data[offset:offset + length])
        for i in range(len(chunk)):
            chunk[i] ^= key
        out.append(bytes(chunk))
    return out


class StringEncrypt(BaseTechnique):
    name = "string_encrypt"
    required = False

    def __init__(self, min_string_length: int = _MIN_STRING):
        self._min_len = min_string_length

    def apply(self, pe: pefile.PE) -> None:
        if not STUB_BYTES:
            raise TechniqueError(
                "STUB_BYTES is empty in xor_decryptor_x64.py. "
                "Run `python src/stubs/generate.py` and paste the output."
            )

        entries: list[tuple[int, int, int]] = []

        for section in pe.sections:
            name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
            if name not in (".rdata", ".data"):
                continue
            sec_data = bytes(pe.__data__[section.PointerToRawData:
                                         section.PointerToRawData + section.Misc_VirtualSize])
            for offset, length in _find_strings(sec_data, self._min_len):
                abs_offset = section.PointerToRawData + offset
                rva = section.VirtualAddress + offset
                key = int.from_bytes(os.urandom(1), "little") or 0x41
                encrypted = bytes(sec_data[offset + i] ^ key for i in range(length))
                safe_write(pe, abs_offset, encrypted)
                entries.append((rva, length, key))

        if not entries:
            return

        table = struct.pack("<I", len(entries))
        for rva, length, key in entries:
            table += struct.pack("<IIBxxx", rva, length, key)

        stub_section = pe_math.find_executable_section(pe)
        if stub_section is None:
            raise TechniqueError("No executable section found to inject stub")

        slack = pe_math.section_slack(stub_section)
        needed = len(STUB_BYTES) + len(table)
        if slack < needed:
            try:
                append_new_section(pe, ".init", STUB_BYTES + table, constants.CHARS_RDATA)
            except Exception as exc:
                raise TechniqueError(f"Cannot inject stub: {exc}") from exc
            return

        stub_file_offset = stub_section.PointerToRawData + stub_section.Misc_VirtualSize
        safe_write(pe, stub_file_offset, STUB_BYTES)

        table_file_offset = stub_file_offset + len(STUB_BYTES)
        safe_write(pe, table_file_offset, table)

        new_virt = stub_section.Misc_VirtualSize + needed
        safe_write(pe, stub_section.get_file_offset() + 8, struct.pack("<I", new_virt))
        stub_section.Misc_VirtualSize = new_virt
