"""Core PE file I/O. Owns all safe writes, append, and header fixup."""
from __future__ import annotations
import struct
from pathlib import Path
import pefile
from src.utils import pe_math


class PEError(Exception):
    """Raised for unrecoverable PE load/save/format errors."""


class PEWriteError(PEError):
    """Raised when a write would exceed pe.__data__ bounds."""


def load(path: Path) -> pefile.PE:
    try:
        return pefile.PE(str(path), fast_load=False)
    except pefile.PEFormatError as exc:
        raise PEError(f"Cannot parse PE: {exc}") from exc


def save(pe: pefile.PE, path: Path) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(pe.write())


def safe_write(pe: pefile.PE, offset: int, data: bytes) -> None:
    """Write data into pe.__data__ at offset. Raises PEWriteError if out of bounds."""
    end = offset + len(data)
    if offset < 0 or end > len(pe.__data__):
        raise PEWriteError(
            f"Write [0x{offset:x}..0x{end:x}) exceeds PE size 0x{len(pe.__data__):x}"
        )
    pe.set_bytes_at_offset(offset, data)


def append_section_data(pe: pefile.PE, data: bytes) -> int:
    """Append data to pe.__data__, padded to FileAlignment. Returns the file offset.

    The existing image is first padded to a FileAlignment boundary so that both
    the returned offset and the final image length are multiples of FileAlignment.
    """
    fa = pe.OPTIONAL_HEADER.FileAlignment
    # Coerce mmap (loaded from file path) to bytearray
    existing = bytearray(pe.__data__)
    # Pad existing data up to next FileAlignment boundary
    aligned_base = pe_math.align(len(existing), fa)
    existing = existing + b"\x00" * (aligned_base - len(existing))
    offset = len(existing)
    # Pad the new chunk to a full FileAlignment block
    aligned_chunk = pe_math.align(len(data), fa)
    padded = bytes(data) + b"\x00" * (aligned_chunk - len(data))
    pe.__data__ = existing + bytearray(padded)
    return offset


def fix_headers(pe: pefile.PE) -> None:
    """Recompute NumberOfSections, SizeOfImage, SizeOfHeaders, and CheckSum.
    Call this once after all techniques have run, before save()."""
    sa = pe.OPTIONAL_HEADER.SectionAlignment
    fa = pe.OPTIONAL_HEADER.FileAlignment

    pe.FILE_HEADER.NumberOfSections = len(pe.sections)

    max_va = max(s.VirtualAddress + s.Misc_VirtualSize for s in pe.sections)
    pe.OPTIONAL_HEADER.SizeOfImage = pe_math.align(max_va, sa)

    e_lfanew = pe.DOS_HEADER.e_lfanew
    section_table_start = e_lfanew + 4 + pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader
    headers_raw_end = section_table_start + len(pe.sections) * 40
    pe.OPTIONAL_HEADER.SizeOfHeaders = pe_math.align(headers_raw_end, fa)

    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()


def append_new_section(
    pe: pefile.PE,
    name: str,
    data: bytes,
    characteristics: int,
) -> None:
    """Add a new section. Raises PEError if no space in the section table header."""
    fa = pe.OPTIONAL_HEADER.FileAlignment
    sa = pe.OPTIONAL_HEADER.SectionAlignment

    e_lfanew = pe.DOS_HEADER.e_lfanew
    section_table_start = e_lfanew + 4 + pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader
    existing_headers_end = section_table_start + len(pe.sections) * 40

    first_raw = min(
        s.PointerToRawData for s in pe.sections if s.PointerToRawData > 0
    )
    available = first_raw - existing_headers_end
    if available < 40:
        raise PEError(
            f"No header space for new section (need 40 bytes, have {available}). "
            "Consider enlarging SizeOfHeaders or use section slack instead."
        )

    last = max(pe.sections, key=lambda s: s.VirtualAddress)
    new_va = pe_math.align(last.VirtualAddress + last.Misc_VirtualSize, sa)

    raw_offset = append_section_data(pe, data)
    raw_size = pe_math.align(len(data), fa)

    name_bytes = name.encode("ascii").ljust(8, b"\x00")[:8]
    hdr = struct.pack(
        "<8sIIIIIIHHI",
        name_bytes,
        len(data),       # Misc_VirtualSize
        new_va,          # VirtualAddress
        raw_size,        # SizeOfRawData
        raw_offset,      # PointerToRawData
        0, 0, 0, 0,      # Relocations, Linenumbers (unused)
        characteristics,
    )

    safe_write(pe, existing_headers_end, hdr)
    # Increment NumberOfSections in the in-memory struct so parse_sections
    # reads all entries including the new one we just wrote.
    pe.FILE_HEADER.NumberOfSections = len(pe.sections) + 1
    pe.parse_sections(section_table_start)
