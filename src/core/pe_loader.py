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
    """Write data into pe.__data__ at offset. Raises PEWriteError if out of bounds.

    Every parsed structure that overlaps the written range is then re-read from
    pe.__data__, so the write survives pe.write() (which repacks every entry of
    pe.__structures__) and attributes such as section.Name reflect it.
    """
    end = offset + len(data)
    if offset < 0 or end > len(pe.__data__):
        raise PEWriteError(
            f"Write [0x{offset:x}..0x{end:x}) exceeds PE size 0x{len(pe.__data__):x}"
        )
    if not data:
        return
    pe.set_bytes_at_offset(offset, bytes(data))
    _resync_structures(pe, offset, end)


def _resync_structures(pe: pefile.PE, start: int, end: int) -> None:
    """Re-unpack every structure in pe.__structures__ that overlaps [start, end)."""
    data_len = len(pe.__data__)
    for structure in pe.__structures__:
        s_off = structure.get_file_offset()
        if s_off is None:
            continue
        s_end = s_off + structure.sizeof()
        if s_off < end and start < s_end and s_end <= data_len:
            structure.__unpack__(bytes(pe.__data__[s_off:s_end]))


IMAGE_DIRECTORY_ENTRY_SECURITY = 4
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11
SECTION_HEADER_SIZE = 40


def _data_directory(pe: pefile.PE, index: int):
    """Return DATA_DIRECTORY[index], or None if the optional header has no such entry."""
    directories = pe.OPTIONAL_HEADER.DATA_DIRECTORY
    return directories[index] if index < len(directories) else None


def _set_data_directory(pe: pefile.PE, index: int, va: int, size: int) -> None:
    """Rewrite a data directory entry in pe.__data__; safe_write resyncs the struct."""
    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[index]
    safe_write(pe, entry.get_file_offset(), struct.pack("<II", va, size))


def _sections_raw_end(pe: pefile.PE) -> int:
    """File offset just past the raw data of every section (SizeOfHeaders if none)."""
    return max(
        (s.PointerToRawData + s.SizeOfRawData for s in pe.sections),
        default=pe.OPTIONAL_HEADER.SizeOfHeaders,
    )


def append_section_data(pe: pefile.PE, data: bytes) -> int:
    """Insert data after the last section's raw data, padded to FileAlignment.

    Returns the file offset of the inserted chunk: the end of section raw data
    rounded up to FileAlignment. Anything that followed the section data (the
    overlay and the Authenticode certificate) is moved after the new chunk, and
    DATA_DIRECTORY[4] (a file offset) is shifted with it.
    """
    fa = pe.OPTIONAL_HEADER.FileAlignment
    raw_end = _sections_raw_end(pe)
    offset = pe_math.align(raw_end, fa)
    # Coerce mmap (loaded from file path) to bytearray
    existing = bytearray(pe.__data__)
    head = existing[:raw_end]
    tail = existing[raw_end:]
    head += b"\x00" * (offset - len(head))
    aligned_chunk = pe_math.align(len(data), fa)
    padded = bytes(data) + b"\x00" * (aligned_chunk - len(data))
    pe.__data__ = head + bytearray(padded) + tail

    shift = offset + aligned_chunk - raw_end
    if tail and shift:
        # Parsed structures that lived in the moved tail must be repacked at their
        # new offsets, or pe.write() would write them over the new chunk.
        for structure in pe.__structures__:
            s_off = structure.get_file_offset()
            if s_off is not None and s_off >= raw_end:
                structure.set_file_offset(s_off + shift)
    security = _data_directory(pe, IMAGE_DIRECTORY_ENTRY_SECURITY)
    if security is not None and security.VirtualAddress and security.VirtualAddress >= raw_end:
        _set_data_directory(pe, IMAGE_DIRECTORY_ENTRY_SECURITY,
                            security.VirtualAddress + shift, security.Size)
    return offset


def fix_headers(pe: pefile.PE) -> None:
    """Recompute NumberOfSections, SizeOfImage, SizeOfHeaders, and CheckSum.
    Call this once after all techniques have run, before save().

    SizeOfHeaders is never lowered: data may legitimately sit in the header area
    past the section table.
    """
    sa = pe.OPTIONAL_HEADER.SectionAlignment
    fa = pe.OPTIONAL_HEADER.FileAlignment

    pe.FILE_HEADER.NumberOfSections = len(pe.sections)

    max_va = max(s.VirtualAddress + pe_math.effective_virtual_size(s) for s in pe.sections)
    pe.OPTIONAL_HEADER.SizeOfImage = pe_math.align(max_va, sa)

    e_lfanew = pe.DOS_HEADER.e_lfanew
    section_table_start = e_lfanew + 4 + pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader
    headers_raw_end = section_table_start + len(pe.sections) * SECTION_HEADER_SIZE
    pe.OPTIONAL_HEADER.SizeOfHeaders = max(
        pe.OPTIONAL_HEADER.SizeOfHeaders, pe_math.align(headers_raw_end, fa)
    )

    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()


def _drop_bound_import_in(pe: pefile.PE, start: int, end: int) -> None:
    """Zero the bound-import directory and its data if its file range overlaps [start, end).

    Bound imports are an optional loader cache; the loader re-resolves imports
    without them, so they can be dropped to make room for a section header.
    """
    bound = _data_directory(pe, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT)
    if bound is None or not (bound.VirtualAddress or bound.Size):
        return
    b_start = bound.VirtualAddress
    b_end = b_start + bound.Size
    if not (b_start < end and start < b_end):
        return
    # The directory holds a file offset; clamp to the file before zeroing.
    z_start = min(b_start, len(pe.__data__))
    z_end = min(b_end, len(pe.__data__))
    safe_write(pe, z_start, b"\x00" * (z_end - z_start))
    _set_data_directory(pe, IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT, 0, 0)
    if hasattr(pe, "DIRECTORY_ENTRY_BOUND_IMPORT"):
        del pe.DIRECTORY_ENTRY_BOUND_IMPORT


def append_new_section(
    pe: pefile.PE,
    name: str,
    data: bytes,
    characteristics: int,
) -> None:
    """Add a new section.

    The new header goes in the 40 bytes after the section table. A bound-import
    directory in that window is dropped; any other non-zero byte there, or too
    little room before the first section's raw data, raises PEError.
    """
    fa = pe.OPTIONAL_HEADER.FileAlignment
    sa = pe.OPTIONAL_HEADER.SectionAlignment

    e_lfanew = pe.DOS_HEADER.e_lfanew
    section_table_start = e_lfanew + 4 + pe.FILE_HEADER.sizeof() + pe.FILE_HEADER.SizeOfOptionalHeader
    existing_headers_end = section_table_start + len(pe.sections) * SECTION_HEADER_SIZE
    window_end = existing_headers_end + SECTION_HEADER_SIZE

    raw_offsets = [s.PointerToRawData for s in pe.sections if s.PointerToRawData > 0]
    if not raw_offsets:
        raise PEError("No sections with valid raw data offsets; cannot determine header space.")
    first_raw = min(raw_offsets)
    available = first_raw - existing_headers_end
    if available < SECTION_HEADER_SIZE:
        raise PEError(
            f"No header space for new section (need {SECTION_HEADER_SIZE} bytes, have {available}). "
            "Consider enlarging SizeOfHeaders or use section slack instead."
        )

    _drop_bound_import_in(pe, existing_headers_end, window_end)
    if any(pe.__data__[existing_headers_end:window_end]):
        raise PEError(
            f"Header space [0x{existing_headers_end:x}..0x{window_end:x}) after the section "
            "table holds unknown data; refusing to overwrite it with a section header."
        )

    new_va = pe_math.align(
        max(s.VirtualAddress + pe_math.effective_virtual_size(s) for s in pe.sections), sa
    )

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
