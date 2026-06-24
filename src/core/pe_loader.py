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
