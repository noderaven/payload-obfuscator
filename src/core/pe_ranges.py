"""File-offset ranges that hold data the Windows loader reads.

Techniques that rewrite section bytes must leave these ranges alone, or the
output stops loading (missing imports, broken exports, corrupt debug data).
"""
from __future__ import annotations
from bisect import bisect_left
import pefile

_SECURITY_DIR = 4  # IMAGE_DIRECTORY_ENTRY_SECURITY holds a file offset, not an RVA


def _thunk_size(pe: pefile.PE) -> int:
    return 8 if pe.OPTIONAL_HEADER.Magic == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4


def _rva_range(pe: pefile.PE, rva: int, size: int) -> tuple[int, int] | None:
    """Map [rva, rva+size) to a file range; None when empty or unmappable."""
    if not rva or size <= 0:
        return None
    try:
        off = pe.get_offset_from_rva(rva)
    except pefile.PEFormatError:
        return None
    if off is None:
        return None
    return off, off + size


def _import_ranges(pe: pefile.PE, entries, name_field: str, ilt_field: str,
                   iat_field: str) -> list[tuple[int, int] | None]:
    """DLL name, hint/name entries and both thunk arrays of each import entry."""
    out: list[tuple[int, int] | None] = []
    thunk = _thunk_size(pe)
    for entry in entries:
        if entry.dll:
            out.append(_rva_range(pe, getattr(entry.struct, name_field), len(entry.dll) + 1))
        n_thunks = len(entry.imports) + 1
        for field in (ilt_field, iat_field):
            out.append(_rva_range(pe, getattr(entry.struct, field), n_thunks * thunk))
        for imp in entry.imports:
            if imp.name and imp.name_offset is not None:
                # hint (2 bytes), the name, and its NUL
                out.append((imp.name_offset - 2, imp.name_offset + len(imp.name) + 1))
    return out


def protected_file_ranges(pe: pefile.PE) -> list[tuple[int, int]]:
    """Return sorted, merged, half-open file-offset ranges of loader-needed data.

    Covers every non-empty data directory, the import and delay-import DLL
    names, hint/name entries and thunk arrays, the export DLL name and export
    names, and the raw data of each debug entry. Unmappable RVAs are skipped.
    """
    found: list[tuple[int, int] | None] = []

    for index, d in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
        if not d.VirtualAddress or not d.Size:
            continue
        if index == _SECURITY_DIR:
            found.append((d.VirtualAddress, d.VirtualAddress + d.Size))
        else:
            found.append(_rva_range(pe, d.VirtualAddress, d.Size))

    found += _import_ranges(pe, getattr(pe, "DIRECTORY_ENTRY_IMPORT", []),
                            "Name", "OriginalFirstThunk", "FirstThunk")
    found += _import_ranges(pe, getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []),
                            "szName", "pINT", "pIAT")

    export = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export is not None:
        dll_name = pe.get_string_at_rva(export.struct.Name) if export.struct.Name else b""
        if dll_name:
            found.append(_rva_range(pe, export.struct.Name, len(dll_name) + 1))
        for sym in export.symbols:
            if sym.name and sym.name_offset is not None:
                found.append((sym.name_offset, sym.name_offset + len(sym.name) + 1))

    for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        ptr, size = dbg.struct.PointerToRawData, dbg.struct.SizeOfData
        if ptr and size:
            found.append((ptr, ptr + size))

    merged: list[tuple[int, int]] = []
    for start, end in sorted(r for r in found if r is not None and r[1] > r[0]):
        if merged and start <= merged[-1][1]:
            if end > merged[-1][1]:
                merged[-1] = (merged[-1][0], end)
        else:
            merged.append((start, end))
    return merged


def overlaps(ranges: list[tuple[int, int]], start: int, end: int) -> bool:
    """True if [start, end) intersects any range in sorted, merged `ranges`."""
    if end <= start:
        return False
    # Last range whose start is below `end` is the only candidate.
    idx = bisect_left(ranges, (end,)) - 1
    return idx >= 0 and ranges[idx][1] > start
