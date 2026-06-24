"""PE arithmetic utilities. No pefile imports allowed here -- pure math."""
from __future__ import annotations
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    import pefile


def align(value: int, boundary: int) -> int:
    """Round value up to the nearest multiple of boundary."""
    if boundary <= 0:
        return value
    rem = value % boundary
    return value if rem == 0 else value + (boundary - rem)


def rva_to_offset(pe: "pefile.PE", rva: int) -> int:
    """Convert a virtual address (RVA) to a file offset."""
    for section in pe.sections:
        start = section.VirtualAddress
        end = start + section.SizeOfRawData
        if start <= rva < end:
            return rva - start + section.PointerToRawData
    raise ValueError(f"RVA 0x{rva:08x} does not fall within any section")


def offset_to_rva(pe: "pefile.PE", offset: int) -> int:
    """Convert a file offset to an RVA."""
    for section in pe.sections:
        start = section.PointerToRawData
        end = start + section.SizeOfRawData
        if start <= offset < end:
            return offset - start + section.VirtualAddress
    raise ValueError(f"File offset 0x{offset:08x} does not fall within any section")


def section_slack(section: "pefile.SectionStructure") -> int:
    """Return unused bytes at the end of a section's raw data."""
    return max(0, section.SizeOfRawData - section.Misc_VirtualSize)


def find_section_by_name(pe: "pefile.PE", name: str):
    """Return the first section with the given name, or None."""
    encoded = name.encode("ascii").ljust(8, b"\x00")[:8]
    for section in pe.sections:
        if section.Name == encoded:
            return section
    return None


def find_executable_section(pe: "pefile.PE"):
    """Return the first section with IMAGE_SCN_MEM_EXECUTE, or None."""
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    for section in pe.sections:
        if section.Characteristics & IMAGE_SCN_MEM_EXECUTE:
            return section
    return None


def _ror32(value: int, count: int) -> int:
    count %= 32
    return ((value >> count) | (value << (32 - count))) & 0xFFFFFFFF


def ror13_hash(name: str) -> int:
    """ROR-13 API hash. Case-insensitive. Must match api_hasher_x64 stub exactly."""
    h = 0
    for c in name.upper():
        h = _ror32(h, 13)
        h = (h + ord(c)) & 0xFFFFFFFF
    return h
