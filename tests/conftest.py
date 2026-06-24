# tests/conftest.py
import struct
import pytest
import pefile
from pathlib import Path


def make_minimal_pe64(
    text_data: bytes = b"\xC3",
    rdata_data: bytes = b"TestString\x00" + b"AnotherLongString\x00",
) -> bytes:
    """Build a minimal valid PE64 entirely from struct.pack. No external tools needed."""
    FILE_ALIGN  = 0x200
    SECT_ALIGN  = 0x1000
    IMAGE_BASE  = 0x140000000

    def align_up(v, b):
        rem = v % b
        return v if rem == 0 else v + b - rem

    def pad(data: bytes) -> bytes:
        rem = len(data) % FILE_ALIGN
        return data if rem == 0 else data + b"\x00" * (FILE_ALIGN - rem)

    text_raw  = pad(text_data)
    rdata_raw = pad(rdata_data)

    SZ_HEADERS    = 0x200
    TEXT_VA       = 0x1000
    TEXT_RAW_OFF  = SZ_HEADERS
    RDATA_VA      = 0x2000
    RDATA_RAW_OFF = SZ_HEADERS + len(text_raw)
    SZ_IMAGE      = align_up(RDATA_VA + len(rdata_data), SECT_ALIGN)

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, 0x40)

    fh = struct.pack("<HHIIIHH",
        0x8664,     # Machine: x64
        2,          # NumberOfSections
        0,          # TimeDateStamp
        0, 0,       # PointerToSymbolTable, NumberOfSymbols
        240,        # SizeOfOptionalHeader
        0x0022,     # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    oh = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQIIxx",
        0x020B,            # Magic
        14, 0,             # LinkerVersion
        len(text_raw),     # SizeOfCode
        len(rdata_raw),    # SizeOfInitializedData
        0,                 # SizeOfUninitializedData
        TEXT_VA,           # AddressOfEntryPoint
        TEXT_VA,           # BaseOfCode
        IMAGE_BASE,        # ImageBase
        SECT_ALIGN,        # SectionAlignment
        FILE_ALIGN,        # FileAlignment
        6, 0,              # OS version
        0, 0,              # Image version
        6, 0,              # Subsystem version
        0,                 # Win32VersionValue
        SZ_IMAGE,          # SizeOfImage
        SZ_HEADERS,        # SizeOfHeaders
        0,                 # CheckSum
        3,                 # Subsystem: CUI
        0x8160,            # DllCharacteristics
        0x100000, 0x1000,  # StackReserve, StackCommit
        0x100000, 0x1000,  # HeapReserve, HeapCommit
        0,                 # LoaderFlags
        16,                # NumberOfRvaAndSizes
    )
    data_dirs = b"\x00" * 128

    def section_hdr(name, virt_size, virt_addr, raw_size, raw_off, chars):
        return struct.pack("<8sIIIIIIHHI",
            name.encode().ljust(8, b"\x00")[:8],
            virt_size, virt_addr, raw_size, raw_off,
            0, 0, 0, 0, chars,
        )

    text_hdr  = section_hdr(".text",  len(text_data),  TEXT_VA,  len(text_raw),  TEXT_RAW_OFF,  0x60000020)
    rdata_hdr = section_hdr(".rdata", len(rdata_data), RDATA_VA, len(rdata_raw), RDATA_RAW_OFF, 0x40000040)

    hdr = bytearray(SZ_HEADERS)
    hdr[0x00:0x40] = dos
    hdr[0x40:0x44] = b"PE\x00\x00"
    hdr[0x44:0x58] = fh
    hdr[0x58:0xC8] = oh
    hdr[0xC8:0x148] = data_dirs
    hdr[0x148:0x170] = text_hdr
    hdr[0x170:0x198] = rdata_hdr

    return bytes(hdr) + text_raw + rdata_raw


@pytest.fixture
def minimal_pe_bytes():
    return make_minimal_pe64()


@pytest.fixture
def minimal_pe_path(tmp_path, minimal_pe_bytes):
    p = tmp_path / "test.exe"
    p.write_bytes(minimal_pe_bytes)
    return p


def write_and_reload(pe: pefile.PE) -> pefile.PE:
    """Serialize pe to bytes and reload -- verifies pefile can parse the result."""
    data = pe.write()
    return pefile.PE(data=data)
