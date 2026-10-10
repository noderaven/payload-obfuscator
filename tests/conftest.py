# tests/conftest.py
from __future__ import annotations

import struct
from collections.abc import Sequence

import pytest
import pefile
from pathlib import Path

DEBUG_TIMESTAMP = 0x12345678
EXPORT_TIMESTAMP = 0x12345678
RICH_KEY = 0xA5A5A5A5

_FILE_ALIGN = 0x200
_SECT_ALIGN = 0x1000
_IMAGE_BASE = 0x140000000
_HEADER_HEADROOM = 40          # room for one appended section header
_BOUND_IMPORT_DLL = b"KERNEL32.dll"
_BOUND_IMPORT_TIMESTAMP = 0x12345678
_RICH_ENTRIES = ((0x01047A64, 1), (0x01037A64, 3))  # (comp.id, count) pairs
_DOS_STUB_MESSAGE = b"This program cannot be run in DOS mode.\r\r\n$"
_EXPORT_DLL_NAME = b"fixture.exe\x00"


def _align_up(v: int, b: int) -> int:
    rem = v % b
    return v if rem == 0 else v + b - rem


def _pad(data: bytes, boundary: int = _FILE_ALIGN) -> bytes:
    return data + b"\x00" * (_align_up(len(data), boundary) - len(data))


class _RdataBuilder:
    """Accumulates .rdata contents and hands out RVAs for appended structures."""

    def __init__(self, base_rva: int, initial: bytes):
        self.base_rva = base_rva
        self.buf = bytearray(initial)

    def reserve(self, size: int, align: int = 8) -> int:
        """Append `size` zero bytes at an `align`-aligned offset; return their RVA."""
        self.buf += b"\x00" * (_align_up(len(self.buf), align) - len(self.buf))
        rva = self.base_rva + len(self.buf)
        self.buf += b"\x00" * size
        return rva

    def put(self, data: bytes, align: int = 8) -> int:
        rva = self.reserve(len(data), align)
        self.write(rva, data)
        return rva

    def write(self, rva: int, data: bytes) -> None:
        off = rva - self.base_rva
        self.buf[off:off + len(data)] = data

    def pack(self, fmt: str, rva: int, *values) -> None:
        struct.pack_into(fmt, self.buf, rva - self.base_rva, *values)


def _add_imports(rd: _RdataBuilder, imports: dict[str, list[str]]) -> tuple[tuple[int, int], tuple[int, int]]:
    """Append the import descriptor table, ILTs, IATs, hint/name entries and DLL names.

    Returns the (rva, size) pairs for DATA_DIRECTORY[1] and DATA_DIRECTORY[12].
    """
    dlls = list(imports.items())
    desc_size = (len(dlls) + 1) * 20
    desc_rva = rd.reserve(desc_size)
    ilt_rvas = [rd.reserve((len(names) + 1) * 8) for _, names in dlls]
    iat_rvas = [rd.reserve((len(names) + 1) * 8) for _, names in dlls]
    iat_start = iat_rvas[0] if iat_rvas else desc_rva
    iat_end = rd.base_rva + len(rd.buf)
    hint_name_rvas = [
        [rd.put(struct.pack("<H", 0) + name.encode("ascii") + b"\x00", align=2) for name in names]
        for _, names in dlls
    ]
    dll_name_rvas = [rd.put(dll.encode("ascii") + b"\x00", align=2) for dll, _ in dlls]

    for i in range(len(dlls)):
        for j, hn_rva in enumerate(hint_name_rvas[i]):
            rd.pack("<Q", ilt_rvas[i] + j * 8, hn_rva)
            rd.pack("<Q", iat_rvas[i] + j * 8, hn_rva)
        rd.pack("<IIIII", desc_rva + i * 20,
                ilt_rvas[i],       # OriginalFirstThunk
                0,                 # TimeDateStamp
                0,                 # ForwarderChain
                dll_name_rvas[i],  # Name
                iat_rvas[i])       # FirstThunk
    return (desc_rva, desc_size), (iat_start, iat_end - iat_start)


def _add_exports(rd: _RdataBuilder, exports: list[str], func_rva: int) -> tuple[int, int]:
    """Append an export directory whose functions all point at `func_rva`."""
    n = len(exports)
    dir_rva = rd.reserve(40)
    eat_rva = rd.reserve(4 * n, align=4)
    names_rva = rd.reserve(4 * n, align=4)
    ords_rva = rd.reserve(2 * n, align=2)
    dll_name_rva = rd.put(_EXPORT_DLL_NAME, align=1)
    name_rvas = {name: rd.put(name.encode("ascii") + b"\x00", align=1) for name in exports}

    for i in range(n):
        rd.pack("<I", eat_rva + 4 * i, func_rva)
    # The name pointer table must be sorted; each name maps to its function index.
    for k, (ordinal, name) in enumerate(sorted(enumerate(exports), key=lambda t: t[1].encode("ascii"))):
        rd.pack("<I", names_rva + 4 * k, name_rvas[name])
        rd.pack("<H", ords_rva + 2 * k, ordinal)
    rd.pack("<IIHHIIIIIII", dir_rva,
            0,                 # Characteristics
            EXPORT_TIMESTAMP,  # TimeDateStamp
            0, 0,              # Major/MinorVersion
            dll_name_rva,      # Name
            1,                 # Base
            n,                 # NumberOfFunctions
            n,                 # NumberOfNames
            eat_rva,           # AddressOfFunctions
            names_rva,         # AddressOfNames
            ords_rva)          # AddressOfNameOrdinals
    return dir_rva, rd.base_rva + len(rd.buf) - dir_rva


def _add_debug(rd: _RdataBuilder, pdb: str, rdata_raw_off: int) -> tuple[int, int]:
    """Append one CODEVIEW debug directory entry followed by its RSDS record."""
    entry_rva = rd.reserve(28)
    rsds = (b"RSDS" + bytes(range(16)) + struct.pack("<I", 1)
            + pdb.encode("ascii") + b"\x00")
    rsds_rva = rd.put(rsds, align=4)
    rd.pack("<IIHHIIII", entry_rva,
            0,                 # Characteristics
            DEBUG_TIMESTAMP,   # TimeDateStamp
            0, 0,              # Major/MinorVersion
            2,                 # Type: IMAGE_DEBUG_TYPE_CODEVIEW
            len(rsds),         # SizeOfData
            rsds_rva,          # AddressOfRawData
            rdata_raw_off + rsds_rva - rd.base_rva)  # PointerToRawData
    return entry_rva, 28


def _rich_block() -> bytes:
    """DanS marker, padding dwords and entries, all XORed with RICH_KEY, then Rich + key."""
    k = RICH_KEY
    dwords = [0x536E6144 ^ k, k, k, k]  # "DanS" ^ key, then three zero dwords ^ key
    for compid, count in _RICH_ENTRIES:
        dwords += [compid ^ k, count ^ k]
    return struct.pack(f"<{len(dwords)}I", *dwords) + b"Rich" + struct.pack("<I", k)


def _bound_import_block() -> bytes:
    """One IMAGE_BOUND_IMPORT_DESCRIPTOR, a null descriptor, then the module name.

    OffsetModuleName is relative to the start of the bound-import directory.
    """
    return (struct.pack("<IHH", _BOUND_IMPORT_TIMESTAMP, 16, 0)
            + b"\x00" * 8
            + _BOUND_IMPORT_DLL + b"\x00")


def make_minimal_pe64(
    text_data: bytes = b"\xC3",
    rdata_data: bytes = b"TestString\x00" + b"AnotherLongString\x00",
    *,
    imports: dict[str, list[str]] | None = None,
    exports: list[str] | None = None,
    debug_pdb: str | None = None,
    rich_header: bool = False,
    bound_import: bool = False,
    overlay: bytes = b"",
    certificate: bytes = b"",
    extra_sections: Sequence[tuple[str, bytes]] = (),
) -> bytes:
    """Build a valid PE64 entirely from struct.pack. No external tools needed.

    With the defaults the image is 0x600 bytes: headers 0x200 (section table at
    0x148), .text raw at 0x200 and .rdata raw at 0x400. The keyword arguments add
    loader structures (imports, exports, debug, bound imports, a certificate) and
    artefacts (Rich header, overlay, extra sections) one at a time.
    """
    e_lfanew = 0x100 if rich_header else 0x40
    n_sections = 2 + len(extra_sections)
    sect_table_off = e_lfanew + 4 + 20 + 240
    sect_table_end = sect_table_off + 40 * n_sections
    bound_block = _bound_import_block() if bound_import else b""
    header_data_end = sect_table_end + len(bound_block)
    size_of_headers = max(_FILE_ALIGN, _align_up(header_data_end + _HEADER_HEADROOM, _FILE_ALIGN))

    data_dirs = bytearray(128)

    def set_dir(index: int, rva: int, size: int) -> None:
        struct.pack_into("<II", data_dirs, index * 8, rva, size)

    text_va = _SECT_ALIGN
    text_raw = _pad(text_data)
    text_raw_off = size_of_headers

    rdata_va = _align_up(text_va + max(len(text_data), 1), _SECT_ALIGN)
    rdata_raw_off = text_raw_off + len(text_raw)
    rd = _RdataBuilder(rdata_va, rdata_data)
    if imports:
        import_dir, iat_dir = _add_imports(rd, imports)
        set_dir(1, *import_dir)
        set_dir(12, *iat_dir)
    if exports:
        set_dir(0, *_add_exports(rd, exports, text_va))
    if debug_pdb is not None:
        set_dir(6, *_add_debug(rd, debug_pdb, rdata_raw_off))
    rdata_full = bytes(rd.buf)
    rdata_raw = _pad(rdata_full)

    # (name, virtual size, VA, raw bytes, raw offset, characteristics)
    sections = [
        (".text", len(text_data), text_va, text_raw, text_raw_off, 0x60000020),
        (".rdata", len(rdata_full), rdata_va, rdata_raw, rdata_raw_off, 0x40000040),
    ]
    for name, data in extra_sections:
        _, prev_vs, prev_va, prev_raw, prev_off, _ = sections[-1]
        sections.append((name, len(data), _align_up(prev_va + max(prev_vs, 1), _SECT_ALIGN),
                         _pad(data), prev_off + len(prev_raw), 0x40000040))

    _, last_vs, last_va, last_raw, last_off, _ = sections[-1]
    size_of_image = _align_up(last_va + max(last_vs, 1), _SECT_ALIGN)
    sections_end = last_off + len(last_raw)

    if bound_import:
        set_dir(11, sect_table_end, len(bound_block))

    tail = bytearray(overlay)
    if certificate:
        tail += b"\x00" * (_align_up(sections_end + len(tail), 8) - sections_end - len(tail))
        cert_off = sections_end + len(tail)
        tail += struct.pack("<IHH", 8 + len(certificate), 0x0200, 2) + certificate
        set_dir(4, cert_off, 8 + len(certificate))

    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 60, e_lfanew)

    fh = struct.pack("<HHIIIHH",
        0x8664,     # Machine: x64
        n_sections, # NumberOfSections
        0,          # TimeDateStamp
        0, 0,       # PointerToSymbolTable, NumberOfSymbols
        240,        # SizeOfOptionalHeader
        0x0022,     # Characteristics: EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE
    )

    oh = struct.pack("<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x020B,                                  # Magic
        14, 0,                                   # LinkerVersion
        len(text_raw),                           # SizeOfCode
        sum(len(s[3]) for s in sections[1:]),    # SizeOfInitializedData
        0,                                       # SizeOfUninitializedData
        text_va,                                 # AddressOfEntryPoint
        text_va,                                 # BaseOfCode
        _IMAGE_BASE,                             # ImageBase
        _SECT_ALIGN,                             # SectionAlignment
        _FILE_ALIGN,                             # FileAlignment
        6, 0,                                    # OS version
        0, 0,                                    # Image version
        6, 0,                                    # Subsystem version
        0,                                       # Win32VersionValue
        size_of_image,                           # SizeOfImage
        size_of_headers,                         # SizeOfHeaders
        0,                                       # CheckSum
        3,                                       # Subsystem: CUI
        0x8160,                                  # DllCharacteristics
        0x100000, 0x1000,                        # StackReserve, StackCommit
        0x100000, 0x1000,                        # HeapReserve, HeapCommit
        0,                                       # LoaderFlags
        16,                                      # NumberOfRvaAndSizes
    )
    assert len(oh) == 112

    def section_hdr(name, virt_size, virt_addr, raw_size, raw_off, chars):
        return struct.pack("<8sIIIIIIHHI",
            name.encode().ljust(8, b"\x00")[:8],
            virt_size, virt_addr, raw_size, raw_off,
            0, 0, 0, 0, chars,
        )

    sect_table = b"".join(
        section_hdr(name, vs, va, len(raw), off, chars)
        for name, vs, va, raw, off, chars in sections
    )

    hdr = bytearray(size_of_headers)
    hdr[0x00:0x40] = dos
    if rich_header:
        hdr[0x40:0x40 + len(_DOS_STUB_MESSAGE)] = _DOS_STUB_MESSAGE
        rich = _rich_block()
        hdr[0x80:0x80 + len(rich)] = rich
    pe_off = e_lfanew
    hdr[pe_off:pe_off + 4] = b"PE\x00\x00"
    hdr[pe_off + 4:pe_off + 24] = fh
    hdr[pe_off + 24:pe_off + 136] = oh
    hdr[pe_off + 136:pe_off + 264] = data_dirs
    hdr[sect_table_off:sect_table_end] = sect_table
    hdr[sect_table_end:header_data_end] = bound_block
    assert len(hdr) == size_of_headers

    return bytes(hdr) + b"".join(s[3] for s in sections) + bytes(tail)


@pytest.fixture
def minimal_pe_bytes():
    return make_minimal_pe64()


@pytest.fixture
def minimal_pe_path(tmp_path, minimal_pe_bytes):
    p = tmp_path / "test.exe"
    p.write_bytes(minimal_pe_bytes)
    return p


@pytest.fixture
def full_pe_path(tmp_path) -> Path:
    """A PE64 with every structure the obfuscation techniques must preserve."""
    p = tmp_path / "full.exe"
    p.write_bytes(make_minimal_pe64(
        imports={"KERNEL32.dll": ["VirtualAlloc", "GetProcAddress", "ExitProcess"]},
        exports=["ExportedFunction"],
        debug_pdb=r"C:\build\secret\project.pdb",
        rich_header=True,
        bound_import=True,
        overlay=b"OVERLAY!" * 8,
        certificate=b"\x30\x82" + b"\x00" * 30,
    ))
    return p


def write_and_reload(pe: pefile.PE) -> pefile.PE:
    """Serialize pe to bytes and reload -- verifies pefile can parse the result."""
    data = pe.write()
    return pefile.PE(data=data)
