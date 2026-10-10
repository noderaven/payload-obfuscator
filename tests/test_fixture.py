"""Tests for the PE fixture builder in tests/conftest.py."""
import struct

import pefile

from tests.conftest import DEBUG_TIMESTAMP, EXPORT_TIMESTAMP, make_minimal_pe64


def test_default_fixture_layout():
    d = make_minimal_pe64()
    pe = pefile.PE(data=d)
    assert len(d) == 0x600
    assert pe.get_data(0x1000, 1) == b"\xC3"
    assert [s.PointerToRawData for s in pe.sections] == [0x200, 0x400]
    assert pe.get_data(0x2000, 10) == b"TestString"


def test_full_fixture_parses_every_feature(full_pe_path):
    pe = pefile.PE(str(full_pe_path))
    imp = pe.DIRECTORY_ENTRY_IMPORT[0]
    assert imp.dll == b"KERNEL32.dll"
    assert [i.name for i in imp.imports] == [b"VirtualAlloc", b"GetProcAddress", b"ExitProcess"]
    assert [e.name for e in pe.DIRECTORY_ENTRY_EXPORT.symbols] == [b"ExportedFunction"]
    assert pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp == EXPORT_TIMESTAMP
    dbg = pe.DIRECTORY_ENTRY_DEBUG[0]
    assert dbg.struct.TimeDateStamp == DEBUG_TIMESTAMP
    assert dbg.entry.PdbFileName.rstrip(b"\x00") == rb"C:\build\secret\project.pdb"
    assert pe.parse_rich_header() is not None
    assert pe.DOS_HEADER.e_lfanew == 0x100
    dir11 = pe.OPTIONAL_HEADER.DATA_DIRECTORY[11]
    assert dir11.VirtualAddress != 0
    # Bound-import directory must cover both descriptors (8+8) and the name (13 bytes).
    assert dir11.Size == 29
    # Import descriptor must sit directly after the 29-byte rdata_data (aligned to 8).
    _rdata_data_len = len(b"TestString\x00" + b"AnotherLongString\x00")  # 29
    _rdata_base = 0x2000
    _expected_idata_va = _rdata_base + ((_rdata_data_len + 7) & ~7)
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress == _expected_idata_va
    # .rdata Misc_VirtualSize must cover the full extent of the RSDS record.
    rdata_sec = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".rdata")
    dbg = pe.DIRECTORY_ENTRY_DEBUG[0]
    rsds_end_rva = dbg.struct.AddressOfRawData + dbg.struct.SizeOfData - _rdata_base
    assert rdata_sec.Misc_VirtualSize >= rsds_end_rva
    sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    assert sec.Size == 8 + 32
    assert struct.unpack_from("<IHH", pe.__data__, sec.VirtualAddress) == (40, 0x0200, 2)
    assert pe.get_overlay().startswith(b"OVERLAY!" * 8)
    pe.close()


def test_extra_sections_are_appended():
    pe = pefile.PE(data=make_minimal_pe64(extra_sections=[(".data", b"x" * 16), (".pdata", b"y" * 16)]))
    assert [s.Name.rstrip(b"\x00") for s in pe.sections] == [b".text", b".rdata", b".data", b".pdata"]
