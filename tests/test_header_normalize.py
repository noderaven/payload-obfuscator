import struct
import pefile
import pytest
from src.core.pe_loader import load, fix_headers
from src.techniques.header_normalize import HeaderNormalize
from tests.conftest import (
    DEBUG_TIMESTAMP,
    EXPORT_TIMESTAMP,
    make_minimal_pe64,
    write_and_reload,
)


def test_header_normalize_zeros_timestamp(minimal_pe_path):
    pe = load(minimal_pe_path)
    pe.FILE_HEADER.TimeDateStamp = 0xDEADBEEF
    HeaderNormalize().apply(pe)
    assert pe.FILE_HEADER.TimeDateStamp == 0


def test_header_normalize_does_not_crash_without_rich_header(tmp_path):
    data = make_minimal_pe64()
    path = tmp_path / "pe.exe"
    path.write_bytes(data)
    pe = load(path)
    HeaderNormalize().apply(pe)  # must not raise
    pe.close()


def _load_bytes(data: bytes) -> pefile.PE:
    return pefile.PE(data=data)


def test_rich_header_removed_dos_header_intact(full_pe_path):
    pe = load(full_pe_path)
    e_lfanew = pe.DOS_HEADER.e_lfanew
    assert pe.parse_rich_header() is not None
    dos_before = bytes(pe.__data__[:0x80])  # DOS header and stub, up to the Rich block
    HeaderNormalize().apply(pe)
    # Check the raw bytes too: pe.write() would restore DOS_HEADER from its struct.
    raw = bytes(pe.__data__)
    assert raw[:4] == dos_before[:4] and raw[0x40:0x80] == dos_before[0x40:0x80]
    data = bytes(pe.write())
    assert data[:2] == b"MZ"
    assert struct.unpack_from("<I", data, 0x3C)[0] == e_lfanew
    assert b"Rich" not in data[0x40:e_lfanew]
    assert pefile.PE(data=data).parse_rich_header() is None
    pe.close()


def test_corrupt_rich_header_left_untouched():
    data = bytearray(make_minimal_pe64(rich_header=True))
    data[0x80:0x84] = b"\x00" * 4  # kill the DanS marker
    pe = _load_bytes(bytes(data))
    before = bytes(pe.__data__[0x40:0x100])
    HeaderNormalize()._strip_rich_header(pe)
    assert bytes(pe.__data__[0x40:0x100]) == before


def test_debug_data_and_pdb_path_wiped(full_pe_path):
    pe = load(full_pe_path)
    entry_off = pe.DIRECTORY_ENTRY_DEBUG[0].struct.get_file_offset()
    assert bytes(pe.__data__[entry_off + 4:entry_off + 8]) == struct.pack("<I", DEBUG_TIMESTAMP)
    HeaderNormalize().apply(pe)
    data = bytes(pe.write())
    assert rb"project.pdb" not in data
    assert b"RSDS" not in data
    out = pefile.PE(data=data)
    debug_dir = out.OPTIONAL_HEADER.DATA_DIRECTORY[6]
    assert (debug_dir.VirtualAddress, debug_dir.Size) == (0, 0)
    assert data[entry_off + 4:entry_off + 8] != struct.pack("<I", DEBUG_TIMESTAMP)
    assert not hasattr(out, "DIRECTORY_ENTRY_DEBUG")
    out.close()
    pe.close()


def test_export_timestamp_zeroed(full_pe_path):
    pe = load(full_pe_path)
    assert pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp == EXPORT_TIMESTAMP
    HeaderNormalize().apply(pe)
    out = pefile.PE(data=pe.write())
    assert out.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp == 0
    assert [e.name for e in out.DIRECTORY_ENTRY_EXPORT.symbols] == [b"ExportedFunction"]
    out.close()
    pe.close()


def test_few_data_directories_no_crash(full_pe_path):
    pe = load(full_pe_path)
    pe.OPTIONAL_HEADER.NumberOfRvaAndSizes = 5
    del pe.OPTIONAL_HEADER.DATA_DIRECTORY[5:]
    HeaderNormalize().apply(pe)  # must not raise
    pe.close()


def test_header_normalize_output_parses(minimal_pe_path):
    pe = load(minimal_pe_path)
    HeaderNormalize().apply(pe)
    fix_headers(pe)
    out = write_and_reload(pe)
    assert out.OPTIONAL_HEADER.Magic == 0x20B
    out.close()
