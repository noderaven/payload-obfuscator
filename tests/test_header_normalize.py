import struct
import pefile
import pytest
from src.core.pe_loader import load, fix_headers
from src.techniques.header_normalize import HeaderNormalize
from tests.conftest import write_and_reload, make_minimal_pe64


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


def test_header_normalize_zeros_debug_directory(minimal_pe_path):
    pe = load(minimal_pe_path)
    HeaderNormalize().apply(pe)
    debug_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6]
    assert debug_dir.VirtualAddress == 0
    assert debug_dir.Size == 0


def test_header_normalize_output_parses(minimal_pe_path):
    pe = load(minimal_pe_path)
    HeaderNormalize().apply(pe)
    fix_headers(pe)
    out = write_and_reload(pe)
    assert out.OPTIONAL_HEADER.Magic == 0x20B
    out.close()
