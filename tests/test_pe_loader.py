# tests/test_pe_loader.py
import pytest
import pefile
from pathlib import Path
from src.core.pe_loader import load, save, safe_write, append_section_data, PEError, PEWriteError
from tests.conftest import write_and_reload


def test_load_returns_pe_object(minimal_pe_path):
    pe = load(minimal_pe_path)
    assert isinstance(pe, pefile.PE)
    assert pe.OPTIONAL_HEADER.Magic == 0x20B  # PE32+
    pe.close()


def test_load_raises_on_invalid_file(tmp_path):
    bad = tmp_path / "bad.exe"
    bad.write_bytes(b"not a pe file")
    with pytest.raises(PEError):
        load(bad)


def test_save_writes_parseable_file(minimal_pe_path, tmp_path):
    pe = load(minimal_pe_path)
    out = tmp_path / "out.exe"
    save(pe, out)
    pe.close()
    assert out.exists()
    pe2 = pefile.PE(str(out))
    assert pe2.OPTIONAL_HEADER.Magic == 0x20B
    pe2.close()


def test_safe_write_modifies_bytes(minimal_pe_path):
    pe = load(minimal_pe_path)
    offset = pe.sections[0].PointerToRawData
    safe_write(pe, offset, b"\xAA\xBB\xCC\xDD")
    assert bytes(pe.__data__[offset:offset + 4]) == b"\xAA\xBB\xCC\xDD"
    pe.close()


def test_safe_write_raises_on_oob(minimal_pe_path):
    pe = load(minimal_pe_path)
    with pytest.raises(PEWriteError):
        safe_write(pe, len(pe.__data__) - 2, b"\x00" * 10)
    pe.close()


def test_append_section_data_grows_file(minimal_pe_path):
    pe = load(minimal_pe_path)
    original_size = len(pe.__data__)
    payload = b"X" * 100
    offset = append_section_data(pe, payload)
    assert len(pe.__data__) > original_size
    assert bytes(pe.__data__[offset:offset + len(payload)]) == payload
    pe.close()


def test_append_section_data_is_file_aligned(minimal_pe_path):
    pe = load(minimal_pe_path)
    fa = pe.OPTIONAL_HEADER.FileAlignment
    offset = append_section_data(pe, b"Y" * 7)
    assert len(pe.__data__) % fa == 0
    pe.close()
