# tests/test_validator.py
import pytest
import pefile
from src.core.validator import pre_validate, post_validate, ValidationError
from src.core.pe_loader import load, fix_headers
from tests.conftest import make_minimal_pe64


def test_pre_validate_accepts_valid_pe64(minimal_pe_path):
    pe = load(minimal_pe_path)
    pre_validate(pe)   # must not raise
    pe.close()


def test_pre_validate_rejects_wrong_magic(tmp_path):
    data = bytearray(make_minimal_pe64())
    # Corrupt the optional header Magic to 0x10B (PE32)
    # Magic is at e_lfanew(0x40) + 4(PE sig) + 20(FILE_HDR) = 0x58
    data[0x58:0x5A] = b"\x0B\x01"
    bad = tmp_path / "bad.exe"
    bad.write_bytes(data)
    pe = load(bad)
    with pytest.raises(ValidationError, match="PE32\\+"):
        pre_validate(pe)
    pe.close()


def test_post_validate_accepts_fixed_pe(minimal_pe_path):
    pe = load(minimal_pe_path)
    fix_headers(pe)
    post_validate(pe)  # must not raise
    pe.close()
