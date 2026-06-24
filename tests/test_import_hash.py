# tests/test_import_hash.py
import struct
import pytest
import pefile
from src.core.pe_loader import load, fix_headers
from src.core.validator import post_validate
from src.techniques.import_hash import ImportHash
from src.utils.pe_math import ror13_hash
from src.utils.constants import HIGH_RISK_IMPORTS
from tests.conftest import write_and_reload, make_minimal_pe64


def test_import_hash_does_not_crash_on_no_imports(tmp_path):
    path = tmp_path / "pe.exe"
    path.write_bytes(make_minimal_pe64())
    pe = load(path)
    ImportHash().apply(pe)   # must not raise even with no imports
    fix_headers(pe)
    post_validate(pe)
    out = write_and_reload(pe)
    out.close()


def test_ror13_hash_used_in_import_hash_is_consistent():
    h1 = ror13_hash("VirtualAlloc")
    h2 = ror13_hash("VirtualAlloc")
    assert h1 == h2
    assert h1 != ror13_hash("ExitProcess")


def test_import_hash_output_parses(minimal_pe_path):
    pe = load(minimal_pe_path)
    ImportHash().apply(pe)
    fix_headers(pe)
    out = write_and_reload(pe)
    out.close()


def test_high_risk_imports_are_defined():
    assert "VirtualAlloc" in HIGH_RISK_IMPORTS
    assert "CreateThread" in HIGH_RISK_IMPORTS
    assert "WriteProcessMemory" in HIGH_RISK_IMPORTS
