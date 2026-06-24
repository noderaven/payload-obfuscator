# tests/test_section_rename.py
import pefile
import pytest
from src.core.pe_loader import load, fix_headers
from src.core.validator import post_validate
from src.techniques.section_rename import SectionRename
from src.utils.constants import MSVC_SECTION_NAMES, CRITICAL_SECTION_NAMES
from tests.conftest import write_and_reload, make_minimal_pe64


def test_section_rename_produces_valid_pe(minimal_pe_path, tmp_path):
    pe = load(minimal_pe_path)
    SectionRename().apply(pe)
    fix_headers(pe)
    post_validate(pe)
    out = write_and_reload(pe)
    assert out.FILE_HEADER.NumberOfSections == 2
    out.close()


def test_section_rename_uses_msvc_names(minimal_pe_path):
    pe = load(minimal_pe_path)
    SectionRename().apply(pe)
    for section in pe.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        assert name in MSVC_SECTION_NAMES, f"Unexpected section name: {name!r}"
    pe.close()


def test_section_rename_preserves_critical_sections(tmp_path):
    import struct
    data = bytearray(make_minimal_pe64())
    # Rename second section (.rdata at 0x170) to .rsrc
    data[0x170:0x178] = b".rsrc\x00\x00\x00"
    path = tmp_path / "with_rsrc.exe"
    path.write_bytes(data)
    pe = load(path)
    SectionRename().apply(pe)
    names = [s.Name.rstrip(b"\x00").decode() for s in pe.sections]
    assert ".rsrc" in names, "Critical .rsrc section was renamed"
    pe.close()


def test_section_rename_names_written_to_pe_data(minimal_pe_path):
    pe = load(minimal_pe_path)
    SectionRename().apply(pe)
    raw = pe.write()
    pe.close()
    pe2 = pefile.PE(data=raw)
    for section in pe2.sections:
        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")
        assert name in MSVC_SECTION_NAMES
    pe2.close()
