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


def _section_names(pe):
    return [s.Name.rstrip(b"\x00").decode("ascii", errors="replace") for s in pe.sections]


def test_rename_never_assigns_critical_names():
    raw = make_minimal_pe64()
    for _ in range(50):
        pe = pefile.PE(data=raw)
        SectionRename().apply(pe)
        for name in _section_names(pe):
            assert name not in CRITICAL_SECTION_NAMES, f"Assigned critical name {name!r}"
        pe.close()


def test_rename_names_unique_with_many_sections():
    extra = [(n, b"z") for n in [".data", ".pdata", ".rsrc", ".reloc", ".gfids", ".00cfg", ".foo"]]
    raw = make_minimal_pe64(extra_sections=extra)
    before = _section_names(pefile.PE(data=raw))
    for _ in range(50):
        pe = pefile.PE(data=raw)
        SectionRename().apply(pe)
        names = _section_names(pe)
        assert len(names) == len(set(names)), f"Duplicate section names: {names}"
        for critical in (".rsrc", ".reloc"):
            assert names.count(critical) == 1
            assert names.index(critical) == before.index(critical)
        pe.close()
