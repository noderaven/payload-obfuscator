# tests/test_junk_sections.py
import pefile
import pytest
from src.core.pe_loader import load, fix_headers
from src.core.validator import post_validate
from src.techniques.base import TechniqueError
from src.techniques.junk_sections import JunkSections, _DECOY_NAMES
from src.techniques.section_rename import SectionRename
from tests.conftest import write_and_reload, make_minimal_pe64


def test_junk_sections_adds_one_section(minimal_pe_path):
    pe = load(minimal_pe_path)
    original = len(pe.sections)
    JunkSections().apply(pe)
    fix_headers(pe)
    out = write_and_reload(pe)
    assert out.FILE_HEADER.NumberOfSections == original + 1
    out.close()


def test_junk_section_is_non_executable(minimal_pe_path):
    pe = load(minimal_pe_path)
    JunkSections().apply(pe)
    fix_headers(pe)
    raw = pe.write()
    pe.close()
    pe2 = pefile.PE(data=raw)
    IMAGE_SCN_MEM_EXECUTE = 0x20000000
    new_section = pe2.sections[-1]
    assert not (new_section.Characteristics & IMAGE_SCN_MEM_EXECUTE)
    pe2.close()


def test_junk_sections_output_parses(minimal_pe_path):
    pe = load(minimal_pe_path)
    JunkSections().apply(pe)
    fix_headers(pe)
    post_validate(pe)
    out = write_and_reload(pe)
    out.close()


def _section_names(pe):
    return [s.Name.rstrip(b"\x00").decode("ascii", errors="replace") for s in pe.sections]


def test_junk_section_name_unused():
    raw = make_minimal_pe64(extra_sections=[(".gfids", b"z"), (".00cfg", b"z")])
    for _ in range(50):
        pe = pefile.PE(data=raw)
        SectionRename().apply(pe)
        JunkSections().apply(pe)
        names = _section_names(pe)
        assert len(names) == 5
        assert len(names) == len(set(names)), f"Duplicate section names: {names}"
        pe.close()


def test_junk_section_no_name_left():
    pe = pefile.PE(data=make_minimal_pe64(extra_sections=[(n, b"z") for n in _DECOY_NAMES]))
    with pytest.raises(TechniqueError):
        JunkSections().apply(pe)
    pe.close()
