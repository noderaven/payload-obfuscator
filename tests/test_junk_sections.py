# tests/test_junk_sections.py
import pefile
from src.core.pe_loader import load, fix_headers
from src.core.validator import post_validate
from src.techniques.junk_sections import JunkSections
from tests.conftest import write_and_reload


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
