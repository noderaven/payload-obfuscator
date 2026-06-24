# tests/test_entropy_reduce.py
import math
import os
import pefile
from src.core.pe_loader import load, fix_headers
from src.techniques.entropy_reduce import EntropyReduce, shannon_entropy
from tests.conftest import make_minimal_pe64, write_and_reload


def test_shannon_entropy_high_for_random():
    data = os.urandom(4096)
    assert shannon_entropy(data) > 7.5


def test_shannon_entropy_low_for_uniform():
    data = b"\x00" * 4096
    assert shannon_entropy(data) == 0.0


def test_entropy_reduce_output_parses(minimal_pe_path):
    pe = load(minimal_pe_path)
    EntropyReduce().apply(pe)
    fix_headers(pe)
    out = write_and_reload(pe)
    out.close()


def test_entropy_reduce_no_crash_on_tight_sections(minimal_pe_path):
    """EntropyReduce must not crash even if sections have no slack."""
    pe = load(minimal_pe_path)
    # Force all sections to have zero slack by setting SizeOfRawData == Misc_VirtualSize
    for section in pe.sections:
        section.SizeOfRawData = section.Misc_VirtualSize
    EntropyReduce().apply(pe)  # must not raise
    pe.close()
