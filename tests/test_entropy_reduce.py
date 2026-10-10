# tests/test_entropy_reduce.py
import math
import os
import struct
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


def test_entropy_reduce_keeps_bytes_when_vs_zero():
    """When VS is 0, effective_virtual_size returns SizeOfRawData, so no slack exists."""
    data = bytearray(make_minimal_pe64())
    # .rdata section header is at 0x170; VirtualSize (Misc_VirtualSize) is at offset 8
    struct.pack_into("<I", data, 0x170 + 8, 0)
    pe = pefile.PE(data=bytes(data))
    rdata = next(s for s in pe.sections if s.Name == b".rdata\x00\x00")
    before = bytes(pe.__data__[rdata.PointerToRawData:rdata.PointerToRawData + rdata.SizeOfRawData])
    EntropyReduce().apply(pe)
    after = bytes(pe.__data__[rdata.PointerToRawData:rdata.PointerToRawData + rdata.SizeOfRawData])
    assert before == after


def test_entropy_reduce_never_raises_entropy(minimal_pe_path, full_pe_path):
    """Entropy must not increase for any section on either fixture."""
    for path in (minimal_pe_path, full_pe_path):
        pe = load(path)
        before = {
            s.Name: shannon_entropy(
                bytes(pe.__data__[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData])
            )
            for s in pe.sections
        }
        EntropyReduce().apply(pe)
        for s in pe.sections:
            after_entropy = shannon_entropy(
                bytes(pe.__data__[s.PointerToRawData:s.PointerToRawData + s.SizeOfRawData])
            )
            assert after_entropy <= before[s.Name], (
                f"Entropy raised for section {s.Name!r} in {path}"
            )
        pe.close()


def test_entropy_reduce_keeps_used_bytes():
    """Used bytes are preserved; slack is filled with a uniform byte."""
    data = bytearray(make_minimal_pe64())
    # .text raw starts at 0x200; VS=1 (b"\xC3"), so slack begins at 0x201
    junk = bytes(range(256))[:0x40]
    data[0x201:0x201 + len(junk)] = junk
    pe = pefile.PE(data=bytes(data))
    EntropyReduce().apply(pe)
    text = next(s for s in pe.sections if s.Name == b".text\x00\x00\x00")
    raw = bytes(pe.__data__[text.PointerToRawData:text.PointerToRawData + text.SizeOfRawData])
    # The used byte must be preserved
    assert raw[0:1] == b"\xC3"
    # All slack bytes must be the same (uniform fill)
    slack = raw[1:]
    assert len(set(slack)) == 1
