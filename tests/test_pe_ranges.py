"""Tests for src/core/pe_ranges.py."""
import pefile

from src.core.pe_ranges import overlaps, protected_file_ranges


def test_protects_import_and_export_names(full_pe_path):
    pe = pefile.PE(str(full_pe_path))
    ranges = protected_file_ranges(pe)
    rdata = next(s for s in pe.sections if s.Name.rstrip(b"\x00") == b".rdata")
    data = bytes(pe.__data__)
    for needle in (b"KERNEL32.dll", b"VirtualAlloc", b"ExportedFunction",
                   rb"C:\build\secret\project.pdb"):
        off = data.find(needle, rdata.PointerToRawData)
        assert off != -1, needle
        assert overlaps(ranges, off, off + 1), needle
    off = data.find(b"AnotherLongString", rdata.PointerToRawData)
    assert off != -1
    assert not overlaps(ranges, off, off + len(b"AnotherLongString"))
    pe.close()


def test_ranges_are_sorted_and_merged(full_pe_path):
    pe = pefile.PE(str(full_pe_path))
    ranges = protected_file_ranges(pe)
    assert ranges
    for (s1, e1), (s2, e2) in zip(ranges, ranges[1:]):
        assert s1 < e1 < s2 < e2
    pe.close()


def test_overlaps_is_half_open():
    ranges = [(10, 20), (30, 40)]
    assert overlaps(ranges, 19, 21)
    assert overlaps(ranges, 5, 11)
    assert overlaps(ranges, 25, 35)
    assert not overlaps(ranges, 20, 30)
    assert not overlaps(ranges, 0, 10)
    assert not overlaps(ranges, 40, 50)
    assert not overlaps([], 0, 100)
