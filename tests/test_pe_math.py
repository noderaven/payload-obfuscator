import types

import pytest
from src.utils.pe_math import align, effective_virtual_size, ror13_hash, section_slack

def test_align_rounds_up():
    assert align(401, 512) == 512
    assert align(512, 512) == 512
    assert align(513, 512) == 1024
    assert align(0, 512) == 0

def test_align_boundary_one():
    assert align(7, 1) == 7

def test_ror13_hash_known_values():
    h = ror13_hash("VirtualAlloc")
    assert isinstance(h, int)
    assert 0 <= h <= 0xFFFFFFFF
    assert ror13_hash("VirtualAlloc") == ror13_hash("VirtualAlloc")
    assert ror13_hash("virtualalloc") == ror13_hash("VIRTUALALLOC")

def test_ror13_hash_different_for_different_names():
    assert ror13_hash("VirtualAlloc") != ror13_hash("CreateThread")
    assert ror13_hash("LoadLibraryA") != ror13_hash("LoadLibraryW")

def test_ror13_hash_virtualalloc_pinned():
    """Pin the ROR-13 hash for VirtualAlloc to catch algorithm regressions."""
    assert ror13_hash("VirtualAlloc") == 0x302ebe1c


def test_effective_virtual_size_falls_back_to_raw_size():
    assert effective_virtual_size(types.SimpleNamespace(Misc_VirtualSize=0, SizeOfRawData=0x200)) == 0x200
    assert effective_virtual_size(types.SimpleNamespace(Misc_VirtualSize=0x10, SizeOfRawData=0x200)) == 0x10


def test_section_slack_is_zero_when_virtual_size_zero():
    assert section_slack(types.SimpleNamespace(Misc_VirtualSize=0, SizeOfRawData=0x200)) == 0
    assert section_slack(types.SimpleNamespace(Misc_VirtualSize=0x10, SizeOfRawData=0x200)) == 0x1F0
