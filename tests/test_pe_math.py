import pytest
from src.utils.pe_math import align, ror13_hash

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
