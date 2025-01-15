#!/usr/bin/env python3

import os
import pytest
from src.obfuscator import PayloadObfuscator
from utils.techniques import CodeMutation, ImportObfuscation, StringObfuscation

@pytest.fixture
def sample_pe_file():
    # TODO: Create or download a sample PE file for testing
    return "sample.exe"

@pytest.fixture
def obfuscator(sample_pe_file):
    return PayloadObfuscator(sample_pe_file)

def test_pe_validation(obfuscator):
    """Test PE file validation."""
    assert obfuscator._validate_pe() == True

def test_section_encryption(obfuscator):
    """Test section encryption functionality."""
    assert obfuscator.apply_section_encryption() == True

def test_import_obfuscation(obfuscator):
    """Test import table obfuscation."""
    assert obfuscator.apply_import_obfuscation() == True

def test_code_mutation(obfuscator):
    """Test code mutation techniques."""
    assert obfuscator.apply_code_mutation() == True

class TestStringObfuscation:
    def test_xor_encryption(self):
        data = b"TestString"
        key = b"K"
        obfuscated = StringObfuscation.xor_encrypt(data, key)
        deobfuscated = StringObfuscation.xor_encrypt(obfuscated, key)
        assert deobfuscated == data

    def test_string_rotation(self):
        data = b"TestString"
        rotation = 13
        obfuscated = StringObfuscation.rotate_string(data, rotation)
        deobfuscated = StringObfuscation.rotate_string(obfuscated, -rotation)
        assert deobfuscated == data

    def test_string_splitting(self):
        data = "TestString"
        chunks = StringObfuscation.split_string(data)
        assert "".join(chunks) == data

class TestImportObfuscation:
    def test_api_name_hashing(self):
        api_name = "CreateProcessA"
        hash_val = ImportObfuscation.hash_api_name(api_name)
        assert isinstance(hash_val, int)
        assert hash_val != 0

if __name__ == "__main__":
    pytest.main([__file__]) 