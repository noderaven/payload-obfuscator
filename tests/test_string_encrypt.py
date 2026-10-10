# tests/test_string_encrypt.py
import struct
import pefile
import pytest
from src.core.pe_loader import load, fix_headers
from src.core.validator import post_validate
from src.techniques.string_encrypt import StringEncrypt, xor_decrypt_table
from tests.conftest import write_and_reload, make_minimal_pe64


def test_xor_decrypt_table_round_trips():
    """Python-side decryption must reproduce the original string."""
    plaintext = b"VirtualAlloc"
    key = 0xAB
    encrypted = bytes(b ^ key for b in plaintext)
    result = xor_decrypt_table(encrypted, [(0, len(plaintext), key)])
    assert result[0] == plaintext


def test_string_encrypt_output_parses_when_stub_empty(minimal_pe_path):
    """When STUB_BYTES is empty, StringEncrypt raises TechniqueError gracefully."""
    from src.stubs.xor_decryptor_x64 import STUB_BYTES
    pe = load(minimal_pe_path)
    if not STUB_BYTES:
        with pytest.raises(Exception):  # TechniqueError or similar
            StringEncrypt().apply(pe)
    else:
        StringEncrypt().apply(pe)
        fix_headers(pe)
        post_validate(pe)
        out = write_and_reload(pe)
        out.close()
    pe.close()


def test_string_encrypt_removes_plaintext_strings(minimal_pe_path):
    """After encryption, the original strings should not appear in raw bytes (only if stub non-empty)."""
    from src.stubs.xor_decryptor_x64 import STUB_BYTES
    if not STUB_BYTES:
        pytest.skip("STUB_BYTES empty -- run generate.py first")
    pe = load(minimal_pe_path)
    raw_before = bytes(pe.__data__)
    assert b"TestString" in raw_before
    StringEncrypt().apply(pe)
    raw_after = bytes(pe.__data__)
    assert b"TestString" not in raw_after
    pe.close()


def test_string_encrypt_skips_pe_without_suitable_slack(tmp_path):
    """If no slack exists, technique must skip gracefully."""
    from src.stubs.xor_decryptor_x64 import STUB_BYTES
    if not STUB_BYTES:
        pytest.skip("STUB_BYTES empty -- skipping slack test")
    data = bytearray(make_minimal_pe64())
    # Tighten .rdata: set SizeOfRawData = Misc_VirtualSize (zero slack)
    rdata_virt_size = struct.unpack_from("<I", data, 0x170 + 8)[0]
    struct.pack_into("<I", data, 0x170 + 16, rdata_virt_size)
    path = tmp_path / "tight.exe"
    path.write_bytes(data)
    pe = load(path)
    StringEncrypt(min_string_length=8).apply(pe)
    pe.close()


def test_string_encrypt_keeps_imports_loadable(full_pe_path):
    """Import, export and debug strings are loader data and must stay plaintext."""
    pe = load(full_pe_path)
    before = [(d.dll, [i.name for i in d.imports]) for d in pe.DIRECTORY_ENTRY_IMPORT]
    StringEncrypt().apply(pe)
    fix_headers(pe)
    out = write_and_reload(pe)
    after = [(d.dll, [i.name for i in d.imports]) for d in out.DIRECTORY_ENTRY_IMPORT]
    assert after == before
    assert [e.name for e in out.DIRECTORY_ENTRY_EXPORT.symbols] == [b"ExportedFunction"]
    assert b"AnotherLongString" not in out.__data__
    out.close()
    pe.close()


def test_string_straddling_protected_range_is_skipped():
    """A printable run that runs into the import descriptor is left alone whole."""
    data = make_minimal_pe64(rdata_data=b"UserPrefixAAAAAA",
                             imports={"KERNEL32.dll": ["VirtualAlloc"]})
    pe = pefile.PE(data=data)
    StringEncrypt().apply(pe)
    assert b"UserPrefixAAAAAA" in bytes(pe.__data__)
    out = write_and_reload(pe)
    assert out.DIRECTORY_ENTRY_IMPORT[0].imports[0].name == b"VirtualAlloc"
    out.close()
    pe.close()
