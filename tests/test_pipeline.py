# tests/test_pipeline.py
import pytest
import pefile
from pathlib import Path
from src.core.pe_loader import PEWriteError, safe_write
from src.core.pipeline import ObfuscationPipeline
from src.core.validator import ValidationError
from src.techniques.base import BaseTechnique, TechniqueError


class _NoopTechnique(BaseTechnique):
    name = "noop"
    def apply(self, pe): pass


class _FailOptional(BaseTechnique):
    name = "fail-optional"
    required = False
    def apply(self, pe): raise TechniqueError("intentional")


class _FailRequired(BaseTechnique):
    name = "fail-required"
    required = True
    def apply(self, pe): raise TechniqueError("intentional")


class _WriteThenFail(BaseTechnique):
    name = "write-then-fail"
    required = False
    def apply(self, pe):
        safe_write(pe, pe.sections[0].PointerToRawData, b"\xCC" * 16)
        raise TechniqueError("intentional after partial write")


class _RaisePEWriteError(BaseTechnique):
    name = "raise-pe-write-error"
    required = False
    def apply(self, pe): raise PEWriteError("boom")


def test_pipeline_runs_noop_and_produces_valid_output(minimal_pe_path, tmp_path):
    out = tmp_path / "out.exe"
    pipeline = ObfuscationPipeline()
    assert pipeline.run(minimal_pe_path, out, [_NoopTechnique()])
    pe2 = pefile.PE(str(out))
    assert pe2.OPTIONAL_HEADER.Magic == 0x20B
    pe2.close()


def test_pipeline_skips_optional_failing_technique(minimal_pe_path, tmp_path):
    out = tmp_path / "out.exe"
    pipeline = ObfuscationPipeline()
    assert pipeline.run(minimal_pe_path, out, [_NoopTechnique(), _FailOptional()])
    assert out.exists()


def test_pipeline_aborts_on_required_failure(minimal_pe_path, tmp_path):
    out = tmp_path / "out.exe"
    pipeline = ObfuscationPipeline()
    with pytest.raises(TechniqueError):
        pipeline.run(minimal_pe_path, out, [_FailRequired()])


def test_full_pipeline_produces_valid_pe(minimal_pe_path, tmp_path):
    """End-to-end: run all techniques; verify output parses as valid PE64."""
    from src.techniques.header_normalize import HeaderNormalize
    from src.techniques.section_rename import SectionRename
    from src.techniques.entropy_reduce import EntropyReduce
    from src.techniques.junk_sections import JunkSections
    from src.techniques.string_encrypt import StringEncrypt
    from src.techniques.import_hash import ImportHash

    from src.stubs.xor_decryptor_x64 import STUB_BYTES as _XOR_BYTES

    out = tmp_path / "out_obf.exe"
    pipeline = ObfuscationPipeline()
    pipeline.run(
        minimal_pe_path,
        out,
        [HeaderNormalize(), StringEncrypt(), ImportHash(),
         SectionRename(), EntropyReduce(), JunkSections()],
    )
    assert out.exists()
    pe2 = pefile.PE(str(out))
    assert pe2.OPTIONAL_HEADER.Magic == 0x20B
    assert pe2.FILE_HEADER.NumberOfSections >= 2
    assert pe2.OPTIONAL_HEADER.SizeOfImage % pe2.OPTIONAL_HEADER.SectionAlignment == 0
    pe2.close()
    if _XOR_BYTES:
        raw = out.read_bytes()
        assert b"TestString" not in raw, "StringEncrypt should have encrypted this string"


def test_pipeline_rolls_back_partial_edits(minimal_pe_path, tmp_path):
    a = tmp_path / "a.exe"
    b = tmp_path / "b.exe"
    pipeline = ObfuscationPipeline()
    assert pipeline.run(minimal_pe_path, a, [_NoopTechnique()])
    assert pipeline.run(minimal_pe_path, b, [_WriteThenFail()])
    assert a.read_bytes() == b.read_bytes()


def test_pipeline_aborts_on_non_technique_error_without_output(minimal_pe_path, tmp_path):
    out = tmp_path / "out.exe"
    pipeline = ObfuscationPipeline()
    with pytest.raises(PEWriteError):
        pipeline.run(minimal_pe_path, out, [_RaisePEWriteError()])
    assert not out.exists()


def test_full_pipeline_on_full_fixture(full_pe_path, tmp_path):
    """End-to-end: run all six techniques on full_pe_path; verify every preserved attribute."""
    from src.techniques.header_normalize import HeaderNormalize
    from src.techniques.section_rename import SectionRename
    from src.techniques.entropy_reduce import EntropyReduce
    from src.techniques.junk_sections import JunkSections
    from src.techniques.string_encrypt import StringEncrypt
    from src.techniques.import_hash import ImportHash, _DECOY_MAP

    out_path = tmp_path / "out_full.exe"
    pipeline = ObfuscationPipeline()
    pipeline.run(
        full_pe_path,
        out_path,
        [HeaderNormalize(), StringEncrypt(), ImportHash(),
         SectionRename(), EntropyReduce(), JunkSections()],
    )

    out = pefile.PE(str(out_path))
    try:
        # Imports: single DLL, three entries; decoys replace high-risk names.
        assert hasattr(out, "DIRECTORY_ENTRY_IMPORT"), "output has no import directory"
        assert len(out.DIRECTORY_ENTRY_IMPORT) == 1
        assert out.DIRECTORY_ENTRY_IMPORT[0].dll == b"KERNEL32.dll"
        import_names = [
            imp.name
            for imp in out.DIRECTORY_ENTRY_IMPORT[0].imports
            if imp.name is not None
        ]
        assert len(import_names) == 3
        assert b"ExitProcess" in import_names
        decoy_virtualalloc = _DECOY_MAP["VirtualAlloc"].rstrip("\x00").encode("ascii")
        decoy_getprocaddress = _DECOY_MAP["GetProcAddress"].rstrip("\x00").encode("ascii")
        assert decoy_virtualalloc in import_names
        assert decoy_getprocaddress in import_names

        # Exports: ExportedFunction still present.
        assert hasattr(out, "DIRECTORY_ENTRY_EXPORT")
        export_names = [
            exp.name
            for exp in out.DIRECTORY_ENTRY_EXPORT.symbols
            if exp.name is not None
        ]
        assert b"ExportedFunction" in export_names

        # Section names are unique.
        section_names = [s.Name.rstrip(b"\x00") for s in out.sections]
        assert len(section_names) == len(set(section_names))

        # Entry-point byte intact.
        ep = out.OPTIONAL_HEADER.AddressOfEntryPoint
        assert out.get_data(ep, 1) == b"\xC3"

        # Checksum matches.
        assert out.verify_checksum()

        # Rich header was stripped.
        assert out.parse_rich_header() is None

        # Overlay preserved.
        overlay = out.get_overlay()
        assert overlay is not None and overlay.startswith(b"OVERLAY!" * 8)
    finally:
        out.close()


def test_pipeline_closes_pe_when_pre_validate_fails(minimal_pe_path, tmp_path, monkeypatch):
    def _fail(pe):
        raise ValidationError("intentional")

    calls = []
    original_close = pefile.PE.close

    def _record_close(self):
        calls.append(self)
        original_close(self)

    monkeypatch.setattr("src.core.pipeline.validator.pre_validate", _fail)
    monkeypatch.setattr(pefile.PE, "close", _record_close)
    out = tmp_path / "out.exe"
    with pytest.raises(ValidationError):
        ObfuscationPipeline().run(minimal_pe_path, out, [_NoopTechnique()])
    assert len(calls) == 1
    assert not out.exists()
