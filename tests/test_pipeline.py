# tests/test_pipeline.py
import pytest
import pefile
from pathlib import Path
from src.core.pipeline import ObfuscationPipeline
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

    out = tmp_path / "out_obf.exe"
    pipeline = ObfuscationPipeline()
    pipeline.run(
        minimal_pe_path,
        out,
        [HeaderNormalize(), SectionRename(), StringEncrypt(),
         ImportHash(), EntropyReduce(), JunkSections()],
    )
    assert out.exists()
    pe2 = pefile.PE(str(out))
    assert pe2.OPTIONAL_HEADER.Magic == 0x20B
    assert pe2.FILE_HEADER.NumberOfSections >= 2
    assert pe2.OPTIONAL_HEADER.SizeOfImage % pe2.OPTIONAL_HEADER.SectionAlignment == 0
    pe2.close()
