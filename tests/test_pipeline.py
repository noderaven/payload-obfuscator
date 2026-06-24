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
