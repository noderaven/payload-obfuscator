"""Tests for CLI --skip name resolution and validation."""
from __future__ import annotations

import pytest

from src.__main__ import main


@pytest.fixture
def captured(monkeypatch):
    """Monkeypatch ObfuscationPipeline.run to record technique names and return True."""
    runs: list[list[str]] = []

    def _fake_run(self, input_path, output_path, techniques):  # noqa: ANN001
        runs.append([t.name for t in techniques])
        return True

    monkeypatch.setattr("src.__main__.ObfuscationPipeline.run", _fake_run)
    return runs


def test_skip_unknown_name_errors(minimal_pe_path, captured, capsys):
    with pytest.raises(SystemExit) as exc_info:
        main([str(minimal_pe_path), "--skip", "bogus"])
    assert exc_info.value.code == 2
    assert "bogus" in capsys.readouterr().err
    assert captured == []  # pipeline must not have run


def test_skip_mixed_unknown_errors_sorted(minimal_pe_path, captured, capsys):
    """A mix of valid and unknown tokens is rejected; unknown names are sorted."""
    with pytest.raises(SystemExit) as exc_info:
        main([str(minimal_pe_path), "--skip", "section_rename,zzz,aaa"])
    assert exc_info.value.code == 2
    err = capsys.readouterr().err
    assert "aaa" in err and "zzz" in err
    assert err.index("aaa") < err.index("zzz")
    assert captured == []  # pipeline must not have run


def test_skip_accepts_both_name_forms(minimal_pe_path, captured):
    result = main([str(minimal_pe_path), "--skip", " HeaderNormalize , section_rename "])
    assert result == 0
    assert len(captured) == 1
    names = captured[0]
    assert "header_normalize" not in names
    assert "section_rename" not in names
    assert "string_encrypt" in names


def test_list_techniques_exit_zero():
    assert main(["--list-techniques"]) == 0
