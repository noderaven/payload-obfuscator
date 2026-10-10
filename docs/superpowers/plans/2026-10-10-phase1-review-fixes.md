# Phase 1 Review Fixes Implementation Plan

> **For agentic workers:** This plan is executed with the parallel-lanes skill (user default). Tasks list `Depends on` and owned `Files` so lanes can be scheduled; a task must not edit files owned by another task unless its Files block lists them. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix Phase 1 defects 1-14 from the 2026-10-10 code review (including the malformed test fixture) so obfuscated output stays loadable and structurally consistent.

**Architecture:** A richer test fixture builder lands first (Task 1) together with one shared helper for the "VirtualSize == 0" root cause. Then independent lanes fix the PE I/O layer (`pe_loader`), the pipeline, the validator, the CLI, and each technique, and each lane is pinned by tests against the new fixture. A final integration task runs the full pipeline on a fixture that has every hazard the review found.

**Tech Stack:** Python >=3.10, pefile (venv has 2024.8.26), pytest, loguru, rich.

**Spec:** `docs/superpowers/code-review-2026-10-10.md` (section "Phase 1 defects"). Executors read both.

## Global Constraints

- Run tests with `.venv/bin/python -m pytest` from the repo root (there is no `python` on PATH).
- Branch from `main` @ 87f405c. Do not touch `README.md` or `pyproject.toml` (open PR noderaven/payload-obfuscator#3 edits both).
- No new runtime or dev dependencies.
- Package stays importable as `src.*` (rename is deferred).
- Phase 2 behaviour is out of scope: do not change the stubs, the TLS wiring, the import_hash decoy names, or the `.init`/`.resolv` section characteristics.
- Keep the existing public signatures in `src/core/pe_loader.py` (`load`, `save`, `safe_write`, `append_section_data`, `fix_headers`, `append_new_section`) and `ObfuscationPipeline.run`.
- Out of scope (Low, deferred): output==input overwrite, unused capstone/pycryptodomex deps, `src` package rename, `--verbose` no-op, Rich console wrapping, low-alignment images, `rva_to_offset` header region. In scope because they sit in code these tasks already rewrite: header_normalize IndexError (Task 9), pipeline handle leak (Task 4), fix_headers shrinking SizeOfHeaders (Task 3), `--output` help text (Task 6).

## Review Focus

- Full pipeline on a binary with imports, exports, debug info, a Rich header, bound imports, an overlay and an Authenticode blob, all at once: the output must still parse with the same imports and exports, have unique section names, and pass `verify_checksum()`. Test in Task 11.
- A printable run that starts in user data and continues into a protected (loader-needed) range with no NUL between them must be skipped whole, not partly encrypted. Test in Task 7.
- `--skip` with mixed case, spaces and both name forms (`" HeaderNormalize , section_rename "`) resolves correctly. Test in Task 6.
- A technique that raises a non-`TechniqueError` (for example `PEWriteError`) aborts the run and writes no output file. Test in Task 4.
- A "Rich" marker with no matching DanS (a corrupted Rich header) leaves the file bytes untouched. Test in Task 9.

---

### Task 1: Fix the fixture, extend the builder, add the effective-size helper

**Depends on:** none

**Files:**
- Modify: `tests/conftest.py`
- Modify: `src/utils/pe_math.py`
- Create: `tests/test_fixture.py`
- Modify: `tests/test_pe_math.py`

**Interfaces:**
- Produces: `make_minimal_pe64(text_data: bytes = b"\xC3", rdata_data: bytes = b"TestString\x00AnotherLongString\x00", *, imports: dict[str, list[str]] | None = None, exports: list[str] | None = None, debug_pdb: str | None = None, rich_header: bool = False, bound_import: bool = False, overlay: bytes = b"", certificate: bytes = b"", extra_sections: Sequence[tuple[str, bytes]] = ()) -> bytes`
- Produces: pytest fixture `full_pe_path` (a Path). Built with `imports={"KERNEL32.dll": ["VirtualAlloc", "GetProcAddress", "ExitProcess"]}, exports=["ExportedFunction"], debug_pdb=r"C:\build\secret\project.pdb", rich_header=True, bound_import=True, overlay=b"OVERLAY!" * 8, certificate=b"\x30\x82" + b"\x00" * 30`
- Produces: module constants in `tests/conftest.py`: `DEBUG_TIMESTAMP = 0x12345678`, `EXPORT_TIMESTAMP = 0x12345678`, `RICH_KEY = 0xA5A5A5A5`
- Produces: `pe_math.effective_virtual_size(section) -> int` returns `Misc_VirtualSize or SizeOfRawData`. `pe_math.section_slack` now uses it, so slack is 0 when VirtualSize is 0.

Builder layout rules (the defaults must give exactly the fixed fixture: 0x600 bytes, e_lfanew 0x40, `.text` raw 0x200, `.rdata` raw 0x400, section table at 0x148):
- Optional header format is `"<HBBIIIIIQIIHHHHHHIIIIHHQQQQII"` (112 bytes). Drop the trailing `xx`.
- `rich_header=True`: a DOS stub message at 0x40, DanS at file offset 0x80 (dwords `DanS^key, key, key, key`, two `(compid^key, count^key)` pairs, `b"Rich"`, key), and `e_lfanew = 0x100`.
- `imports`, `exports` and `debug_pdb` structures are appended to `.rdata` after `rdata_data` (8-byte aligned), with data directories 1+12, 0 and 6 set. The export function RVAs point at 0x1000. The export directory and debug entry TimeDateStamps use the constants above. The debug entry is CODEVIEW (type 2) pointing at an `RSDS` record in `.rdata`.
- `extra_sections`: appended after `.rdata` with consecutive 0x1000 VAs and characteristics 0x40000040.
- `bound_import=True`: an IMAGE_BOUND_IMPORT_DESCRIPTOR for `KERNEL32.dll` plus a null descriptor plus the name, placed directly after the section table. DATA_DIRECTORY[11] = (file offset, size).
- SizeOfHeaders: the smallest multiple of 0x200 that is ≥ the end of the header data (section table plus bound import) plus 40 bytes of headroom for one appended section header, minimum 0x200. The default fixture stays at 0x200.
- `overlay` goes after the last section. `certificate` is wrapped as WIN_CERTIFICATE (`<IHH` dwLength=8+len, 0x0200, 2), placed 8-byte aligned after the overlay, with DATA_DIRECTORY[4] = (file offset, 8+len).

- [ ] **Step 1: Write the failing tests** in `tests/test_fixture.py`:

```python
def test_default_fixture_layout():
    d = make_minimal_pe64(); pe = pefile.PE(data=d)
    assert len(d) == 0x600
    assert pe.get_data(0x1000, 1) == b"\xC3"
    assert [s.PointerToRawData for s in pe.sections] == [0x200, 0x400]
    assert pe.get_data(0x2000, 10) == b"TestString"

def test_full_fixture_parses_every_feature(full_pe_path):
    pe = pefile.PE(str(full_pe_path))
    imp = pe.DIRECTORY_ENTRY_IMPORT[0]
    assert imp.dll == b"KERNEL32.dll"
    assert [i.name for i in imp.imports] == [b"VirtualAlloc", b"GetProcAddress", b"ExitProcess"]
    assert [e.name for e in pe.DIRECTORY_ENTRY_EXPORT.symbols] == [b"ExportedFunction"]
    assert pe.DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp == EXPORT_TIMESTAMP
    dbg = pe.DIRECTORY_ENTRY_DEBUG[0]
    assert dbg.struct.TimeDateStamp == DEBUG_TIMESTAMP
    assert dbg.entry.PdbFileName.rstrip(b"\x00") == rb"C:\build\secret\project.pdb"
    assert pe.parse_rich_header() is not None
    assert pe.DOS_HEADER.e_lfanew == 0x100
    assert pe.OPTIONAL_HEADER.DATA_DIRECTORY[11].VirtualAddress != 0
    sec = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    assert sec.Size == 8 + 32
    assert struct.unpack_from("<IHH", pe.__data__, sec.VirtualAddress) == (40, 0x0200, 2)
    assert pe.get_overlay().startswith(b"OVERLAY!" * 8)

def test_extra_sections_are_appended():
    pe = pefile.PE(data=make_minimal_pe64(extra_sections=[(".data", b"x" * 16), (".pdata", b"y" * 16)]))
    assert [s.Name.rstrip(b"\x00") for s in pe.sections] == [b".text", b".rdata", b".data", b".pdata"]
```

In `tests/test_pe_math.py`, add `test_effective_virtual_size_falls_back_to_raw_size` and `test_section_slack_is_zero_when_virtual_size_zero`. Use a `types.SimpleNamespace(Misc_VirtualSize=0, SizeOfRawData=0x200)` and assert `0x200` and `0`. Also assert normal values (VS=0x10, raw=0x200 → 0x10 and 0x1F0).

- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_fixture.py tests/test_pe_math.py -v`. Expected: FAIL (len 0x602, missing kwargs, missing helper).
- [ ] **Step 3: Implement the builder and the helper** following the layout rules above.
- [ ] **Step 4: Run** `.venv/bin/python -m pytest -q`. Expected: all pass (47 existing + new).
- [ ] **Step 5: Commit** `test: fix malformed PE fixture; add feature-rich fixture builder` (pe_math may be noted in the body).

---

### Task 2: safe_write keeps parsed structures in sync (#14)

**Depends on:** Task 1

**Files:**
- Modify: `src/core/pe_loader.py` (`safe_write` only)
- Modify: `tests/test_pe_loader.py`

**Interfaces:**
- Produces: `safe_write(pe, offset, data)`, same signature. After writing, every structure in `pe.__structures__` whose `[get_file_offset(), +sizeof())` overlaps the write is re-read from `pe.__data__` via `structure.__unpack__(...)`. So raw writes survive `pe.write()`, and attributes such as `section.Name` reflect them. A linear scan is fine.

- [ ] **Step 1: Write the failing test** `test_safe_write_survives_pe_write`:

```python
pe = load(minimal_pe_path)
safe_write(pe, pe.sections[0].get_file_offset(), b".zzz\x00\x00\x00\x00")
assert pe.sections[0].Name == b".zzz\x00\x00\x00\x00"
out = pefile.PE(data=pe.write())
assert out.sections[0].Name.rstrip(b"\x00") == b".zzz"
```

Add `test_safe_write_partial_structure_overlap`. Write 4 bytes at `pe.FILE_HEADER.get_file_offset() + 4`, the TimeDateStamp, as `struct.pack("<I", 0xCAFEBABE)`, and assert `pe.FILE_HEADER.TimeDateStamp == 0xCAFEBABE` and that the reparsed `pe.write()` matches.
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_pe_loader.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement** the resync in `safe_write`.
- [ ] **Step 4: Run** `.venv/bin/python -m pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit** `fix(pe_loader): resync parsed structures after raw writes`

---

### Task 3: Section append respects VS=0, the overlay, and header-space data (#11, #12, #13)

**Depends on:** Task 1, Task 2 (same file)

**Files:**
- Modify: `src/core/pe_loader.py` (`append_section_data`, `fix_headers`, `append_new_section`)
- Modify: `tests/test_pe_loader.py`

**Interfaces:**
- Consumes: `pe_math.effective_virtual_size(section)`.
- Produces: same signatures. `append_section_data(pe, data) -> int` now inserts the data at `align(max(PointerToRawData + SizeOfRawData over sections), FileAlignment)`, not at EOF. Any bytes after that point (the overlay and certificate) move after the new chunk, and if DATA_DIRECTORY[4].VirtualAddress (a file offset) is ≥ the insertion point it is increased by the inserted length. `fix_headers` and `append_new_section` use `effective_virtual_size` for every "end of section VA" calculation. `fix_headers` never lowers SizeOfHeaders: `max(current, computed)`. `append_new_section` header-space check: if DATA_DIRECTORY[11] (bound import) overlaps `[headers_end, headers_end + 40)`, zero that directory entry (VirtualAddress and Size, in both struct and bytes) and continue. If any non-zero byte still remains in that 40-byte window, raise `PEError`.

- [ ] **Step 1: Write the failing tests:**
  - `test_append_new_section_after_vs_zero_last_section`: patch the `.rdata` header VS (file offset `0x170 + 8`) to 0 in `make_minimal_pe64()`, load it, `append_new_section(pe, ".new", b"A" * 16, 0x40000040)`, then `fix_headers`. Assert the new section's `VirtualAddress == 0x3000` and `SizeOfImage == 0x4000`.
  - `test_fix_headers_size_of_image_with_vs_zero`: same patch, `fix_headers` only, assert `SizeOfImage == 0x3000`.
  - `test_fix_headers_never_shrinks_size_of_headers`: set `pe.OPTIONAL_HEADER.SizeOfHeaders = 0x400`, `fix_headers`, assert `== 0x400`.
  - `test_append_keeps_overlay_and_certificate`: use `make_minimal_pe64(overlay=b"OVERLAY!" * 8, certificate=b"\x30\x82" + b"\x00" * 30)`, append `.new`, `fix_headers`, reparse `pe.write()`. Assert that the new section's `PointerToRawData == 0x600`, that `get_overlay()` starts with `b"OVERLAY!" * 8`, and that `struct.unpack_from("<IHH", data, dir4.VirtualAddress) == (40, 0x0200, 2)`.
  - `test_append_drops_bound_import_in_the_way`: with `make_minimal_pe64(bound_import=True)`, append succeeds. After reparse, DATA_DIRECTORY[11] is (0, 0) and `.new` is in the section names.
  - `test_append_refuses_unknown_header_data`: write `b"\xFF" * 8` at the section table end (0x198) of the default fixture before loading, and assert `append_new_section` raises `PEError`.
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_pe_loader.py -v`. Expected: the new tests FAIL.
- [ ] **Step 3: Implement** the three functions as described.
- [ ] **Step 4: Run** `.venv/bin/python -m pytest -q`. Expected: all pass, including `test_junk_sections.py`.
- [ ] **Step 5: Commit** `fix(pe_loader): append before overlay, honour VS=0 and header-space data`

---

### Task 4: Pipeline rolls back a skipped technique (#2, handle leak)

**Depends on:** Task 1

**Files:**
- Modify: `src/core/pipeline.py`
- Modify: `tests/test_pipeline.py`

**Interfaces:**
- Produces: `ObfuscationPipeline.run(...) -> bool`, same signature. Before each technique it takes `snapshot = pe.write()`. On an optional `TechniqueError` it does `pe.close()`, then `pe = pefile.PE(data=bytearray(snapshot))`, then logs the skip. Any other exception propagates and no output is written. `pre_validate` moves inside the `try` so `pe.close()` always runs, and `finally` closes whichever `pe` is current.

- [ ] **Step 1: Write the failing tests:**
  - `test_pipeline_rolls_back_partial_edits`: a `_WriteThenFail` technique (`required=False`) calls `safe_write(pe, pe.sections[0].PointerToRawData, b"\xCC" * 16)` and then raises `TechniqueError`. Run `[_NoopTechnique()]` to `a.exe` and `[_WriteThenFail()]` to `b.exe`, then assert `a.read_bytes() == b.read_bytes()`.
  - `test_pipeline_aborts_on_non_technique_error_without_output` (Review Focus): a technique raising `PEWriteError("boom")`. `pytest.raises(PEWriteError)`, and `not out.exists()`.
  - `test_pipeline_closes_pe_when_pre_validate_fails`: monkeypatch `src.core.pipeline.validator.pre_validate` to raise `ValidationError`, and monkeypatch `pefile.PE.close` to record calls. Assert it was called once.
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_pipeline.py -v`. Expected: the rollback and close tests FAIL.
- [ ] **Step 3: Implement** the changes in `run`.
- [ ] **Step 4: Run** `.venv/bin/python -m pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit** `fix(pipeline): restore PE state when an optional technique fails`

---

### Task 5: Validator rejects non-AMD64 machines (#10)

**Depends on:** Task 1

**Files:**
- Modify: `src/core/validator.py`
- Modify: `tests/test_validator.py`

**Interfaces:**
- Produces: `pre_validate(pe)` also raises `ValidationError(f"Not an x64 (AMD64) binary; Machine=0x{m:x}")` when `pe.FILE_HEADER.Machine != 0x8664`.

- [ ] **Step 1: Write the failing test** `test_pre_validate_rejects_arm64`: patch the 2 bytes at 0x44 to `struct.pack("<H", 0xAA64)` and expect `pytest.raises(ValidationError, match="AMD64")`.
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_validator.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the check.
- [ ] **Step 4: Run** `.venv/bin/python -m pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit** `fix(validator): require AMD64 machine type`

---

### Task 6: CLI resolves --skip names and rejects unknown ones (#9)

**Depends on:** Task 1

**Files:**
- Modify: `src/__main__.py`
- Create: `tests/test_cli.py`

**Interfaces:**
- Produces: `main(argv) -> int`, same signature. Each comma-separated `--skip` token is stripped, lowercased, and looked up in `_TECHNIQUE_MAP`. Any misses lead to `parser.error(f"unknown technique(s) in --skip: {', '.join(sorted(misses))}")` (SystemExit 2). Techniques are filtered by class: `[cls() for cls in _ALL_TECHNIQUES if cls not in skipped_classes]`. The `--output` help text becomes `"Output path (default: <input stem>_obf<input suffix> next to the input)"`.

- [ ] **Step 1: Write the failing tests** in `tests/test_cli.py`. Use a `captured` fixture that monkeypatches `src.__main__.ObfuscationPipeline.run` to record `[t.name for t in techniques]` and return True.
  - `test_skip_unknown_name_errors`: `pytest.raises(SystemExit)` on `main([str(minimal_pe_path), "--skip", "bogus"])`, `.code == 2`, and `"bogus"` in `capsys.readouterr().err`.
  - `test_skip_accepts_both_name_forms` (Review Focus): `main([path, "--skip", " HeaderNormalize , section_rename "]) == 0`. `"header_normalize"` and `"section_rename"` are not in captured, and `"string_encrypt"` is.
  - `test_list_techniques_exit_zero`: `main(["--list-techniques"]) == 0`.
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_cli.py -v`. Expected: the unknown-name and class-name tests FAIL.
- [ ] **Step 3: Implement** the changes.
- [ ] **Step 4: Run** `.venv/bin/python -m pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit** `fix(cli): resolve --skip via technique map; error on unknown names`

---

### Task 7: string_encrypt leaves loader-needed bytes alone (#1)

**Depends on:** Task 1

**Files:**
- Create: `src/core/pe_ranges.py`
- Create: `tests/test_pe_ranges.py`
- Modify: `src/techniques/string_encrypt.py`
- Modify: `tests/test_string_encrypt.py`

**Interfaces:**
- Produces: `pe_ranges.protected_file_ranges(pe: pefile.PE) -> list[tuple[int, int]]`. It returns sorted, merged, half-open file-offset ranges covering:
  - every non-empty data directory `[rva, rva+size)` (the security directory, index 4, is already a file offset);
  - for each import and delay-import entry: the DLL name string (`len(dll)+1`), each hint/name entry (`imp.name_offset - 2` through the name and its NUL), and the thunk arrays;
  - for exports: the DLL name string and every export name (`len(name)+1` at `name_offset`);
  - for each debug entry: `[PointerToRawData, +SizeOfData)`.
  
  RVAs are converted with `pe.get_offset_from_rva`. Unmappable RVAs are skipped, not raised.
- Produces: `pe_ranges.overlaps(ranges, start: int, end: int) -> bool` (binary search).
- `StringEncrypt.apply` computes the ranges once and skips any string whose `[abs_offset, abs_offset+length)` overlaps one.

- [ ] **Step 1: Write the failing tests:**
  - `tests/test_pe_ranges.py::test_protects_import_and_export_names(full_pe_path)`. For the offset of each of `b"KERNEL32.dll"`, `b"VirtualAlloc"`, `b"ExportedFunction"` and the PDB path (find them with `pe.__data__.find` after the `.rdata` raw start), assert `overlaps(ranges, off, off + 1)`. Also assert that `b"AnotherLongString"` is not covered.
  - `tests/test_string_encrypt.py::test_string_encrypt_keeps_imports_loadable(full_pe_path)`: apply `StringEncrypt()`, `fix_headers`, then `write_and_reload`. The DLL and import names equal the originals, `ExportedFunction` is still exported, and `b"AnotherLongString" not in` the output bytes.
  - `test_string_straddling_protected_range_is_skipped` (Review Focus): build with `make_minimal_pe64(rdata_data=b"UserPrefixAAAAAA", imports={"KERNEL32.dll": ["VirtualAlloc"]})`. The 16 bytes are 8-aligned, so the import descriptor follows with no NUL, and its first RVA bytes are printable, so one printable run crosses into the descriptor. After `apply`, assert `b"UserPrefixAAAAAA" in bytes(pe.__data__)` (skipped whole) and `write_and_reload(pe).DIRECTORY_ENTRY_IMPORT[0].imports[0].name == b"VirtualAlloc"`.
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_pe_ranges.py tests/test_string_encrypt.py -v`. Expected: FAIL (module missing; imports destroyed).
- [ ] **Step 3: Implement** `pe_ranges.py` and the skip in `StringEncrypt.apply`.
- [ ] **Step 4: Run** `.venv/bin/python -m pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit** `fix(string_encrypt): never encrypt import/export/debug data`

---

### Task 8: entropy_reduce never overwrites section data or raises entropy (#3, #7)

**Depends on:** Task 1

**Files:**
- Modify: `src/techniques/entropy_reduce.py`
- Modify: `tests/test_entropy_reduce.py`

**Interfaces:**
- Consumes: `pe_math.effective_virtual_size`.
- Produces: `EntropyReduce.apply(pe)`. For each section, `used = effective_virtual_size(section)` and slack is `[raw + used, raw + SizeOfRawData)`, clipped to the file. The fill byte is the most frequent byte in the section's whole raw data. Write only if `shannon_entropy(new_raw) < shannon_entropy(old_raw)`. `_LOW_ENTROPY_FILL` is removed.

- [ ] **Step 1: Write the failing tests:**
  - `test_entropy_reduce_keeps_bytes_when_vs_zero`: patch the `.rdata` VS at `0x170 + 8` to 0, apply, and assert the `.rdata` raw bytes are unchanged.
  - `test_entropy_reduce_never_raises_entropy`: on the default fixture and on `full_pe_path`, for each section compare `shannon_entropy` of the raw bytes before and after, and assert after ≤ before.
  - `test_entropy_reduce_keeps_used_bytes`: put non-zero junk (`bytes(range(256))[:0x40]`) in `.text` slack at `0x200 + 1`, apply, and assert that `.text[0:1] == b"\xC3"` and that the slack is now uniform.
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_entropy_reduce.py -v`. Expected: the VS-zero and never-raises tests FAIL.
- [ ] **Step 3: Implement** the changes.
- [ ] **Step 4: Run** `.venv/bin/python -m pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit** `fix(entropy_reduce): respect VS=0 and only write when entropy drops`

---

### Task 9: header_normalize strips the Rich header and debug data correctly (#5, #8, IndexError)

**Depends on:** Task 1

**Files:**
- Modify: `src/techniques/header_normalize.py`
- Modify: `tests/test_header_normalize.py`

**Interfaces:**
- Produces: `HeaderNormalize.apply(pe)`.
  - `_strip_rich_header`: DanS marker is `xor_key ^ 0x536E6144`. If it is not found before "Rich", return without writing. Otherwise zero `[dans, rich + 8)`.
  - `_zero_debug_directory`: if `NumberOfRvaAndSizes <= 6` or the entry is empty, return. Otherwise, for each `pe.DIRECTORY_ENTRY_DEBUG` entry, zero its raw data `[PointerToRawData, +SizeOfData)` and then the debug directory bytes, then zero DATA_DIRECTORY[6] (struct and bytes).
  - New `_zero_directory_timestamps`: set the export directory's TimeDateStamp to 0, and the top-level resource directory's TimeDateStamp if present (struct and bytes).

- [ ] **Step 1: Write the failing tests** (replace the vacuous `test_header_normalize_zeros_debug_directory`):
  - `test_rich_header_removed_dos_header_intact(full_pe_path)`: after apply, `data[:2] == b"MZ"`, `e_lfanew` is unchanged, `b"Rich" not in data[0x40:e_lfanew]`, and `pefile.PE(data=pe.write()).parse_rich_header() is None`.
  - `test_corrupt_rich_header_left_untouched` (Review Focus): build with `rich_header=True`, overwrite the 4 bytes at 0x80 with zeros (killing DanS), apply only `_strip_rich_header`, and assert `data[0x40:0x100]` is unchanged.
  - `test_debug_data_and_pdb_path_wiped(full_pe_path)`: after apply, `rb"project.pdb" not in data`, `b"RSDS" not in data`, DATA_DIRECTORY[6] is (0, 0), and `DEBUG_TIMESTAMP` packed `<I` no longer appears where the debug entry was.
  - `test_export_timestamp_zeroed(full_pe_path)`: the reparsed `DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp == 0`.
  - `test_few_data_directories_no_crash`: set `pe.OPTIONAL_HEADER.NumberOfRvaAndSizes = 5` and `del pe.OPTIONAL_HEADER.DATA_DIRECTORY[5:]`, and apply without raising.
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_header_normalize.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the changes. Write through `safe_write` and also set the struct attributes, so the result does not depend on Task 2.
- [ ] **Step 4: Run** `.venv/bin/python -m pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit** `fix(header_normalize): correct DanS constant, wipe debug data and timestamps`

---

### Task 10: Section names stay unique and never claim critical names (#6)

**Depends on:** Task 1

**Files:**
- Modify: `src/techniques/section_rename.py`
- Modify: `src/techniques/junk_sections.py`
- Modify: `tests/test_section_rename.py`
- Modify: `tests/test_junk_sections.py`

**Interfaces:**
- Produces: `SectionRename.apply(pe)`. Algorithm:
  1. Let `reserved` be the names of sections whose current name is in `CRITICAL_SECTION_NAMES`.
  2. Let `pool` be a shuffled `[n for n in MSVC_SECTION_NAMES if n not in CRITICAL_SECTION_NAMES]`.
  3. Let `renameable` be the non-critical sections in order. Pick the largest `m` such that the first `m` get renamed, the rest keep their names, and `len([n for n in pool if n not in reserved | names(rest)]) >= m`.
  4. Assign those pool names to the first `m`. The final names are all distinct, unless the input already had duplicates among kept sections.
  
  It never raises.
- Produces: `JunkSections.apply(pe)` picks `random.choice` from `_DECOY_NAMES` minus the existing section names. If none is left, it raises `TechniqueError("No unused decoy section name")`.

- [ ] **Step 1: Write the failing tests:**
  - `test_rename_never_assigns_critical_names`: loop 50 times over `make_minimal_pe64()`, and no resulting name may be in `CRITICAL_SECTION_NAMES`.
  - `test_rename_names_unique_with_many_sections`: use `make_minimal_pe64(extra_sections=[(n, b"z") for n in [".data", ".pdata", ".rsrc", ".reloc", ".gfids", ".00cfg", ".foo"]])`. Loop 50 times: names are unique, `.rsrc` and `.reloc` are each present exactly once and on the same section indices as before.
  - `test_junk_section_name_unused`: loop 50 times. Apply `SectionRename` then `JunkSections` to `make_minimal_pe64(extra_sections=[(".gfids", b"z"), (".00cfg", b"z")])` (header space permitting) and assert the section names are unique.
  - `test_junk_section_no_name_left`: use a fixture whose sections already use all four decoy names, and expect `pytest.raises(TechniqueError)`.
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_section_rename.py tests/test_junk_sections.py -v`. Expected: FAIL.
- [ ] **Step 3: Implement** the changes.
- [ ] **Step 4: Run** `.venv/bin/python -m pytest -q`. Expected: all pass.
- [ ] **Step 5: Commit** `fix(section_rename): unique names, critical names reserved; junk picks unused name`

---

### Task 11: End-to-end pipeline on the full-hazard fixture

**Depends on:** Tasks 2-10

**Files:**
- Modify: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: `full_pe_path`, all techniques, `ObfuscationPipeline.run`.

- [ ] **Step 1: Write the test** `test_full_pipeline_on_full_fixture` (Review Focus): run all six techniques in `_ALL_TECHNIQUES` order on `full_pe_path`, then reparse the output. Assert:
  - the import DLL and names equal the originals, and `ExportedFunction` is still exported;
  - the section names are unique, and the entry-point byte is intact: `out.get_data(out.OPTIONAL_HEADER.AddressOfEntryPoint, 1) == b"\xC3"`;
  - `out.verify_checksum()`;
  - `parse_rich_header() is None`;
  - `get_overlay()` contains `b"OVERLAY!" * 8`.
- [ ] **Step 2: Run** `.venv/bin/python -m pytest tests/test_pipeline.py -v`. Expected: PASS. If it fails, find the owning task's bug and fix it there with a regression test in that task's test file.
- [ ] **Step 3: Run** `.venv/bin/python -m pytest -q --cov=src`. Expected: all pass, and coverage is at least the 60% baseline.
- [ ] **Step 4: Commit** `test: end-to-end pipeline on full-hazard fixture`
