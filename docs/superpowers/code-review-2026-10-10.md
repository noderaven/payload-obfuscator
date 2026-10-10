# payload-obfuscator code review (2026-10-10)

Full-repo review by 5 parallel read-only reviewers (core PE layer, code-injecting
techniques + stubs, header/section techniques, pipeline/CLI/packaging, tests).
Baseline: origin/main 87f405c. Local only (docs/superpowers/ is gitignored).

Context: README says Phase 1 output is not runtime-functional (stubs are injected
but not invoked; TLS wiring is Phase 2). Findings are split accordingly.

Confidence key: [run] confirmed by running code, [read] confirmed by reading code,
[not run] traced by hand only.

## Related open PR

- noderaven/payload-obfuscator#3 (branch docs-readme-install-windows): README install
  steps (Windows activate line, `pip install -e .`) and pyproject build-backend fix
  (`setuptools.backends.legacy:build` does not exist -> `setuptools.build_meta`).
  Verified in a fresh venv; 47 tests pass. Gemini had not reviewed it after ~15 min.

## Phase 1 defects

### High
1. string_encrypt encrypts loader-needed strings (DLL names, import names, export
   names) in .rdata; pefile finds no imports afterwards, so the binary cannot load.
   Also blocks Phase 2 (imports resolve before TLS). src/techniques/string_encrypt.py:73-86 [run]
   Fix: exclude ranges of import/delay-import/export/debug/load-config/TLS/exception
   directories and every name string they reference.
2. Pipeline "skips" a technique on TechniqueError but keeps its partial edits.
   string_encrypt encrypts strings, then fails to place the stub; strings are lost
   (keys stored nowhere), exit 0. src/core/pipeline.py:22-29 [run]
   Fix: snapshot pe.__data__ + header state per technique and restore on failure,
   or check all preconditions before writing.
3. entropy_reduce overwrites the whole section when Misc_VirtualSize == 0.
   src/techniques/entropy_reduce.py:26 [run]
4. Test fixture is malformed: optional header format in tests/conftest.py:48 ends in
   `xx` (114 bytes into 112-byte slot hdr[0x58:0xC8]); all section data shifted +2,
   file 0x602 bytes, entry point byte is 00. Fix: drop `xx`. [run]

### Medium
5. Rich header strip uses big-endian "DanS" constant 0x44616E53; correct LE dword is
   0x536E6144. Marker never found, start=0, zeroes from MZ to Rich+8.
   src/techniques/header_normalize.py:34 [run] Fix: correct constant; return
   without writing if DanS not found.
6. section_rename: .rsrc/.reloc/.tls are in the assignable pool and only reserved
   when reached; fallback allows duplicates; junk_sections reuses names.
   Real binary: code section named .reloc, two .rsrc, two .reloc.
   src/techniques/section_rename.py:13-26, src/utils/constants.py [run]
   Fix: pre-reserve existing critical names, remove critical names from pool,
   never duplicate (leave unrenamed), junk_sections picks an unused name.
7. entropy_reduce raises entropy: slack is already zeros; 00..07 pattern adds
   entropy (.reloc 2.5 -> 3.5, _RDATA 1.1 -> 3.6). src/techniques/entropy_reduce.py:18,35 [run]
8. Debug wipe only zeroes DATA_DIRECTORY[6]; RSDS/PDB path and debug entry
   TimeDateStamps remain; export/resource timestamps untouched.
   src/techniques/header_normalize.py:48-56 [run]
9. --skip silently ignores unknown names; _TECHNIQUE_MAP unused.
   src/__main__.py:28-32,73-74 [run] Fix: resolve via map, parser.error on unknown.
10. pre_validate checks Magic 0x20B only, not Machine == 0x8664; ARM64 PE32+ passes.
    src/core/validator.py:12 [run]
11. append_section_data appends at EOF after overlay/Authenticode cert; security
    directory left pointing mid-file. src/core/pe_loader.py:46-57 [run]
12. append_new_section header-space check ignores data after the section table
    (bound import dir 11 gets overwritten). src/core/pe_loader.py:93-122 [run]
    (same root cause as the junk_sections finding)
13. New section VA and SizeOfImage use Misc_VirtualSize only; VS=0 last section ->
    overlapping VA, image fails to load. src/core/pe_loader.py:68,104-105 [run]
    Fix: effective size = vs or SizeOfRawData. Same root cause as #3.
14. safe_write writes only __data__; generate_checksum -> pe.write() repacks parsed
    structures and reverts overlapping raw writes. src/core/pe_loader.py:30-37 [run]
    Fix: detect overlap with pe.__structures__ and raise, or document the rule.

### Low
- header_normalize IndexError when NumberOfRvaAndSizes < 7 (aborts pipeline). header_normalize.py:50
- Output path == input path overwrites original, non-atomic write. __main__.py:71, pe_loader.py:27
- PE handle leaked when pre_validate raises (outside try/finally). pipeline.py:16-17
- capstone and pycryptodomex listed as runtime deps but never imported.
- Package installs as top-level `src` (collision risk). Rename to payload_obfuscator.
- --verbose is a no-op (loguru default is DEBUG; no debug calls).
- Rich Console wraps output path at 80 cols when not a TTY.
- Help/README say default output `<input>_obf.exe`; actual is `<stem>_obf<suffix>`.
- fix_headers can shrink SizeOfHeaders. pe_loader.py:74
- Low-alignment images (SA < 0x1000) get raw != VA for appended section.
- rva_to_offset/offset_to_rva fail for header region (only used by tests). pe_math.py:16-33

## Phase 2 blockers
- import_hash decoys not real exports: GetSystemInfoA, FreeLibraryW,
  NtQueryInformation; decoy map ignores DLL (api-ms-win-* imports break).
  src/techniques/import_hash.py:20-34 [read]
- Nothing patches the IAT from the (iat_rva, hash) table; calls land in decoys.
- Decryptor writes to read-only .rdata; fallback .init section is CHARS_RDATA
  (not executable). string_encrypt.py:103
- Decryptor ABI (rcx/rdx/r8 = base/table/count) != TLS callback ABI; no run-once
  guard; XOR re-encrypts on every thread attach.
- PEB-walk resolver loops forever when hash not found (no list-head check).
  src/stubs/generate.py:119-121 [not run]
- Forwarded exports not handled by resolver. [not run]

## Tests
- 47 pass, 60% coverage. Gaps: __main__.py 0%, import_hash.py 23% (45-86),
  header_normalize.py 30-46/53-56, string_encrypt.py 102-106 fallback, validator
  failure branches.
- Fixture has no imports, Rich header, debug dir, relocs, TLS, overlay.
- Vacuous: test_xor_decrypt_table_round_trips (tests a helper production never
  uses), test_ror13_hash_used_in_import_hash_is_consistent (h == h),
  test_string_encrypt_skips_pe_without_suitable_slack (no assertion),
  test_string_encrypt_output_parses_when_stub_empty (pytest.raises(Exception)),
  test_header_normalize_zeros_debug_directory (debug dir already zero).
- Worth adding: verify_checksum on pipeline output; bytes up to VirtualSize unchanged
  by entropy_reduce; fixture with real imports + Rich header + debug dir; unicorn
  test tying stub ROR-13 loop to pe_math.ror13_hash; CLI tests via main([...]).

## Suggested next step
Turn Phase 1 items 1-14 + the fixture fix into an implementation plan
(superpowers:writing-plans), then execute with parallel-lanes.
Shared root causes: #3/#13 (VirtualSize 0), #12/junk_sections (header space).
