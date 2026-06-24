# payload-obfuscator: Rebuild & Modernize Design

**Date:** 2026-06-24
**Scope:** Full rebuild — correct working core + modernized Windows 11 / EDR evasion techniques
**Target:** Generic x64 PE files (shellcode loaders, C2 implants, arbitrary EXEs)
**Run environment:** Linux/Kali (cross-platform Python driver); output deployed on Windows 11

---

## 1. Goals

1. Produce a tool that actually runs end-to-end and emits a structurally valid, working PE.
2. Apply modern static evasion techniques effective against Windows 11 + current commercial EDRs (Defender, CrowdStrike, SentinelOne).
3. Lay groundwork for Phase 2 memory/runtime evasion (ETW, AMSI, unhooking, header stomp).
4. Be testable: each technique independently verifiable against a real PE fixture.

Non-goals for this phase: GUI, support for x86 (32-bit) PEs, dynamic behavioral evasion at the process level (Phase 2).

---

## 2. Architecture

The tool is a Python package with three layers: **core** (pipeline + PE I/O), **techniques** (independently composable evasion passes), and **stubs** (verified x64 shellcode constants).

```
payload-obfuscator/
├── src/
│   ├── core/
│   │   ├── pipeline.py         # Runs the technique chain
│   │   ├── pe_loader.py        # pefile load/save, append_section_data, fix_headers
│   │   └── validator.py        # Pre/post structural validation
│   ├── techniques/
│   │   ├── base.py             # BaseTechnique ABC
│   │   ├── section_rename.py   # Section name normalization
│   │   ├── string_encrypt.py   # String XOR encryption + runtime decryptor injection
│   │   ├── import_hash.py      # Replace imports with PEB-walk hash resolver
│   │   ├── entropy_reduce.py   # Pad encrypted sections to reduce Shannon entropy
│   │   ├── header_normalize.py # Strip Rich header, debug dir, zero TimeDateStamp
│   │   └── junk_sections.py    # Add decoy low-entropy sections
│   ├── stubs/
│   │   ├── xor_decryptor_x64.py  # Verified x64 decryptor bytes (STUB_BYTES constant)
│   │   └── api_hasher_x64.py     # Verified x64 PEB-walk ROR-13 resolver bytes
│   └── utils/
│       ├── pe_math.py          # RVA/offset/alignment arithmetic, safe_write
│       └── constants.py        # Section characteristics, MSVC section names
├── tests/
│   ├── fixtures/               # Small committed real x64 PE binaries
│   └── test_*.py               # Per-technique unit tests
└── __main__.py
```

### Key principle: one mandatory header-fix pass

No technique is responsible for maintaining `SizeOfImage`, `NumberOfSections`, `SizeOfHeaders`, or `PointerToRawData`. After all techniques run, `pe_loader.fix_headers(pe)` recomputes every derived header field in one place. This eliminates the entire class of bugs where one technique's header edits were invalidated by a later technique.

---

## 3. Core Layer

### 3.1 `pe_loader.py`

Owns all PE I/O and the only correct header arithmetic in the codebase.

**Public API:**
```python
def load(path: Path) -> pefile.PE
def save(pe: pefile.PE, path: Path) -> None
def fix_headers(pe: pefile.PE) -> None       # mandatory after all techniques
def append_section_data(pe: pefile.PE, data: bytes) -> int   # returns file offset
def safe_write(pe: pefile.PE, offset: int, data: bytes) -> None  # bounds-checked
```

`fix_headers` recomputes:
- `FILE_HEADER.NumberOfSections` = `len(pe.sections)`
- `OPTIONAL_HEADER.SizeOfHeaders` = aligned size of DOS header + NT headers + section table
- `OPTIONAL_HEADER.SizeOfImage` = `align(max(s.VirtualAddress + s.Misc_VirtualSize for s in pe.sections), SectionAlignment)`
- `PointerToRawData` for every section (repack sequentially if any section grew)
- `OPTIONAL_HEADER.CheckSum` via `pe.generate_checksum()`

`append_section_data(pe, data)` is the one sanctioned way to grow the file: it appends `data` to `pe.__data__`, returns the file offset of the new bytes, and rounds up to `FileAlignment`.

`safe_write(pe, offset, data)` asserts `offset + len(data) <= len(pe.__data__)` before writing, raising `PEWriteError` otherwise. No silent out-of-bounds writes.

### 3.2 `validator.py`

`pre_validate(pe)`: confirms PE magic, valid `e_lfanew`, at least one section, x64 magic (`0x20b`). Raises `ValidationError` early if the input is not a usable PE64.

`post_validate(pe)`: confirms `NumberOfSections` matches `len(pe.sections)`, `SizeOfImage` is section-aligned, all `PointerToRawData` values are within `len(pe.__data__)`. This is a sanity net after `fix_headers`; it does not re-parse import/resource directories.

### 3.3 `pipeline.py`

```python
class ObfuscationPipeline:
    def run(self, input_path: Path, output_path: Path,
            techniques: list[BaseTechnique]) -> bool:
        pe = pe_loader.load(input_path)
        validator.pre_validate(pe)

        for technique in techniques:
            try:
                technique.apply(pe)
                logger.success(f"{technique.name}: applied")
            except TechniqueError as e:
                if technique.required:
                    raise
                logger.warning(f"{technique.name}: skipped ({e})")

        pe_loader.fix_headers(pe)
        validator.post_validate(pe)
        pe_loader.save(pe, output_path)
        return True
```

Each technique declares `required: bool`. Non-required techniques (e.g. `junk_sections`) are skipped on failure without aborting. Required techniques (e.g. `fix_headers` itself, `save`) abort the run.

### 3.4 `pe_math.py`

Single source of truth for all arithmetic:

```python
def rva_to_offset(pe, rva: int) -> int
def offset_to_rva(pe, offset: int) -> int
def align(value: int, boundary: int) -> int   # rounds up to boundary
def section_slack(section) -> int             # SizeOfRawData - Misc_VirtualSize
def find_section_by_name(pe, name: str)       # returns SectionStructure or None
def find_executable_section(pe)               # first section with MEM_EXECUTE
```

---

## 4. Technique Interface

```python
# techniques/base.py
from abc import ABC, abstractmethod
import pefile

class BaseTechnique(ABC):
    name: str           # display name for logging
    required: bool = False

    @abstractmethod
    def apply(self, pe: pefile.PE) -> None:
        """Mutate pe in place. Raise TechniqueError on failure."""
```

Each technique receives a `pefile.PE` object loaded with `fast_load=False` and mutates it directly. Techniques do not call `fix_headers` or `pe.write()` — that is the pipeline's job.

---

## 5. Phase 1 Techniques

### 5.1 `section_rename`

Renames sections to a plausible MSVC-compiled mix. Draws from a curated list of real section names (`.text`, `.rdata`, `.data`, `.pdata`, `.rsrc`, `.reloc`, `.tls`, `.debug`). Critical sections (`.rsrc`, `.reloc`) are never renamed. Applies the name by writing padded bytes directly to the section header in `pe.__data__` at the correct file offset — no `section.Name =` in-memory-only mutation.

### 5.2 `string_encrypt`

1. Scans `.rdata` and `.data` sections for printable ASCII/UTF-16LE strings ≥ 8 characters.
2. XOR-encrypts each string in place using a per-string random 1-byte key.
3. Builds a decryption table: `[(rva, length, key), ...]` for all encrypted strings.
4. Injects the `xor_decryptor_x64` stub + the table into section slack space (or a new section if no slack available).
5. Adds a TLS callback entry that calls the stub before `main`, so strings are decrypted at load time before any IAT-based AV scan.

The stub calling convention: `rcx = table_ptr`, `rdx = entry_count`. The stub iterates the table and XORs each string in place.

If no TLS directory exists, the technique creates one. This is the most complex technique; it is `required = False` and skips gracefully if the PE has no suitable section.

### 5.3 `import_hash`

1. Identifies high-risk imports: `VirtualAlloc`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateThread`, `CreateRemoteThread`, `NtAllocateVirtualMemory`, `LoadLibraryA/W`, `GetProcAddress`.
2. For each high-risk import, removes the entry from the import descriptor table (zeroes the thunk RVA) so it no longer appears as a named import.
3. Injects the `api_hasher_x64` stub and a hash-lookup table `[{hash: u32, slot: u32}, ...]` into section slack or a new section.
4. Injects a small init stub (called via TLS or from the resolver table itself) that, at load time, calls the resolver for each entry and writes the resolved VA into a shadow IAT in the injected section.
5. Patches each original call site (`call [__imp_VirtualAlloc]`-style indirect calls) to instead `call [shadow_iat_slot]`. This requires a capstone disassembly pass over `.text` to find IAT-indirect call patterns.
6. The Python side pre-computes hashes using the exact same ROR-13 algorithm embedded in the stub (single `ror13_hash` function in `pe_math.py`, used by both).
7. Leaves benign imports (`GetLastError`, `ExitProcess`, string functions) in the original IAT to maintain a plausible-looking import table.

Note: step 5 (call-site patching) is the most mechanically complex step and is the primary implementation risk. If call sites cannot be reliably identified via static disasm (e.g. indirect jumps through registers), the technique falls back to: keep the IAT entry but overwrite the import name string with a benign decoy name, and rely on the init stub to fix up the resolved address. This is a weaker form but does not require call-site patching.

### 5.4 `entropy_reduce`

After `string_encrypt` runs, encrypted sections have high Shannon entropy (~7.9 bits/byte). This technique appends structured low-entropy "padding" (e.g. repeated patterns derived from the section name, resembling uninitialized data) to bring section entropy below 6.8. The amount appended is calculated so the final entropy is in the 6.0–6.7 range.

Implementation: append bytes to `pe.__data__`, update `SizeOfRawData` for the section, leave `Misc_VirtualSize` unchanged (the padding is not mapped into virtual memory — it is file slack).

### 5.5 `header_normalize`

- **Rich header**: located by scanning backward from the PE signature for `Rich` marker; zeroed out (replaced with `DanS` stub zeros).
- **Debug directory**: zero out `IMAGE_DIRECTORY_ENTRY_DEBUG` RVA and size; zero the pointed-to `IMAGE_DEBUG_DIRECTORY` struct.
- **TimeDateStamp**: zero in both `FILE_HEADER` and any `EXPORT_DIRECTORY`.
- **Checksum**: zeroed here (will be recomputed correctly by `fix_headers`).
- **Version info**: if a `VS_VERSIONINFO` resource exists, overwrite `CompanyName`/`FileDescription` with plausible Microsoft values; if none exists, skip.

### 5.6 `junk_sections`

Adds one decoy section (`.debug` or a random MSVC-style name) containing 512–2048 bytes of low-entropy data (a mix of zeros and repeated ASCII text). Purpose: disrupts YARA rules that match on section count or layout patterns. The section has characteristics `IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ` — readable, non-executable, non-writable.

---

## 6. Runtime Stubs

### 6.1 Design constraint

Stubs are pre-assembled: each stub file contains a single `STUB_BYTES: bytes` constant that has been assembled from commented asm source (kept as a string constant in the same file for reference) and tested on a real Windows 11 x64 VM. The assembler (keystone) is used once to produce the bytes; the output is committed as a literal. At runtime, `keystone` is not required.

### 6.2 `xor_decryptor_x64`

```
; Calling convention: rcx = ptr to [{rva: u32, len: u32, key: u8}, ...], rdx = entry count
; All registers preserved (full push/pop frame)
; For each entry: XOR bytes at (image_base + rva) with key, length times
```

The stub locates `image_base` from the TLS callback's third argument (`PVOID Reserved`), which on Windows 8+ contains the image base. Fallback: `lea rax, [rip-offset]` to derive image base from a known RVA.

### 6.3 `api_hasher_x64`

ROR-13 PEB-walk resolver. Standard algorithm:
```
; hash(name) = for each char c in uppercase(name): hash = ROR32(hash, 13) + c
; Walk PEB->Ldr->InMemoryOrderModuleList
; For each module: walk export table, hash each export name, compare
; On match: return function address in rax
; Calling convention: rcx = hash_value -> rax = function_ptr (or 0 on failure)
```

The Python-side hash function in `pe_math.py` uses the identical algorithm. There is exactly one implementation; the stub bytes are the compiled form of it.

### 6.4 Stub verification

`stubs/verify_stubs.py` is a standalone script (not part of the main test suite) intended to run on a Windows VM:
- Allocates executable memory via ctypes
- Copies stub bytes in
- Calls stub with known inputs
- Asserts expected outputs

This is run manually when stubs are updated and before committing new stub bytes.

---

## 7. Error Handling

Two exception types:

- `PEError(Exception)` — base; raised by `pe_loader` and `validator` for unrecoverable load/save problems.
- `TechniqueError(Exception)` — raised by any technique when it cannot apply. Pipeline skips non-required techniques on this; aborts on required ones.

No broad `except Exception` swallowing. Each `try/except` catches the narrowest applicable type and either re-raises as `TechniqueError` or logs-and-skips.

---

## 8. Phase 2 Techniques (design only, not implemented this cycle)

| Technique | Mechanism | Dependency |
|---|---|---|
| `header_stomp` | TLS callback zeroes PE headers after load | Verified stub on Win11 |
| `etw_patch` | Patch `EtwEventWrite` to `ret 0` | ntdll offset varies; needs version-aware lookup |
| `amsi_patch` | Patch `AmsiScanBuffer` to return `AMSI_RESULT_CLEAN` | Same |
| `unhook` | Map fresh ntdll from disk, restore `.text` section | Most complex; defeats userland hook EDRs |

These are designed to slot into the same `BaseTechnique` interface without changes to the pipeline.

---

## 9. Testing Strategy

### Fixtures

`tests/fixtures/` contains:
- `hello_x64.exe` — minimal x64 PE (compiled with MinGW `x86_64-w64-mingw32-gcc` on Kali, or any small stripped Windows binary). Small, clean, known structure.
- `loader_x64.exe` — a minimal shellcode loader skeleton (MinGW-compiled, no actual shellcode payload — just the IAT and allocation calls). Tests import-heavy obfuscation.

Build script committed at `tests/fixtures/build.sh` (MinGW). Both EXEs are committed to the repo. Their SHA-256 hashes are asserted at the start of each test to catch fixture tampering.

### Per-technique tests

Each test follows the pattern:
```python
def test_section_rename_produces_valid_pe(fixture_pe):
    technique = SectionRename()
    pe = pe_loader.load(fixture_pe)
    technique.apply(pe)
    pe_loader.fix_headers(pe)
    # 1. Output parses without pefile error
    out = write_and_reload(pe)
    # 2. Technique-specific assertion
    assert all(s.Name.rstrip(b'\x00').decode() in KNOWN_MSVC_NAMES for s in out.sections
               if s.Name.rstrip(b'\x00').decode() not in CRITICAL_SECTIONS)
    # 3. Structural integrity
    assert out.OPTIONAL_HEADER.SizeOfImage % out.OPTIONAL_HEADER.SectionAlignment == 0
    assert out.FILE_HEADER.NumberOfSections == len(out.sections)
```

### String encrypt round-trip

A Python reimplementation of the stub's XOR loop validates that the encrypted bytes, decrypted using the same key table, reproduce the original strings. This tests correctness without needing a Windows VM.

---

## 10. CLI

```
python -m payload_obfuscator <input.exe> [options]

Options:
  -o, --output PATH          Output path (default: <input>_obf.exe)
  --techniques LIST          Comma-separated list of techniques to apply
                             (default: all Phase 1 techniques in order)
  --skip LIST                Techniques to skip
  --list-techniques          Print available techniques and exit
  --verbose                  Debug logging
```

Default technique order: `header_normalize` → `section_rename` → `string_encrypt` → `import_hash` → `entropy_reduce` → `junk_sections`. Order matters: header normalization before structural changes, entropy reduction after encryption.

---

## 11. Packaging

- `requirements.txt`: `pefile>=2023.2.7`, `loguru>=0.7.2`, `pycryptodomex>=3.19.0` (imports as `Cryptodome`), `capstone>=5.0` (disasm for call-site patching in `import_hash`), `rich>=13.6.0`. No `keystone-engine` at runtime (stubs are pre-assembled); keystone stays as a dev-only dependency for stub generation.
- `setup.py` / `pyproject.toml`: `python_requires=">=3.10"`, entry point `payload-obfuscator = src.__main__:main`.
- No Windows-only imports in the driver. `wmi`, `netifaces`, `psutil` are removed.

---

## 12. What Is Deleted from the Current Codebase

| Old module | Reason deleted |
|---|---|
| `src/handlers/pe_handler.py` | Docstring-only; no class |
| `src/handlers/anti_analysis/` | All checks were stubs or false-positives; runtime anti-analysis belongs in stubs, not the Python driver |
| `src/utils/code_mutation/` | Instruction substitution/dispatch was broken; offset fixup never implemented; defer to Phase 2 if revived |
| `src/handlers/string_encryption/encryptor.py` | Non-invertible ciphers, wrong crypto import, no runtime stub for most modes |
| `src/utils/import_obfuscation/resolver.py` | Wrong hash algorithm; hash mismatch with shellcode |
| `tests/test_obfuscator.py` | Imports non-existent modules; tests non-existent methods |
| Both `HandlerError` duplicates | Replaced by `PEError` / `TechniqueError` |

Salvaged with fixes: `src/handlers/pe/checksum_handler.py` (logic is correct; integrate into `pe_loader.fix_headers`), `src/handlers/pe/section/constants.py` (section characteristic constants are valid), `src/utils/import_obfuscation/resolver_generator.py` (hash algorithm and shellcode are correct; export this one).
