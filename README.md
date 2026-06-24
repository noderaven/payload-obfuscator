# payload-obfuscator

A Python tool that applies static evasion techniques to Windows PE64 binaries. Built for OSEP (PEN-300) study and Windows 11 / EDR static-detection research. For authorized lab use only.

## Status: Phase 1 (static evasion)

Phase 1 produces a structurally valid, signature-poor PE that defeats common static heuristics. The injected XOR string decryptor and PEB-walk API resolver stubs are written into the binary but are not yet invoked at load time, so the output binaries are not runtime-functional. TLS callback wiring is Phase 2.

## Techniques

Applied in this order via `ObfuscationPipeline`:

1. `header_normalize` - zero TimeDateStamp, strip Rich header, wipe debug directory
2. `string_encrypt` - XOR-encrypt printable ASCII strings in `.rdata`/`.data`; inject decryptor stub and table
3. `import_hash` - overwrite high-risk import names (VirtualAlloc, CreateThread, etc.) with benign decoys; inject ROR-13 PEB-walk resolver stub
4. `section_rename` - rename sections to plausible MSVC names; preserve critical sections (`.rsrc`, `.reloc`, `.tls`)
5. `entropy_reduce` - fill section slack with low-entropy patterns to defeat packer heuristics
6. `junk_sections` - append a low-entropy decoy section

## Install

```bash
git clone https://github.com/noderaven/payload-obfuscator.git
cd payload-obfuscator
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Python 3.10+ required. Runs cross-platform; tested on Linux/Kali.

## Usage

```bash
# List available techniques
python __main__.py --list-techniques

# Obfuscate a binary (default output: <name>_obf.exe)
python __main__.py path/to/input.exe

# Specify output, skip techniques, enable debug logging
python __main__.py input.exe -o output.exe --skip junk_sections,entropy_reduce --verbose
```

After `pip install -e .` the `payload-obfuscator` console script is also available.

## Development

```bash
pip install -r requirements-dev.txt
pytest                          # 47 tests
python src/stubs/generate.py    # regenerate stub bytes (requires keystone-engine)
```

Design notes and the implementation plan live under `docs/superpowers/`.

## Disclaimer

Educational use only. Intended for authorized lab targets and self-study related to OSEP (PEN-300) coursework. The author is not responsible for misuse.
