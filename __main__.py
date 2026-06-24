"""CLI entry point for payload-obfuscator."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from loguru import logger
from rich.console import Console

from src.core.pipeline import ObfuscationPipeline
from src.techniques.header_normalize import HeaderNormalize
from src.techniques.section_rename import SectionRename
from src.techniques.string_encrypt import StringEncrypt
from src.techniques.import_hash import ImportHash
from src.techniques.entropy_reduce import EntropyReduce
from src.techniques.junk_sections import JunkSections

_CONSOLE = Console()

_ALL_TECHNIQUES = [
    HeaderNormalize,
    StringEncrypt,
    ImportHash,
    SectionRename,
    EntropyReduce,
    JunkSections,
]

_TECHNIQUE_MAP = {}
for _cls in _ALL_TECHNIQUES:
    _t = _cls()
    _TECHNIQUE_MAP[_cls.__name__.lower()] = _cls
    _TECHNIQUE_MAP[_t.name] = _cls


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="payload-obfuscator",
        description="PE64 obfuscator for Windows 11 / EDR evasion study (Phase 1: static)",
    )
    parser.add_argument("input", type=Path, nargs="?", help="Input PE64 file")
    parser.add_argument(
        "-o", "--output", type=Path, default=None,
        help="Output path (default: <input>_obf.exe)",
    )
    parser.add_argument(
        "--skip", type=str, default="",
        help="Comma-separated technique names to skip",
    )
    parser.add_argument(
        "--list-techniques", action="store_true",
        help="Print available techniques and exit",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    args = parser.parse_args(argv)

    if args.list_techniques:
        print("Available techniques (applied in this order):")
        for cls in _ALL_TECHNIQUES:
            t = cls()
            req = " [required]" if t.required else ""
            print(f"  {t.name}{req}")
        return 0

    if args.input is None:
        parser.error("the following arguments are required: input")

    if not args.input.exists():
        logger.error(f"Input file not found: {args.input}")
        return 1

    output = args.output or args.input.with_name(args.input.stem + "_obf" + args.input.suffix)

    skip = {s.strip().lower() for s in args.skip.split(",") if s.strip()}
    techniques = [cls() for cls in _ALL_TECHNIQUES if cls().name not in skip]

    if args.verbose:
        logger.remove()
        logger.add(sys.stderr, level="DEBUG")

    pipeline = ObfuscationPipeline()
    try:
        pipeline.run(args.input, output, techniques)
        _CONSOLE.print(f"[bold green]Done:[/bold green] {output}")
        return 0
    except Exception as exc:
        logger.error(f"Failed: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
