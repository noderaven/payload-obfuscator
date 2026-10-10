"""ObfuscationPipeline: runs the technique chain and saves the result."""
from pathlib import Path
from typing import Sequence
import pefile
from loguru import logger
from src.core import pe_loader, validator
from src.techniques.base import BaseTechnique, TechniqueError


class ObfuscationPipeline:
    def run(
        self,
        input_path: Path,
        output_path: Path,
        techniques: Sequence[BaseTechnique],
    ) -> bool:
        pe = pe_loader.load(input_path)
        try:
            validator.pre_validate(pe)
            applied = []
            for technique in techniques:
                snapshot = pe.write()
                try:
                    technique.apply(pe)
                    logger.success(f"[{technique.name}] applied")
                    applied.append(technique.name)
                except TechniqueError as exc:
                    if technique.required:
                        raise
                    # Discard any partial edits the technique made before failing.
                    pe.close()
                    pe = pefile.PE(data=bytearray(snapshot))
                    logger.warning(f"[{technique.name}] skipped: {exc}")

            pe_loader.fix_headers(pe)
            validator.post_validate(pe)
            pe_loader.save(pe, output_path)
            logger.success(f"Saved to {output_path} (techniques: {', '.join(applied)})")
            return True
        finally:
            pe.close()
