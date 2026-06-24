"""ObfuscationPipeline: runs the technique chain and saves the result."""
from pathlib import Path
from typing import Sequence
from loguru import logger
import pefile

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
        validator.pre_validate(pe)

        applied = []
        for technique in techniques:
            try:
                technique.apply(pe)
                logger.success(f"[{technique.name}] applied")
                applied.append(technique.name)
            except TechniqueError as exc:
                if technique.required:
                    pe.close()
                    raise
                logger.warning(f"[{technique.name}] skipped: {exc}")

        pe_loader.fix_headers(pe)
        validator.post_validate(pe)
        pe_loader.save(pe, output_path)
        pe.close()
        logger.success(f"Saved to {output_path} (techniques: {', '.join(applied)})")
        return True
