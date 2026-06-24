"""Rename PE sections to plausible MSVC-compiled names."""
import random
import pefile
from src.techniques.base import BaseTechnique, TechniqueError
from src.core.pe_loader import safe_write
from src.utils.constants import MSVC_SECTION_NAMES, CRITICAL_SECTION_NAMES


class SectionRename(BaseTechnique):
    name = "section_rename"

    def apply(self, pe: pefile.PE) -> None:
        available = list(MSVC_SECTION_NAMES)
        random.shuffle(available)
        used: set[str] = set()

        for section in pe.sections:
            current = section.Name.rstrip(b"\x00").decode("ascii", errors="replace")

            if current in CRITICAL_SECTION_NAMES:
                used.add(current)
                continue

            candidates = [n for n in available if n not in used and n != current]
            if not candidates:
                candidates = [n for n in available if n not in CRITICAL_SECTION_NAMES]
            if not candidates:
                raise TechniqueError("Ran out of MSVC section names to assign")

            new_name = candidates[0]
            used.add(new_name)

            name_bytes = new_name.encode("ascii").ljust(8, b"\x00")[:8]
            safe_write(pe, section.get_file_offset(), name_bytes)
            section.Name = name_bytes
