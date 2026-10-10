"""Rename PE sections to plausible MSVC-compiled names."""
import random
import pefile
from src.techniques.base import BaseTechnique
from src.core.pe_loader import safe_write
from src.utils.constants import MSVC_SECTION_NAMES, CRITICAL_SECTION_NAMES


def _section_name(section) -> str:
    return section.Name.rstrip(b"\x00").decode("ascii", errors="replace")


class SectionRename(BaseTechnique):
    name = "section_rename"

    def apply(self, pe: pefile.PE) -> None:
        """Rename non-critical sections to distinct MSVC names.

        Critical sections keep their names, and those names are never assigned.
        When the pool runs short, the trailing non-critical sections keep their
        names instead, so the result never introduces a duplicate.
        """
        reserved = {_section_name(s) for s in pe.sections
                    if _section_name(s) in CRITICAL_SECTION_NAMES}
        pool = [n for n in MSVC_SECTION_NAMES if n not in CRITICAL_SECTION_NAMES]
        random.shuffle(pool)
        renameable = [s for s in pe.sections if _section_name(s) not in CRITICAL_SECTION_NAMES]

        for m in range(len(renameable), -1, -1):
            kept = {_section_name(s) for s in renameable[m:]}
            names = [n for n in pool if n not in reserved and n not in kept]
            if len(names) >= m:
                break

        for section, new_name in zip(renameable[:m], names):
            name_bytes = new_name.encode("ascii").ljust(8, b"\x00")[:8]
            safe_write(pe, section.get_file_offset(), name_bytes)
            section.Name = name_bytes
