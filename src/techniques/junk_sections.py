"""Add a decoy low-entropy section to disrupt YARA section-count rules."""
import random
import pefile
from src.techniques.base import BaseTechnique, TechniqueError
from src.core.pe_loader import append_new_section
from src.utils.constants import CHARS_RDATA


_DECOY_NAMES = [".debug", ".gfids", ".voltbl", ".00cfg"]


class JunkSections(BaseTechnique):
    name = "junk_sections"

    def apply(self, pe: pefile.PE) -> None:
        decoy_name = random.choice(_DECOY_NAMES)
        phrase = b"Microsoft Corporation\x00" * 50
        size = random.randint(512, 2048)
        data = (phrase * (size // len(phrase) + 1))[:size]
        try:
            append_new_section(pe, decoy_name, data, CHARS_RDATA)
        except Exception as exc:
            raise TechniqueError(f"Could not add junk section: {exc}") from exc
