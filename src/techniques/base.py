"""BaseTechnique ABC and TechniqueError."""
from abc import ABC, abstractmethod
import pefile


class TechniqueError(Exception):
    """Raised by a technique when it cannot apply to the given PE."""


class BaseTechnique(ABC):
    """All obfuscation techniques implement this interface."""

    name: str = "unnamed"
    required: bool = False

    @abstractmethod
    def apply(self, pe: pefile.PE) -> None:
        """Mutate pe in place. Raise TechniqueError on unrecoverable failure.
        Do NOT call fix_headers or pe.write() here -- the pipeline handles that."""
