"""Lower section entropy by filling file slack with structured low-entropy bytes."""
import math
import pefile
from src.techniques.base import BaseTechnique
from src.core.pe_loader import safe_write


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


_LOW_ENTROPY_FILL = b"\x00\x01\x02\x03\x04\x05\x06\x07" * 32  # 256-byte repeating pattern


class EntropyReduce(BaseTechnique):
    name = "entropy_reduce"

    def apply(self, pe: pefile.PE) -> None:
        for section in pe.sections:
            slack = section.SizeOfRawData - section.Misc_VirtualSize
            if slack <= 0:
                continue
            slack_offset = section.PointerToRawData + section.Misc_VirtualSize
            # Guard: don't write beyond the file boundary
            if slack_offset + slack > len(pe.__data__):
                slack = len(pe.__data__) - slack_offset
            if slack <= 0:
                continue
            pattern = (_LOW_ENTROPY_FILL * (slack // len(_LOW_ENTROPY_FILL) + 1))[:slack]
            safe_write(pe, slack_offset, pattern)
