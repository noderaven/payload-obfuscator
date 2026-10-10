"""Lower section entropy by filling file slack with the section's most frequent byte."""
import math
import pefile
from src.techniques.base import BaseTechnique
from src.core.pe_loader import safe_write
from src.utils.pe_math import effective_virtual_size


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq if c)


class EntropyReduce(BaseTechnique):
    name = "entropy_reduce"

    def apply(self, pe: pefile.PE) -> None:
        for section in pe.sections:
            used = effective_virtual_size(section)
            if used >= section.SizeOfRawData:
                continue
            raw_start = section.PointerToRawData
            raw_end = min(raw_start + section.SizeOfRawData, len(pe.__data__))
            slack_start = raw_start + used
            slack_end = raw_end
            if slack_end <= slack_start:
                continue
            slack_len = slack_end - slack_start
            old_raw = bytes(pe.__data__[raw_start:raw_end])
            # Most frequent byte in the whole raw data; ties go to the lowest byte value
            freq = [0] * 256
            for b in old_raw:
                freq[b] += 1
            max_freq = max(freq)
            fill_byte = next(b for b in range(256) if freq[b] == max_freq)
            # Candidate raw data with the fill byte covering the slack
            fill = bytes([fill_byte]) * slack_len
            new_raw = old_raw[:used] + fill
            # Only write if entropy strictly decreases
            if shannon_entropy(new_raw) < shannon_entropy(old_raw):
                safe_write(pe, slack_start, fill)
