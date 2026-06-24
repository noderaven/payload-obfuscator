"""Strip compiler fingerprints: Rich header, debug directory, timestamp."""
import pefile
from src.techniques.base import BaseTechnique
from src.core.pe_loader import safe_write


class HeaderNormalize(BaseTechnique):
    name = "header_normalize"

    def apply(self, pe: pefile.PE) -> None:
        self._zero_timestamp(pe)
        self._strip_rich_header(pe)
        self._zero_debug_directory(pe)

    def _zero_timestamp(self, pe: pefile.PE) -> None:
        pe.FILE_HEADER.TimeDateStamp = 0
        # TimeDateStamp is at byte 4 in FILE_HEADER
        ts_offset = pe.FILE_HEADER.get_file_offset() + 4
        safe_write(pe, ts_offset, b"\x00\x00\x00\x00")

    def _strip_rich_header(self, pe: pefile.PE) -> None:
        """Zero out the Rich header in the DOS stub if present."""
        e_lfanew = pe.DOS_HEADER.e_lfanew
        dos_stub = bytes(pe.__data__[0x40:e_lfanew])

        rich_pos = dos_stub.find(b"Rich")
        if rich_pos == -1:
            return  # no Rich header present

        absolute_rich = 0x40 + rich_pos
        xor_key = int.from_bytes(pe.__data__[absolute_rich + 4 : absolute_rich + 8], "little")

        # Walk backward to find 'DanS' (XOR-encrypted as xor_key ^ 0x44616E53)
        dans_marker = xor_key ^ 0x44616E53
        region_bytes = bytes(pe.__data__[0x40:absolute_rich])
        start = 0
        for i in range(len(region_bytes) - 4):
            val = int.from_bytes(region_bytes[i:i+4], "little")
            if val == dans_marker:
                start = 0x40 + i
                break

        # Zero from 'DanS' through 'Rich' + 4-byte key (8 bytes)
        region_len = absolute_rich + 8 - start
        if region_len > 0:
            safe_write(pe, start, b"\x00" * region_len)

    def _zero_debug_directory(self, pe: pefile.PE) -> None:
        """Zero IMAGE_DIRECTORY_ENTRY_DEBUG RVA and Size."""
        debug_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[6]  # index 6 = debug
        if debug_dir.VirtualAddress == 0:
            return
        debug_dir.VirtualAddress = 0
        debug_dir.Size = 0
        dd_offset = debug_dir.get_file_offset()
        safe_write(pe, dd_offset, b"\x00" * 8)
