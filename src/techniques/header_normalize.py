"""Strip compiler fingerprints: Rich header, debug data, timestamps."""
import pefile
from src.techniques.base import BaseTechnique
from src.core.pe_loader import safe_write

_DANS = 0x536E6144  # b"DanS" read as a little-endian dword
_DEBUG_DIR_INDEX = 6


def _zero_range(pe: pefile.PE, offset: int, size: int) -> None:
    """Zero [offset, offset + size) in pe.__data__, clamped to the file length."""
    end = min(offset + size, len(pe.__data__))
    if offset < 0 or end <= offset:
        return
    safe_write(pe, offset, b"\x00" * (end - offset))


def _zero_structure(pe: pefile.PE, structure: pefile.Structure) -> None:
    """Zero every field of a parsed structure, in the struct and in the bytes.

    pe.write() repacks every structure in pe.__structures__, so zeroing only the
    bytes would be undone on save.
    """
    for names in structure.__keys__:
        for name in names:
            value = getattr(structure, name)
            setattr(structure, name, b"\x00" * len(value) if isinstance(value, bytes) else 0)
    _zero_range(pe, structure.get_file_offset(), structure.sizeof())


class HeaderNormalize(BaseTechnique):
    name = "header_normalize"

    def apply(self, pe: pefile.PE) -> None:
        self._zero_timestamp(pe)
        self._strip_rich_header(pe)
        self._zero_debug_directory(pe)
        self._zero_directory_timestamps(pe)

    def _zero_timestamp(self, pe: pefile.PE) -> None:
        pe.FILE_HEADER.TimeDateStamp = 0
        # TimeDateStamp is at byte 4 in FILE_HEADER
        ts_offset = pe.FILE_HEADER.get_file_offset() + 4
        safe_write(pe, ts_offset, b"\x00\x00\x00\x00")

    def _strip_rich_header(self, pe: pefile.PE) -> None:
        """Zero the Rich header (DanS marker through Rich + key) in the DOS stub.

        If the XOR-encoded DanS marker is not found before "Rich", the header is
        malformed and is left untouched.
        """
        e_lfanew = pe.DOS_HEADER.e_lfanew
        dos_stub = bytes(pe.__data__[0x40:e_lfanew])

        rich_pos = dos_stub.find(b"Rich")
        if rich_pos == -1:
            return  # no Rich header present

        absolute_rich = 0x40 + rich_pos
        xor_key = int.from_bytes(pe.__data__[absolute_rich + 4 : absolute_rich + 8], "little")

        dans_marker = (xor_key ^ _DANS).to_bytes(4, "little")
        dans_pos = dos_stub.find(dans_marker, 0, rich_pos)
        if dans_pos == -1:
            return  # malformed Rich header: leave it alone

        start = 0x40 + dans_pos
        safe_write(pe, start, b"\x00" * (absolute_rich + 8 - start))

    def _zero_debug_directory(self, pe: pefile.PE) -> None:
        """Wipe every debug entry, its raw data (e.g. the PDB path) and DATA_DIRECTORY[6]."""
        if (pe.OPTIONAL_HEADER.NumberOfRvaAndSizes <= _DEBUG_DIR_INDEX
                or len(pe.OPTIONAL_HEADER.DATA_DIRECTORY) <= _DEBUG_DIR_INDEX):
            return
        debug_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[_DEBUG_DIR_INDEX]
        if debug_dir.VirtualAddress == 0 and debug_dir.Size == 0:
            return

        for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
            entry = getattr(dbg, "entry", None)
            if isinstance(entry, pefile.Structure):
                _zero_structure(pe, entry)
            if dbg.struct.PointerToRawData:
                _zero_range(pe, dbg.struct.PointerToRawData, dbg.struct.SizeOfData)
            _zero_structure(pe, dbg.struct)

        debug_dir.VirtualAddress = 0
        debug_dir.Size = 0
        safe_write(pe, debug_dir.get_file_offset(), b"\x00" * 8)

    def _zero_directory_timestamps(self, pe: pefile.PE) -> None:
        """Zero the export directory's and top-level resource directory's TimeDateStamp."""
        for attr in ("DIRECTORY_ENTRY_EXPORT", "DIRECTORY_ENTRY_RESOURCE"):
            directory = getattr(pe, attr, None)
            if directory is None:
                continue
            directory.struct.TimeDateStamp = 0
            # TimeDateStamp follows the 4-byte Characteristics field in both structures.
            safe_write(pe, directory.struct.get_file_offset() + 4, b"\x00" * 4)
