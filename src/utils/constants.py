"""Curated constants for PE manipulation."""

MSVC_SECTION_NAMES = [
    ".text", ".rdata", ".data", ".pdata", ".rsrc",
    ".reloc", ".tls", ".gfids", ".00cfg",
]

CRITICAL_SECTION_NAMES = {".rsrc", ".reloc", ".tls"}

IMAGE_SCN_CNT_CODE               = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE            = 0x20000000
IMAGE_SCN_MEM_READ               = 0x40000000
IMAGE_SCN_MEM_WRITE              = 0x80000000

CHARS_CODE    = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ
CHARS_RDATA   = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ
CHARS_DATA    = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
CHARS_DISCARD = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | 0x02000000

HIGH_RISK_IMPORTS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect",
    "WriteProcessMemory", "ReadProcessMemory",
    "CreateThread", "CreateRemoteThread",
    "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
    "LoadLibraryA", "LoadLibraryW", "GetProcAddress",
}
