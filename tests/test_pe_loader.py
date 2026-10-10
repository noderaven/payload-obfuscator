# tests/test_pe_loader.py
import struct
import pytest
import pefile
from pathlib import Path
from src.core.pe_loader import load, save, safe_write, append_section_data, PEError, PEWriteError
from tests.conftest import make_minimal_pe64, write_and_reload


def test_load_returns_pe_object(minimal_pe_path):
    pe = load(minimal_pe_path)
    assert isinstance(pe, pefile.PE)
    assert pe.OPTIONAL_HEADER.Magic == 0x20B  # PE32+
    pe.close()


def test_load_raises_on_invalid_file(tmp_path):
    bad = tmp_path / "bad.exe"
    bad.write_bytes(b"not a pe file")
    with pytest.raises(PEError):
        load(bad)


def test_save_writes_parseable_file(minimal_pe_path, tmp_path):
    pe = load(minimal_pe_path)
    out = tmp_path / "out.exe"
    save(pe, out)
    pe.close()
    assert out.exists()
    pe2 = pefile.PE(str(out))
    assert pe2.OPTIONAL_HEADER.Magic == 0x20B
    pe2.close()


def test_safe_write_modifies_bytes(minimal_pe_path):
    pe = load(minimal_pe_path)
    offset = pe.sections[0].PointerToRawData
    safe_write(pe, offset, b"\xAA\xBB\xCC\xDD")
    assert bytes(pe.__data__[offset:offset + 4]) == b"\xAA\xBB\xCC\xDD"
    pe.close()


def test_safe_write_raises_on_oob(minimal_pe_path):
    pe = load(minimal_pe_path)
    with pytest.raises(PEWriteError):
        safe_write(pe, len(pe.__data__) - 2, b"\x00" * 10)
    pe.close()


def test_safe_write_survives_pe_write(minimal_pe_path):
    pe = load(minimal_pe_path)
    safe_write(pe, pe.sections[0].get_file_offset(), b".zzz\x00\x00\x00\x00")
    assert pe.sections[0].Name == b".zzz\x00\x00\x00\x00"
    out = pefile.PE(data=pe.write())
    assert out.sections[0].Name.rstrip(b"\x00") == b".zzz"
    out.close()
    pe.close()


def test_safe_write_partial_structure_overlap(minimal_pe_path):
    pe = load(minimal_pe_path)
    safe_write(pe, pe.FILE_HEADER.get_file_offset() + 4, struct.pack("<I", 0xCAFEBABE))
    assert pe.FILE_HEADER.TimeDateStamp == 0xCAFEBABE
    out = pefile.PE(data=pe.write())
    assert out.FILE_HEADER.TimeDateStamp == 0xCAFEBABE
    out.close()
    pe.close()


def test_append_section_data_grows_file(minimal_pe_path):
    pe = load(minimal_pe_path)
    original_size = len(pe.__data__)
    payload = b"X" * 100
    offset = append_section_data(pe, payload)
    assert len(pe.__data__) > original_size
    assert bytes(pe.__data__[offset:offset + len(payload)]) == payload
    pe.close()


def test_append_section_data_is_file_aligned(minimal_pe_path):
    pe = load(minimal_pe_path)
    fa = pe.OPTIONAL_HEADER.FileAlignment
    offset = append_section_data(pe, b"Y" * 7)
    assert len(pe.__data__) % fa == 0
    pe.close()


from src.core.pe_loader import fix_headers, append_new_section


def test_fix_headers_sets_number_of_sections(minimal_pe_path):
    pe = load(minimal_pe_path)
    pe.FILE_HEADER.NumberOfSections = 99
    fix_headers(pe)
    assert pe.FILE_HEADER.NumberOfSections == len(pe.sections)
    pe.close()


def test_fix_headers_size_of_image_is_aligned(minimal_pe_path):
    pe = load(minimal_pe_path)
    fix_headers(pe)
    sa = pe.OPTIONAL_HEADER.SectionAlignment
    assert pe.OPTIONAL_HEADER.SizeOfImage % sa == 0
    pe.close()


def test_fix_headers_checksum_is_nonzero(minimal_pe_path):
    pe = load(minimal_pe_path)
    pe.OPTIONAL_HEADER.CheckSum = 0
    fix_headers(pe)
    assert pe.OPTIONAL_HEADER.CheckSum != 0
    pe.close()


def test_fix_headers_output_parses_cleanly(minimal_pe_path, tmp_path):
    pe = load(minimal_pe_path)
    fix_headers(pe)
    out = tmp_path / "fixed.exe"
    save(pe, out)
    pe.close()
    pe2 = pefile.PE(str(out))
    assert pe2.FILE_HEADER.NumberOfSections == len(pe2.sections)
    pe2.close()


def test_append_new_section_adds_parseable_section(minimal_pe_path, tmp_path):
    pe = load(minimal_pe_path)
    original_count = len(pe.sections)
    append_new_section(pe, ".test", b"\xCC" * 16, 0x40000040)
    fix_headers(pe)
    out = tmp_path / "with_section.exe"
    save(pe, out)
    pe.close()
    pe2 = pefile.PE(str(out))
    assert pe2.FILE_HEADER.NumberOfSections == original_count + 1
    names = [s.Name.rstrip(b"\x00").decode() for s in pe2.sections]
    assert ".test" in names
    pe2.close()

_RDATA_VS_OFFSET = 0x170 + 8   # .rdata section header Misc_VirtualSize
_SECTION_TABLE_END = 0x198     # default fixture: 0x148 + 2 * 40


def _load_bytes(data: bytes) -> pefile.PE:
    return pefile.PE(data=bytes(data))


def _rdata_vs_zero() -> bytes:
    data = bytearray(make_minimal_pe64())
    struct.pack_into("<I", data, _RDATA_VS_OFFSET, 0)
    return bytes(data)


def test_append_new_section_after_vs_zero_last_section():
    pe = _load_bytes(_rdata_vs_zero())
    append_new_section(pe, ".new", b"A" * 16, 0x40000040)
    fix_headers(pe)
    assert pe.sections[-1].Name.rstrip(b"\x00") == b".new"
    assert pe.sections[-1].VirtualAddress == 0x3000
    assert pe.OPTIONAL_HEADER.SizeOfImage == 0x4000
    pe.close()


def test_fix_headers_size_of_image_with_vs_zero():
    pe = _load_bytes(_rdata_vs_zero())
    fix_headers(pe)
    assert pe.OPTIONAL_HEADER.SizeOfImage == 0x3000
    pe.close()


def test_fix_headers_never_shrinks_size_of_headers(minimal_pe_path):
    pe = load(minimal_pe_path)
    pe.OPTIONAL_HEADER.SizeOfHeaders = 0x400
    fix_headers(pe)
    assert pe.OPTIONAL_HEADER.SizeOfHeaders == 0x400
    pe.close()


def test_append_keeps_overlay_and_certificate():
    pe = _load_bytes(make_minimal_pe64(overlay=b"OVERLAY!" * 8,
                                       certificate=b"\x30\x82" + b"\x00" * 30))
    append_new_section(pe, ".new", b"A" * 16, 0x40000040)
    fix_headers(pe)
    data = pe.write()
    pe.close()
    out = pefile.PE(data=data)
    new = [s for s in out.sections if s.Name.rstrip(b"\x00") == b".new"]
    assert len(new) == 1
    assert new[0].PointerToRawData == 0x600
    assert out.get_overlay().startswith(b"OVERLAY!" * 8)
    dir4 = out.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    assert struct.unpack_from("<IHH", data, dir4.VirtualAddress) == (40, 0x0200, 2)
    out.close()


def test_append_drops_bound_import_in_the_way():
    pe = _load_bytes(make_minimal_pe64(bound_import=True))
    append_new_section(pe, ".new", b"A" * 16, 0x40000040)
    fix_headers(pe)
    out = pefile.PE(data=pe.write())
    pe.close()
    dir11 = out.OPTIONAL_HEADER.DATA_DIRECTORY[11]
    assert (dir11.VirtualAddress, dir11.Size) == (0, 0)
    assert b".new" in [s.Name.rstrip(b"\x00") for s in out.sections]
    out.close()


def test_append_refuses_unknown_header_data():
    data = bytearray(make_minimal_pe64())
    data[_SECTION_TABLE_END:_SECTION_TABLE_END + 8] = b"\xFF" * 8
    pe = _load_bytes(data)
    with pytest.raises(PEError):
        append_new_section(pe, ".new", b"A" * 16, 0x40000040)
    pe.close()


def test_append_moves_parsed_structures_in_the_overlay():
    pe = _load_bytes(make_minimal_pe64(overlay=b"OVERLAY!" * 8))
    marker = pefile.Structure(("MARKER", ("I,Magic",)), file_offset=0x600)
    marker.__unpack__(bytes(pe.__data__[0x600:0x604]))
    pe.__structures__.append(marker)
    append_new_section(pe, ".new", b"A" * 16, 0x40000040)
    fix_headers(pe)
    data = pe.write()
    pe.close()
    assert marker.get_file_offset() == 0x800
    assert data[0x600:0x610] == b"A" * 16
    assert data[0x800:0x840] == b"OVERLAY!" * 8


def test_append_shifts_pointer_to_symbol_table():
    """PointerToSymbolTable is shifted when it points into the overlay (F6 fix)."""
    # Default fixture: sections end at 0x600; overlay starts there.
    data = bytearray(make_minimal_pe64(overlay=b"COFF" + b"\x00" * 60))
    # Set FILE_HEADER.PointerToSymbolTable (offset 8 within FILE_HEADER) to the
    # overlay start (0x600).
    pe0 = pefile.PE(data=bytes(data))
    fh_off = pe0.FILE_HEADER.get_file_offset()
    pe0.close()
    struct.pack_into("<I", data, fh_off + 8, 0x600)
    pe = _load_bytes(bytes(data))
    # Append a 16-byte section; the section padded to FileAlignment (0x200) shifts
    # the overlay by 0x200, so the new PointerToSymbolTable must be 0x800.
    append_section_data(pe, b"A" * 16)
    assert pe.FILE_HEADER.PointerToSymbolTable == 0x800
    # The updated value must also be in the raw bytes so pe.write() keeps it.
    out_data = pe.write()
    out = pefile.PE(data=out_data)
    assert out.FILE_HEADER.PointerToSymbolTable == 0x800
    out.close()
    pe.close()


def test_safe_write_resync_unwind_info():
    """Writing into an UnwindInfo-backed range must survive pe.write() (F1 fix).

    _resync_structures must call unpack_in_stages (not __unpack__) for UnwindInfo
    so that self.UnwindCodes is refreshed; otherwise __pack__ rebuilds from stale
    codes and pe.write() silently reverts the written bytes.
    """
    # Build an 8-byte UNWIND_INFO with CountOfCodes=2 and plant it at the start of
    # .rdata raw data (file offset 0x400 in the default fixture).
    # Byte layout: Version=1|Flags=0, SizeOfProlog=4, CountOfCodes=2, Frame=0,
    # Code[0]: CodeOffset=3, (OpInfo=0<<4)|UnwindOp=0 = 0x00 (PUSH_NONVOL RAX),
    # Code[1]: CodeOffset=1, (OpInfo=2<<4)|UnwindOp=0 = 0x20 (PUSH_NONVOL RDX).
    ui_header = bytes([0x01, 0x04, 0x02, 0x00])
    ui_codes  = bytes([0x03, 0x00, 0x01, 0x20])
    ui_bytes  = ui_header + ui_codes  # 8 bytes total

    data = bytearray(make_minimal_pe64())
    rdata_raw_off = 0x400  # known default fixture layout
    data[rdata_raw_off:rdata_raw_off + len(ui_bytes)] = ui_bytes

    pe = pefile.PE(data=bytes(data))
    # Attach a pefile.UnwindInfo at this file offset and do the two-stage parse.
    ui = pefile.UnwindInfo(file_offset=rdata_raw_off)
    ui.unpack_in_stages(bytes(pe.__data__[rdata_raw_off:rdata_raw_off + ui.sizeof()]))
    ui.unpack_in_stages(bytes(pe.__data__[rdata_raw_off:rdata_raw_off + ui.sizeof()]))
    pe.__structures__.append(ui)

    # Overwrite Code[1] with a different but valid code (PUSH_NONVOL RBX, OpInfo=3).
    new_code1 = bytes([0x01, 0x30])
    safe_write(pe, rdata_raw_off + 6, new_code1)

    # pe.write() must preserve the new bytes; without the F1 fix it would revert them.
    out_data = pe.write()
    assert out_data[rdata_raw_off + 6:rdata_raw_off + 8] == new_code1, (
        "UnwindInfo codes were not re-read; pe.write() reverted the written bytes"
    )
    pe.close()
