"""Pre/post PE structural validation."""
import pefile
from src.core.pe_loader import PEError


class ValidationError(PEError):
    pass


def pre_validate(pe: pefile.PE) -> None:
    """Raise ValidationError if pe is not a usable PE64."""
    if pe.OPTIONAL_HEADER.Magic != 0x20B:
        raise ValidationError(f"Not a PE32+ (x64) binary; Magic=0x{pe.OPTIONAL_HEADER.Magic:x}")
    if not pe.sections:
        raise ValidationError("PE has no sections")
    if pe.OPTIONAL_HEADER.SectionAlignment == 0:
        raise ValidationError("SectionAlignment is zero")
    if pe.OPTIONAL_HEADER.FileAlignment == 0:
        raise ValidationError("FileAlignment is zero")


def post_validate(pe: pefile.PE) -> None:
    """Raise ValidationError if fix_headers left the PE in a broken state."""
    sa = pe.OPTIONAL_HEADER.SectionAlignment
    if pe.OPTIONAL_HEADER.SizeOfImage % sa != 0:
        raise ValidationError(
            f"SizeOfImage 0x{pe.OPTIONAL_HEADER.SizeOfImage:x} not aligned to 0x{sa:x}"
        )
    if pe.FILE_HEADER.NumberOfSections != len(pe.sections):
        raise ValidationError(
            f"NumberOfSections {pe.FILE_HEADER.NumberOfSections} != len(sections) {len(pe.sections)}"
        )
    file_size = len(pe.__data__)
    for s in pe.sections:
        end = s.PointerToRawData + s.SizeOfRawData
        if s.PointerToRawData > 0 and end > file_size:
            raise ValidationError(
                f"Section {s.Name!r} raw data extends beyond file "
                f"(0x{end:x} > 0x{file_size:x})"
            )
