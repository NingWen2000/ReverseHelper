"""Core Portable Executable parser."""

from __future__ import annotations

import hashlib
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pefile

from .import_analyzer import analyze_exports, analyze_imports
from .section_analyzer import analyze_sections, rva_to_offset


MACHINE_TYPES = {
    0x014C: "x86",
    0x0200: "Intel Itanium",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "ARM64",
}

SUBSYSTEMS = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows Console",
    5: "OS/2 Console",
    7: "POSIX Console",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "Xbox",
    16: "Windows Boot Application",
}


class PEFormatError(ValueError):
    """Raised when an input is not a readable Portable Executable."""


def _hashes(data: bytes) -> dict[str, str]:
    return {
        "md5": hashlib.md5(data, usedforsecurity=False).hexdigest(),
        "sha1": hashlib.sha1(data, usedforsecurity=False).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _timestamp(value: int) -> str | None:
    if not value:
        return None


def _coff_function_symbols(data: bytes, pe: Any) -> list[dict[str, Any]]:
    """Read bounded COFF function symbols when a PE retained its symbol table."""
    pointer = int(pe.FILE_HEADER.PointerToSymbolTable)
    count = min(int(pe.FILE_HEADER.NumberOfSymbols), 200_000)
    table_end = pointer + count * 18
    if not pointer or not count or pointer < 0 or table_end + 4 > len(data):
        return []
    string_size = struct.unpack_from("<I", data, table_end)[0]
    string_end = min(len(data), table_end + max(4, string_size))
    sections = list(pe.sections)
    result: list[dict[str, Any]] = []
    index = 0
    while index < count:
        offset = pointer + index * 18
        if offset + 18 > len(data):
            break
        raw_name = data[offset:offset + 8]
        value, section_number, symbol_type, storage_class, auxiliaries = struct.unpack_from("<IhHBB", data, offset + 8)
        name = ""
        if raw_name[:4] == b"\0\0\0\0":
            string_offset = struct.unpack_from("<I", raw_name, 4)[0]
            start = table_end + string_offset
            if table_end + 4 <= start < string_end:
                name = data[start:string_end].split(b"\0", 1)[0].decode("utf-8", errors="replace")
        else:
            name = raw_name.split(b"\0", 1)[0].decode("utf-8", errors="replace")
        if 0 < section_number <= len(sections) and (symbol_type & 0x20) and storage_class in {2, 3}:
            section = sections[section_number - 1]
            rva = int(section.VirtualAddress) + int(value)
            result.append({"name": name or f"coff_{rva:X}", "rva": rva,
                           "section_number": section_number, "storage_class": storage_class})
        index += 1 + int(auxiliaries)
    return result
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except (OverflowError, OSError, ValueError):
        return None


class PEParser:
    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser().resolve()
        if not self.path.exists():
            raise PEFormatError(f"Input file does not exist: {self.path}")
        if self.path.is_dir():
            raise PEFormatError(f"Input path is a directory, not a PE file: {self.path}")
        if not self.path.is_file():
            raise PEFormatError(f"Input path is not a regular file: {self.path}")
        try:
            self.data = self.path.read_bytes()
        except OSError as exc:
            detail = exc.strerror or str(exc)
            raise PEFormatError(f"Could not read input file: {self.path} ({detail})") from exc
        if len(self.data) < 2 or self.data[:2] != b"MZ":
            raise PEFormatError("Input is not a PE file: missing MZ signature")
        try:
            self.pe = pefile.PE(data=self.data, fast_load=False)
            self.pe.parse_data_directories()
        except pefile.PEFormatError as exc:
            raise PEFormatError(f"Invalid or unsupported PE file: {exc}") from exc

    def close(self) -> None:
        self.pe.close()

    def parse(self) -> dict[str, Any]:
        pe = self.pe
        file_header = pe.FILE_HEADER
        optional = pe.OPTIONAL_HEADER
        entry_rva = int(optional.AddressOfEntryPoint)
        imports, suspicious_imports = analyze_imports(pe)
        exports = analyze_exports(pe)
        sections = analyze_sections(pe)
        import_count = sum(len(library["functions"]) for library in imports)

        file_type = "DLL" if pe.is_dll() else "EXE" if pe.is_exe() else "PE"
        basic = {
            "file_name": self.path.name,
            "file_path": str(self.path),
            "file_size": len(self.data),
            "file_type": file_type,
            "architecture": MACHINE_TYPES.get(int(file_header.Machine), f"Unknown (0x{file_header.Machine:04X})"),
            "machine": int(file_header.Machine),
            "compile_timestamp": int(file_header.TimeDateStamp),
            "compile_time_utc": _timestamp(int(file_header.TimeDateStamp)),
            "image_base": int(optional.ImageBase),
            "entry_point_rva": entry_rva,
            "entry_point_va": int(optional.ImageBase) + entry_rva,
            "entry_point_offset": rva_to_offset(pe, entry_rva),
            "number_of_sections": int(file_header.NumberOfSections),
            "section_alignment": int(optional.SectionAlignment),
            "file_alignment": int(optional.FileAlignment),
            "size_of_image": int(optional.SizeOfImage),
            "size_of_headers": int(optional.SizeOfHeaders),
            "subsystem": SUBSYSTEMS.get(int(optional.Subsystem), f"Unknown ({optional.Subsystem})"),
            "checksum": int(optional.CheckSum),
            "dll_characteristics": int(optional.DllCharacteristics),
            "is_64_bit": int(file_header.Machine) in {0x8664, 0x0200, 0xAA64},
        }

        return {
            "basic": basic,
            "hashes": _hashes(self.data),
            "sections": sections,
            "imports": imports,
            "import_count": import_count,
            "suspicious_imports": suspicious_imports,
            "exports": exports,
            "export_count": len(exports),
            "parser_warnings": list(pe.get_warnings()),
            "coff_function_symbols": _coff_function_symbols(self.data, pe),
        }
