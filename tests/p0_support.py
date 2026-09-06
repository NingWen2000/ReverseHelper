"""Deterministic instruction fixtures; no compiler or target execution needed."""

import struct

from reversehelper.addressing import annotate_string_locations
from reversehelper.disassembler import Disassembler, iter_instruction_details
from reversehelper.function_index import FunctionIndex
from reversehelper.instruction_context import find_import_calls
from reversehelper.string_analyzer import extract_strings
from reversehelper.string_intelligence import analyze_interesting_strings
from reversehelper.validation_analyzer import discover_validation, find_input_candidates
from reversehelper.target_ranker import rank_targets


class Code:
    def __init__(self, rva=0x1000, base=0x400000, x64=False):
        self.bytes = bytearray()
        self.rva = rva
        self.base = base
        self.x64 = x64
        self.labels = {}
        self.fixups = []

    def emit(self, value):
        self.bytes.extend(bytes.fromhex(value) if isinstance(value, str) else value)

    def label(self, name):
        self.labels[name] = len(self.bytes)

    def jump(self, opcode, label):
        self.emit(opcode)
        self.fixups.append((len(self.bytes), label))
        self.emit(b"\0")

    def call(self, slot):
        address = slot - (self.rva + len(self.bytes) + 6) if self.x64 else self.base + slot
        self.emit(b"\xff\x15" + struct.pack("<i" if self.x64 else "<I", address))

    def pointer(self, rva, register="c"):
        if self.x64:
            opcode = {"c": b"\x48\x8d\x0d", "d": b"\x48\x8d\x15"}[register]
            self.emit(opcode + struct.pack("<i", rva - (self.rva + len(self.bytes) + 7)))
        else:
            self.emit(b"\x68" + struct.pack("<I", self.base + rva))

    def finish(self):
        for offset, label in self.fixups:
            displacement = self.labels[label] - offset - 1
            assert -128 <= displacement <= 127
            self.bytes[offset] = displacement & 0xff
        return bytes(self.bytes)


def compare_code(api="strcmp", *, x64=False, positive=True, overwrite=False):
    c = Code(base=0x140000000 if x64 else 0x400000, x64=x64)
    if positive:
        c.call(0x2008)
    if api in {"memcmp", "strncmp"}:
        c.emit("41 B8 06 00 00 00" if x64 else "6A 06")
    c.pointer(0x3060, "d")
    c.pointer(0x3080, "c")
    c.call(0x2000)
    if overwrite:
        c.emit("31 C0")
    c.emit("85 C0")
    c.jump("75", "failure")
    if positive:
        c.pointer(0x3020)
        c.call(0x2010)
    c.emit("C3")
    c.label("failure")
    if positive:
        c.pointer(0x3000)
        c.call(0x2010)
    c.emit("C3")
    return c.finish()


def analyze_code(code, *, api="strcmp", x64=False, runtime=(), entry=0x1000, extra_data=None):
    base = 0x140000000 if x64 else 0x400000
    architecture = "x86-64" if x64 else "x86"
    data = bytearray(b"\0" * 0x1000)
    data[0x200:0x200 + len(code)] = code
    strings = {0x3000: b"Wrong flag!\0", 0x3020: b"Correct! Congratulations!\0", 0x3060: b"RHdemo\0"}
    strings.update(extra_data or {})
    for rva, value in strings.items():
        offset = rva - 0x3000 + 0x800
        data[offset:offset + len(value)] = value
    sections = [
        {"name": ".text", "virtual_address": 0x1000, "raw_address": 0x200, "raw_size": len(code), "flags": ["EXECUTE", "READ"]},
        {"name": ".rdata", "virtual_address": 0x3000, "raw_address": 0x800, "raw_size": 0x800, "flags": ["READ"]},
    ]
    imports = [{"dll": "msvcrt.dll", "functions": [
        {"name": name, "iat_address": base + slot, "suspicious": False}
        for name, slot in ((api, 0x2000), ("fgets", 0x2008), ("puts", 0x2010), ("strlen", 0x2018))]}]
    instructions = Disassembler(architecture, base).disassemble_range(bytes(data), sections, 0x1000, len(code), skip_invalid=True)
    records = list(iter_instruction_details(instructions, architecture))
    context = FunctionIndex(records, sections, base, entry, runtime_functions=runtime)
    calls = find_import_calls(instructions, imports, architecture, base, records)
    extracted = extract_strings(bytes(data), deduplicate=False)
    annotate_string_locations(extracted, sections, base, 0x200)
    intelligent = analyze_interesting_strings(extracted, context)
    validation = discover_validation(context, calls, intelligent, architecture, bytes(data))
    input_findings = find_input_candidates(instructions, imports, sections, architecture, base, instruction_details=records, import_calls=calls)
    targets = rank_targets(input_findings, context=context, interesting_strings=intelligent, validation_candidates=validation)
    return context, intelligent, validation, targets


def write_pe(path, *, api="strcmp", x64=False, positive=True, code=None):
    """Minimal PE with real import descriptors; used for portable end-to-end tests."""
    code = code if code is not None else compare_code(api, x64=x64, positive=positive)
    data = bytearray(4096)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional_size = 0xF0 if x64 else 0xE0
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664 if x64 else 0x14C, 3, 0, 0, 0, optional_size, 0x22 if x64 else 0x102)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x20B if x64 else 0x10B)
    struct.pack_into("<I", data, optional + 16, 0x1000)
    struct.pack_into("<I", data, optional + 20, 0x1000)
    struct.pack_into("<Q" if x64 else "<I", data, optional + (24 if x64 else 28), 0x140000000 if x64 else 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x4000, 0x200)
    struct.pack_into("<H", data, optional + 68, 3)
    struct.pack_into("<I", data, optional + (108 if x64 else 92), 16)
    directory = optional + (112 if x64 else 96)
    struct.pack_into("<II", data, directory + 8, 0x2100, 40 if x64 else 100)
    for i, (name, rva, raw, size, flags) in enumerate([
        (b".text", 0x1000, 0x200, 0x400, 0x60000020),
        (b".idata", 0x2000, 0x600, 0x200, 0xC0000040),
        (b".rdata", 0x3000, 0x800, 0x800, 0x40000040),
    ]):
        offset = optional + optional_size + i * 40
        struct.pack_into("<8sIIIIIIHHI", data, offset, name, size, rva, size, raw, 0, 0, 0, 0, flags)
    data[0x200:0x200 + len(code)] = code
    for rva, value in {0x3000: b"Wrong flag!\0", 0x3020: b"Correct! Congratulations!\0", 0x3060: b"RHdemo\0"}.items():
        raw = rva - 0x3000 + 0x800
        data[raw:raw + len(value)] = value
    for i, name in enumerate((api, "fgets", "puts", "strlen")):
        name_rva = 0x3100 + i * 32
        raw = name_rva - 0x3000 + 0x800
        value = b"\0\0" + name.encode("ascii") + b"\0"
        data[raw:raw + len(value)] = value
        struct.pack_into("<Q" if x64 else "<I", data, 0x600 + i * 8, name_rva)
        if not x64:
            struct.pack_into("<IIIII", data, 0x700 + i * 20, 0, 0, 0, 0x31F0, 0x2000 + i * 8)
    if x64:
        struct.pack_into("<IIIII", data, 0x700, 0, 0, 0, 0x31F0, 0x2000)
    data[0x9F0:0x9FB] = b"msvcrt.dll\0"
    path.write_bytes(data)
    return path
