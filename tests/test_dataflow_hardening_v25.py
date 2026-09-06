import struct

from reversehelper.dataflow_model import InputSource, StackLocation
from reversehelper.disassembler import Disassembler, iter_instruction_details
from reversehelper.function_index import FunctionIndex
from reversehelper.interproc_dataflow import propagate_input_flows
from reversehelper.intra_dataflow import analyze_intra_function


BASE = 0x400000


def _context(chunks):
    end = max(rva + len(code) for rva, code in chunks)
    data = bytearray(b"\xCC" * (end - 0x1000))
    for rva, code in chunks:
        data[rva - 0x1000:rva - 0x1000 + len(code)] = code
    sections = [{"name": ".text", "virtual_address": 0x1000, "raw_address": 0,
                 "raw_size": len(data), "flags": ["EXECUTE", "READ"]}]
    instructions = Disassembler("x86", BASE).disassemble_range(bytes(data), sections, 0x1000, len(data), skip_invalid=True)
    records = list(iter_instruction_details(instructions, "x86"))
    ranges = tuple((rva, rva + len(code)) for rva, code in chunks)
    return FunctionIndex(records, sections, BASE, runtime_functions=ranges)


def _source(function=0x1000, callsite=0x1000):
    return InputSource("input", f"FUN_{function:X}", function, BASE + callsite, callsite, "ReadFile",
                       StackLocation(function, -0x40), 64, "CONFIRMED", ("test source",))


def test_indexed_stack_alias_can_reach_absolute_indexed_global():
    # nop; ecx=0; al=buffer[ecx]; global[ecx]=al; ret
    code = bytes.fromhex("90 31 C9 8A 44 0D C0 88 81 00 30 40 00 C3")
    context = _context(((0x1000, code),))
    flow = analyze_intra_function(context, [_source(callsite=0x1000)], "x86")
    assert any(edge.edge_type == "LOAD" for edge in flow.edges)
    assert any(edge.destination.to_dict().get("rva") == 0x3000 for edge in flow.edges)


def test_in_place_memory_transform_remains_source_reachable():
    code = bytes.fromhex("90 80 75 C0 41 8A 45 C0 3C 42 C3")
    context = _context(((0x1000, code),))
    flow = analyze_intra_function(context, [_source(callsite=0x1000)], "x86")
    assert any(edge.edge_type == "TRANSFORM" for edge in flow.edges)
    assert any(item["input_flow"] == "CONFIRMED" for item in flow.comparisons)


def test_global_written_by_input_wrapper_reaches_sibling_checker():
    root = bytes.fromhex("90 8A 45 C0 A2 00 30 40 00 C3")
    controller = (b"\xE8" + struct.pack("<i", 0x1000 - 0x1025)
                  + b"\xE8" + struct.pack("<i", 0x1040 - 0x102A) + b"\xC3")
    checker = bytes.fromhex("A0 00 30 40 00 3C 41 C3")
    context = _context(((0x1000, root), (0x1020, controller), (0x1040, checker)))
    trace = propagate_input_flows(context, [_source()], "x86").traces[0]
    assert 0x1040 in trace.functions_visited
    assert any(item["function_rva"] == 0x1040 and item["input_flow"] == "CONFIRMED"
               for item in trace.comparisons)

