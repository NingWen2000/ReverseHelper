from reversehelper.dataflow_model import InputSource, ReturnValueLocation
from reversehelper.disassembler import Disassembler, iter_instruction_details
from reversehelper.function_index import FunctionIndex
from reversehelper.interproc_dataflow import propagate_input_flows


BASE = 0x140000000


def make_context(chunks):
    end = max(rva + len(code) for rva, code in chunks)
    data = bytearray(b"\xCC" * (end - 0x1000))
    for rva, code in chunks:
        data[rva - 0x1000:rva - 0x1000 + len(code)] = code
    sections = [{"name": ".text", "virtual_address": 0x1000, "raw_address": 0,
                 "raw_size": len(data), "flags": ["EXECUTE", "READ"]}]
    instructions = Disassembler("x86-64", BASE).disassemble_range(bytes(data), sections, 0x1000, len(data), skip_invalid=True)
    records = list(iter_instruction_details(instructions, "x86-64"))
    ranges = tuple((rva, rva + len(code)) for rva, code in chunks)
    return FunctionIndex(records, sections, BASE, runtime_functions=ranges)


def root_source():
    return InputSource("root", "FUN_1000", 0x1000, BASE + 0x1000, 0x1000,
                       "GetCommandLineW", ReturnValueLocation(0x1000, 0x1000, "a"),
                       None, "CONFIRMED", ("test",))


def test_input_to_helper_propagates_into_direct_callee_compare():
    caller = bytes.fromhex("E8 00 00 00 00 48 89 C1 E8 13 00 00 00 C3")
    callee = bytes.fromhex("48 83 F9 41 C3")
    context = make_context(((0x1000, caller), (0x1020, callee)))
    trace = propagate_input_flows(context, [root_source()], "x86-64").traces[0]
    assert trace.functions_visited == (0x1000, 0x1020)
    assert any(item["function_rva"] == 0x1020 and item["input_flow"] == "CONFIRMED" for item in trace.comparisons)


def test_return_value_validation_reaches_caller_comparison():
    # source -> check(source); cmp returned value,0
    caller = bytes.fromhex("E8 00 00 00 00 48 89 C1 E8 13 00 00 00 48 85 C0 C3")
    callee = bytes.fromhex("48 89 C8 C3")
    context = make_context(((0x1000, caller), (0x1020, callee)))
    trace = propagate_input_flows(context, [root_source()], "x86-64").traces[0]
    assert any(edge.edge_type == "RETURN" for edge in trace.edges)
    assert any(item["function_rva"] == 0x1000 and item["instruction_rva"] == 0x100D
               and item["input_flow"] == "CONFIRMED" for item in trace.comparisons)


def test_call_depth_budget_is_reported():
    first = bytes.fromhex("E8 00 00 00 00 48 89 C1 E8 13 00 00 00 C3")
    second = bytes.fromhex("E8 1B 00 00 00 C3")  # call 0x1040
    third = bytes.fromhex("48 83 F9 01 C3")
    context = make_context(((0x1000, first), (0x1020, second), (0x1040, third)))
    trace = propagate_input_flows(context, [root_source()], "x86-64", max_call_depth=1).traces[0]
    assert 0x1040 not in trace.functions_visited
    assert trace.incomplete and any("Call-depth" in warning for warning in trace.warnings)


def test_input_to_two_functions_is_propagated_without_recursion():
    # caller sends the same source to transform and validation helpers.
    caller = bytes.fromhex("E8 00 00 00 00 48 89 C3 48 89 D9 E8 10 00 00 00 48 89 D9 E8 28 00 00 00 C3")
    transform = bytes.fromhex("48 83 F1 20 C3")
    validation = bytes.fromhex("48 83 F9 41 C3")
    context = make_context(((0x1000, caller), (0x1020, transform), (0x1040, validation)))
    trace = propagate_input_flows(context, [root_source()], "x86-64").traces[0]
    assert {0x1020, 0x1040}.issubset(trace.functions_visited)
