from reversehelper.dataflow_model import InputSource, ReturnValueLocation, StackLocation
from reversehelper.disassembler import Disassembler, iter_instruction_details
from reversehelper.function_index import FunctionIndex
from reversehelper.intra_dataflow import analyze_intra_function


BASE = 0x140000000


def context_for(code, architecture="x86-64", base=BASE, runtime_functions=None):
    sections = [{"name": ".text", "virtual_address": 0x1000, "raw_address": 0,
                 "raw_size": len(code), "flags": ["EXECUTE", "READ"]}]
    instructions = Disassembler(architecture, base).disassemble_range(code, sections, 0x1000, len(code))
    records = list(iter_instruction_details(instructions, architecture))
    return FunctionIndex(records, sections, base,
                         runtime_functions=runtime_functions or ((0x1000, 0x1000 + len(code)),))


def source(destination, callsite=0x1000):
    return InputSource("input", "FUN", 0x1000, BASE + callsite, callsite, "test", destination,
                       None, "CONFIRMED", ("test source",))


def test_register_copy_reaches_direct_call_argument():
    # input return; mov rcx,rax; call 0x1020; ret
    context = context_for(bytes.fromhex("E8 00 00 00 00 48 89 C1 E8 13 00 00 00 C3"))
    flow = analyze_intra_function(context, [source(ReturnValueLocation(0x1000, 0x1000, "a"))], "x86-64")
    assert any(item["callee_rva"] == 0x1020 and item["argument_index"] == 0 for item in flow.call_arguments)
    assert [edge.edge_type for edge in flow.edges] == ["COPY", "ARGUMENT"]


def test_register_overwrite_kills_input_before_call():
    context = context_for(bytes.fromhex("E8 00 00 00 00 31 C0 48 89 C1 E8 10 00 00 00 C3"))
    flow = analyze_intra_function(context, [source(ReturnValueLocation(0x1000, 0x1000, "a"))], "x86-64")
    assert not flow.call_arguments


def test_stack_input_address_flows_to_argument():
    # input call; lea rcx,[rbp-40h]; call helper
    context = context_for(bytes.fromhex("E8 00 00 00 00 48 8D 4D C0 E8 12 00 00 00 C3"))
    flow = analyze_intra_function(context, [source(StackLocation(0x1000, -0x40), 0x1000)], "x86-64")
    assert any(edge.edge_type == "ADDRESS" for edge in flow.edges)
    assert len(flow.call_arguments) == 1


def test_stack_overwrite_kills_input_before_address_is_passed():
    context = context_for(bytes.fromhex("E8 00 00 00 00 48 C7 45 C0 00 00 00 00 48 8D 4D C0 E8 0B 00 00 00 C3"))
    flow = analyze_intra_function(context, [source(StackLocation(0x1000, -0x40), 0x1000)], "x86-64")
    assert not flow.call_arguments


def test_false_same_function_context_does_not_flow_to_memcmp():
    # input fills [rbp-40]; memcmp receives [rbp-60] and [rbp-70]
    code = bytes.fromhex("E8 00 00 00 00 4C 8D 45 90 48 8D 55 A0 48 8D 4D 90 E8 0A 00 00 00 C3")
    context = context_for(code)
    flow = analyze_intra_function(context, [source(StackLocation(0x1000, -0x40), 0x1000)], "x86-64")
    assert not flow.call_arguments


def test_x86_esp_slot_reaches_direct_call_argument():
    # lea eax,[ebp-40h]; mov [esp],eax; call 0x1020; ret; ... target ret
    code = bytes.fromhex("8D 45 C0 89 04 24 E8 15 00 00 00 C3") + b"\xCC" * 20 + b"\xC3"
    context = context_for(code, "x86", 0x400000,
                          runtime_functions=((0x1000, 0x100C), (0x1020, 0x1021)))
    input_record = InputSource("input", "FUN", 0x1000, 0x401000, 0x1000, "test",
                               StackLocation(0x1000, -0x40), None, "CONFIRMED", ("test source",))
    flow = analyze_intra_function(context, [input_record], "x86")
    assert any(item["callee_rva"] == 0x1020 and item["argument_index"] == 0
               for item in flow.call_arguments)
