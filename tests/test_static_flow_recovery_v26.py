from reversehelper.dataflow_model import ArgumentLocation, InputSource, ReturnValueLocation, StackLocation
from reversehelper.disassembler import Disassembler, iter_instruction_details
from reversehelper.function_index import FunctionIndex
from reversehelper.intra_dataflow import analyze_intra_function
from reversehelper.indirect_resolver import resolve_indirect_call
from reversehelper.instruction_context import find_import_calls
from reversehelper.interproc_dataflow import propagate_input_flows
from reversehelper.static_slice import build_static_flow_breaks
from reversehelper.value_identity import ValueIdentity, merge_identities


BASE = 0x140000000


def context_for(code, runtime_functions=None):
    sections = [{"name": ".text", "virtual_address": 0x1000, "raw_address": 0,
                 "raw_size": len(code), "flags": ["EXECUTE", "READ"]}]
    instructions = Disassembler("x86-64", BASE).disassemble_range(
        code, sections, 0x1000, len(code), skip_invalid=True,
    )
    records = list(iter_instruction_details(instructions, "x86-64"))
    return FunctionIndex(records, sections, BASE, runtime_functions=runtime_functions or ((0x1000, 0x1000 + len(code)),))


def source(destination, callsite=0x1000):
    return InputSource("input", "FUN_1000", 0x1000, BASE + callsite, callsite,
                       "test", destination, 32, "CONFIRMED", ("fixture",))


def identity_ids(flow):
    return {edge.value_identity.id for edge in flow.edges if edge.value_identity is not None}


def test_register_spill_restore_preserves_value_identity():
    # input return -> r12 -> [rsp+40h] -> rdx -> helper arg1
    caller = bytes.fromhex(
        "E8 00 00 00 00 49 89 C4 4C 89 64 24 40 48 8B 54 24 40 "
        "E8 19 00 00 00 C3"
    )
    code = caller + b"\xCC" * (0x30 - len(caller)) + b"\xC3"
    flow = analyze_intra_function(
        context_for(code, ((0x1000, 0x1018), (0x1030, 0x1031))),
        [source(ReturnValueLocation(0x1000, 0x1000, "a"))], "x86-64",
    )
    assert any(item["callee_rva"] == 0x1030 and item["argument_index"] == 1
               for item in flow.call_arguments)
    assert identity_ids(flow) == {"value-input"}


def test_value_identity_chain_survives_register_copies():
    code = bytes.fromhex("E8 00 00 00 00 49 89 C4 4C 89 E1 48 83 F9 20 C3")
    flow = analyze_intra_function(context_for(code), [source(ReturnValueLocation(0x1000, 0x1000, "a"))], "x86-64")
    comparison = next(item for item in flow.comparisons if item["instruction_rva"] == 0x100B)
    assert comparison["input_flow"] == "CONFIRMED"
    assert comparison["value_identities"][0]["id"] == "value-input"


def test_pointer_base_offset_keeps_input_base_object():
    code = bytes.fromhex("E8 00 00 00 00 48 8D 4D C0 48 83 C1 04 80 39 00 C3")
    flow = analyze_intra_function(context_for(code), [source(StackLocation(0x1000, -0x40))], "x86-64")
    comparison = next(item for item in flow.comparisons if item["instruction_rva"] == 0x100D)
    identity = comparison["value_identities"][0]
    assert identity["base_object"]["offset"] == -0x40
    assert identity["offset"] == 4
    assert identity["alias_confidence"] == "BASE_ALIAS"


def test_symbolic_index_preserves_base_identity_with_lower_confidence():
    code = bytes.fromhex("E8 00 00 00 00 48 8D 45 C0 0F B6 0C 10 80 F9 41 C3")
    flow = analyze_intra_function(context_for(code), [source(StackLocation(0x1000, -0x40))], "x86-64")
    comparison = next(item for item in flow.comparisons if item["instruction_rva"] == 0x100D)
    identity = comparison["value_identities"][0]
    assert identity["id"] == "value-input"
    assert identity["index"] == "d"
    assert identity["alias_confidence"] == "BASE_ALIAS"


def test_alias_kill_drops_previous_identity():
    code = bytes.fromhex("E8 00 00 00 00 48 89 C1 B9 2A 00 00 00 48 83 F9 2A C3")
    flow = analyze_intra_function(context_for(code), [source(ReturnValueLocation(0x1000, 0x1000, "a"))], "x86-64")
    comparison = next(item for item in flow.comparisons if item["instruction_rva"] == 0x100D)
    assert comparison["input_flow"] == "NONE"


def test_path_merge_is_explicit_and_possible():
    left = ValueIdentity("v1", "input-1", {"kind": "STACK", "offset": -32})
    right = ValueIdentity("v2", "unknown", {"kind": "UNKNOWN"})
    merged = merge_identities(left, right, "bounded branch merge")
    assert merged.confidence == "POSSIBLE"
    assert merged.alias_confidence == "POSSIBLE_ALIAS"
    assert merged.merged_origins == ("input-1", "unknown")


def test_inplace_transform_advances_object_version():
    code = bytes.fromhex("E8 00 00 00 00 48 8D 45 C0 80 75 C0 69 80 7D C0 00 C3")
    flow = analyze_intra_function(context_for(code), [source(StackLocation(0x1000, -0x40))], "x86-64")
    transform = next(edge for edge in flow.edges if edge.edge_type == "TRANSFORM")
    assert transform.value_identity.version == 1


def test_iat_indirect_call_survives_register_copy_and_spill():
    code = bytes.fromhex(
        "48 8B 05 F9 0F 00 00 49 89 C3 4C 89 5C 24 40 "
        "48 8B 4C 24 40 FF D1 C3"
    )
    context = context_for(code)
    imports = [{"dll": "kernel32.dll", "functions": [{
        "name": "ReadFile", "iat_address": BASE + 0x2000, "ordinal": None,
    }]}]
    calls = find_import_calls(
        [item[0] for item in context.records], imports, "x86-64", BASE, context.records,
    )
    assert len(calls) == 1
    assert calls[0][2]["name"] == "ReadFile"


def test_single_function_pointer_propagates_to_unique_target():
    caller = bytes.fromhex(
        "E8 00 00 00 00 48 89 C1 49 BB 30 10 00 40 01 00 00 00 41 FF D3 C3"
    )
    code = caller + b"\xCC" * (0x30 - len(caller)) + b"\xC3"
    context = context_for(code, ((0x1000, 0x1016), (0x1030, 0x1031)))
    flow = analyze_intra_function(
        context, [source(ReturnValueLocation(0x1000, 0x1000, "a"))], "x86-64",
    )
    assert any(item["callee_rva"] == 0x1030 and item["resolution"] == "resolved-indirect"
               for item in flow.call_arguments)


def test_ambiguous_function_pointer_is_left_unresolved():
    # je enters the final assignment/call region, so two static paths can reach the call.
    code = bytes.fromhex(
        "85 C0 74 0A 49 BB 30 10 00 40 01 00 00 00 "
        "49 BB 40 10 00 40 01 00 00 00 41 FF D3 C3"
    )
    context = context_for(code)
    call_index = next(i for i, (_, decoded) in enumerate(context.records) if decoded.mnemonic == "call")
    resolution = resolve_indirect_call(context.records, call_index, BASE)
    assert resolution.target_address is None
    assert "control-flow paths" in resolution.unresolved_reason


def _wrapper_context():
    caller = bytes.fromhex("48 8D 4D C0 E8 17 00 00 00 80 7D C0 41 C3")
    wrapper = bytes.fromhex("C3")
    code = caller + b"\xCC" * (0x20 - len(caller)) + wrapper
    return context_for(code, ((0x1000, 0x100E), (0x1020, 0x1021)))


def test_input_wrapper_maps_written_argument_back_to_caller():
    context = _wrapper_context()
    wrapper_source = InputSource(
        "wrapper-input", "FUN_1020", 0x1020, BASE + 0x1020, 0x1020, "fgets",
        ArgumentLocation(0x1020, 0), 32, "CONFIRMED", ("fgets writes wrapper arg0",),
    )
    trace = propagate_input_flows(context, [wrapper_source], "x86-64").traces[0]
    assert any(item["function_rva"] == 0x1000 and item["instruction_rva"] == 0x1009
               and item["input_flow"] != "NONE" for item in trace.comparisons)


def test_wrapper_false_positive_does_not_map_local_buffer_to_caller():
    context = _wrapper_context()
    local_source = InputSource(
        "local-input", "FUN_1020", 0x1020, BASE + 0x1020, 0x1020, "fgets",
        StackLocation(0x1020, -0x20), 32, "CONFIRMED", ("fgets writes local",),
    )
    trace = propagate_input_flows(context, [local_source], "x86-64").traces[0]
    assert not any(item["function_rva"] == 0x1000 for item in trace.comparisons)


def test_function_chunk_flow_reaches_jump_connected_tail():
    code = bytes.fromhex("E8 00 00 00 00 48 89 C1 EB 06") + b"\xCC" * 6 + bytes.fromhex("48 83 F9 41 C3")
    context = context_for(code)
    flow = analyze_intra_function(
        context, [source(ReturnValueLocation(0x1000, 0x1000, "a"))], "x86-64",
    )
    assert any(item["instruction_rva"] == 0x1010 and item["input_flow"] == "CONFIRMED"
               for item in flow.comparisons)
    assert any(chunk.relation == "TAIL" for chunk in context.functions[0].chunks)


def test_global_version_flow_reaches_direct_consumer():
    # main: input return -> global; check_global() reads and mutates the value.
    caller = bytes.fromhex(
        "E8 00 00 00 00 48 89 05 F4 0F 00 00 E8 1F 00 00 00 C3"
    )
    checker = bytes.fromhex("48 8B 05 C9 0F 00 00 48 83 C0 04 48 83 F8 2A C3")
    code = caller + b"\xCC" * (0x30 - len(caller)) + checker
    context = context_for(code, ((0x1000, 0x1012), (0x1030, 0x1040)))
    flow = propagate_input_flows(
        context, [source(ReturnValueLocation(0x1000, 0x1000, "a"))], "x86-64",
    )
    comparison = next(
        item for trace in flow.traces for item in trace.comparisons
        if item["function_rva"] == 0x1030 and item["instruction_rva"] == 0x103B
    )
    identity = comparison["value_identities"][0]
    assert identity["origin"] == "input"
    assert identity["version"] == 1


def test_return_derived_pointer_preserves_input_identity():
    # main passes input to transform; transform returns input+4; main compares it.
    caller = bytes.fromhex(
        "E8 00 00 00 00 48 89 C1 E8 23 00 00 00 48 83 F8 2A C3"
    )
    transform = bytes.fromhex("48 89 C8 48 83 C0 04 C3")
    code = caller + b"\xCC" * (0x30 - len(caller)) + transform
    context = context_for(code, ((0x1000, 0x1012), (0x1030, 0x1038)))
    flow = propagate_input_flows(
        context, [source(ReturnValueLocation(0x1000, 0x1000, "a"))], "x86-64",
    )
    comparison = next(
        item for trace in flow.traces for item in trace.comparisons
        if item["function_rva"] == 0x1000 and item["instruction_rva"] == 0x100D
        and item["value_identities"]
    )
    identity = comparison["value_identities"][0]
    assert identity["origin"] == "input"
    assert identity["offset"] == 4
    assert identity["version"] == 1


def test_partial_slice_flow_break_has_real_subchain_and_next_target():
    caller = bytes.fromhex(
        "E8 00 00 00 00 0F B6 45 C0 34 69 88 45 E0 "
        "48 8D 4D A0 E8 0D 00 00 00 C3"
    )
    code = caller + b"\xCC" * (0x24 - len(caller)) + b"\xC3"
    context = context_for(code, ((0x1000, 0x1018), (0x1024, 0x1025)))
    root = source(StackLocation(0x1000, -0x40))
    flow = propagate_input_flows(context, [root], "x86-64")
    breaks = build_static_flow_breaks([root], flow, context, [])
    assert len(breaks) == 1
    assert len(breaks[0].edges) >= 3
    assert breaks[0].next_unresolved_target["function_rva"] == 0x1024
    assert "alias recovery" in breaks[0].reason
