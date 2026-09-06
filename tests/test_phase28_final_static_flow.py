import struct

from reversehelper.dataflow_model import ArgumentLocation, InputSource
from reversehelper.disassembler import Disassembler, iter_instruction_details
from reversehelper.function_index import FunctionIndex
from reversehelper.interproc_dataflow import propagate_input_flows
from reversehelper.validation_analyzer import _branch_after_compare, discover_validation


BASE64 = 0x140000000
BASE32 = 0x400000


def rel_call(source_rva, target_rva):
    return b"\xE8" + struct.pack("<i", target_rva - source_rva - 5)


def make_context(chunks, architecture="x86-64"):
    base = BASE64 if architecture == "x86-64" else BASE32
    end = max(rva + len(code) for rva, code in chunks)
    data = bytearray(b"\xCC" * (end - 0x1000))
    for rva, code in chunks:
        data[rva - 0x1000:rva - 0x1000 + len(code)] = code
    sections = [{"name": ".text", "virtual_address": 0x1000, "raw_address": 0,
                 "raw_size": len(data), "flags": ["EXECUTE", "READ"]}]
    instructions = Disassembler(architecture, base).disassemble_range(
        bytes(data), sections, 0x1000, len(data), skip_invalid=True,
    )
    records = list(iter_instruction_details(instructions, architecture))
    ranges = tuple((rva, rva + len(code)) for rva, code in chunks)
    return FunctionIndex(records, sections, base, runtime_functions=ranges)


def argument_source(architecture="x86-64"):
    base = BASE64 if architecture == "x86-64" else BASE32
    return InputSource(
        "root", "FUN_1000", 0x1000, base + 0x1000, 0x1000,
        "EXPORTED_ARGUMENT", ArgumentLocation(0x1000, 0), None,
        "CONFIRMED", ("test input",),
    )


def summary(flow, rva):
    return next(item for item in flow.function_summaries if item.function_rva == rva)


def test_interproc_arg_identity_x64_survives_callee_spill_reload():
    caller = rel_call(0x1000, 0x1040) + b"\xC3"
    callee = bytes.fromhex("48 89 4C 24 08 48 83 EC 28 48 8B 44 24 30 48 83 F8 41 48 83 C4 28 C3")
    flow = propagate_input_flows(make_context(((0x1000, caller), (0x1040, callee))),
                                 [argument_source()], "x86-64")
    trace = flow.traces[0]
    comparison = next(item for item in trace.comparisons if item["function_rva"] == 0x1040)
    assert comparison["value_identities"][0]["id"] == "value-root"


def test_interproc_arg_identity_x86_uses_cdecl_push_order():
    prefix = bytes.fromhex("55 89 E5 8B 45 08 50")
    caller = prefix + rel_call(0x1000 + len(prefix), 0x1040) + bytes.fromhex("83 C4 04 C9 C3")
    callee = bytes.fromhex("55 89 E5 8B 45 08 83 F8 41 C9 C3")
    flow = propagate_input_flows(make_context(((0x1000, caller), (0x1040, callee)), "x86"),
                                 [argument_source("x86")], "x86")
    comparison = next(item for item in flow.traces[0].comparisons if item["function_rva"] == 0x1040)
    assert comparison["value_identities"][0]["id"] == "value-root"


def test_return_same_argument_summary():
    caller = rel_call(0x1000, 0x1040) + bytes.fromhex("48 85 C0 C3")
    callee = bytes.fromhex("48 89 C8 C3")
    flow = propagate_input_flows(make_context(((0x1000, caller), (0x1040, callee))),
                                 [argument_source()], "x86-64")
    assert summary(flow, 0x1040).returns[0].kind == "RETURNS_ARGUMENT"


def test_return_derived_argument_keeps_base_identity_and_offset():
    caller = rel_call(0x1000, 0x1040) + bytes.fromhex("48 85 C0 C3")
    callee = bytes.fromhex("48 89 C8 48 83 C0 04 C3")
    flow = propagate_input_flows(make_context(((0x1000, caller), (0x1040, callee))),
                                 [argument_source()], "x86-64")
    returned = summary(flow, 0x1040).returns[0]
    assert (returned.kind, returned.offset) == ("RETURNS_DERIVED_ARGUMENT", 4)
    edge = next(edge for edge in flow.traces[0].edges if edge.edge_type == "RETURN"
                and edge.instruction_rva == 0x1000)
    assert edge.value_identity.id == "value-root"


def test_return_overwrite_negative_kills_provenance():
    caller = rel_call(0x1000, 0x1040) + bytes.fromhex("48 85 C0 C3")
    callee = bytes.fromhex("48 89 C8 31 C0 C3")
    flow = propagate_input_flows(make_context(((0x1000, caller), (0x1040, callee))),
                                 [argument_source()], "x86-64")
    assert not any(item.function_rva == 0x1040 for item in flow.function_summaries)
    assert not any(item["function_rva"] == 0x1000 and item["input_flow"] != "NONE"
                   for item in flow.traces[0].comparisons)


def test_inplace_mutation_advances_object_version_in_caller():
    caller = rel_call(0x1000, 0x1040) + bytes.fromhex("80 39 41 C3")
    callee = bytes.fromhex("80 31 20 C3")
    flow = propagate_input_flows(make_context(((0x1000, caller), (0x1040, callee))),
                                 [argument_source()], "x86-64")
    assert summary(flow, 0x1040).mutates_arguments == (0,)
    versions = [item["value_identities"][0]["version"]
                for item in flow.traces[0].comparisons
                if item["function_rva"] == 0x1000 and item["value_identities"]]
    assert max(versions) == 1


def test_output_parameter_derived_from_input_reaches_caller_compare():
    prefix = bytes.fromhex("48 8D 54 24 20")
    caller = prefix + rel_call(0x1000 + len(prefix), 0x1040) + bytes.fromhex("80 7C 24 20 41 C3")
    callee = bytes.fromhex("8A 01 88 02 C3")
    flow = propagate_input_flows(make_context(((0x1000, caller), (0x1040, callee))),
                                 [argument_source()], "x86-64")
    relation = summary(flow, 0x1040).output_parameters[0]
    assert (relation.source_argument, relation.destination_argument) == (0, 1)
    comparison = next(item for item in flow.traces[0].comparisons
                      if item["function_rva"] == 0x1000 and item["value_identities"])
    assert comparison["value_identities"][0]["id"] == "value-root"


def test_summary_recursion_budget_reports_bounded_stop():
    first = rel_call(0x1000, 0x1040) + b"\xC3"
    second = rel_call(0x1040, 0x1080) + b"\xC3"
    third = rel_call(0x1080, 0x1040) + b"\xC3"
    flow = propagate_input_flows(make_context(((0x1000, first), (0x1040, second), (0x1080, third))),
                                 [argument_source()], "x86-64", max_call_depth=1)
    assert flow.traces[0].incomplete
    assert any("BUDGET_LIMIT" in warning for warning in flow.traces[0].warnings)


def test_golf_compare_fixture_uses_argument_related_scalar_return():
    caller = (rel_call(0x1000, 0x1040)
              + bytes.fromhex("0F B6 C0 85 C0 74 01 C3 C3"))
    callee = bytes.fromhex(
        "48 89 4C 24 08 48 83 EC 28 48 8B 4C 24 30 41 FF D3 "
        "88 44 24 20 8A 44 24 20 48 83 C4 28 C3"
    )
    context = make_context(((0x1000, caller), (0x1040, callee)))
    source = argument_source()
    flow = propagate_input_flows(context, [source], "x86-64")
    candidates = discover_validation(
        context, [], [], "x86-64", input_sources=[source],
        function_summaries=flow.function_summaries,
    )
    candidate = next(item for item in candidates if item.compare_origin == "RETURN_SEMANTICS")
    assert candidate.comparator_function == 0x1040
    assert candidate.branch_rva == 0x100A


def test_xor_test_equality_keeps_tainted_zero_result_for_decision():
    code = bytes.fromhex("48 89 C8 48 31 D0 48 85 C0 74 01 C3 C3")
    flow = propagate_input_flows(make_context(((0x1000, code),)),
                                 [argument_source()], "x86-64")
    compare = next(item for item in flow.traces[0].comparisons)
    assert compare["instruction_rva"] == 0x1006
    assert compare["input_flow"] == "CONFIRMED"


def test_sub_jz_equality_is_not_promoted_without_compare_evidence():
    code = bytes.fromhex("48 89 C8 48 29 D0 74 01 C3 C3")
    context = make_context(((0x1000, code),))
    assert discover_validation(context, [], [], "x86-64", input_sources=[argument_source()]) == []


def test_arithmetic_compare_false_positive_is_rejected_without_decision():
    code = bytes.fromhex("48 89 C8 48 31 D0 48 89 C1 C3")
    context = make_context(((0x1000, code),))
    assert discover_validation(context, [], [], "x86-64", input_sources=[argument_source()]) == []


def test_cross_block_compare_accepts_live_flags_within_budget():
    code = bytes.fromhex("48 83 F9 41 90 74 01 C3 C3")
    context = make_context(((0x1000, code),))
    records = context.function_records[0x1000]
    assert _branch_after_compare(records, 0) == 2


def test_flags_killed_negative_rejects_cross_block_branch():
    code = bytes.fromhex("48 83 F9 41 48 83 C0 01 74 01 C3 C3")
    context = make_context(((0x1000, code),))
    records = context.function_records[0x1000]
    assert _branch_after_compare(records, 0) is None
