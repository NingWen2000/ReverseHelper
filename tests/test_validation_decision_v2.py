import struct

from tests.p0_support import Code, analyze_code, compare_code


def test_comparator_result_consumed_by_setcc_is_recorded():
    code = Code()
    code.call(0x2008)  # input
    code.pointer(0x3060)
    code.pointer(0x3080)
    code.call(0x2000)  # strcmp
    code.emit("85 C0 0F 94 C0 C3")  # test eax,eax; sete al; ret
    _, _, candidates, _ = analyze_code(code.finish())
    candidate = candidates[0]
    assert candidate.decision_type == "setcc"
    assert candidate.branch_polarity.startswith("zero/equal")
    assert candidate.context_only is False


def test_callee_comparator_return_is_linked_to_caller_branch():
    code = Code()
    code.emit(b"\xE8" + struct.pack("<i", 0x1100 - 0x1005))
    code.emit("85 C0")
    code.jump("75", "failure")
    code.pointer(0x3020)
    code.call(0x2010)
    code.emit("C3")
    code.label("failure")
    code.pointer(0x3000)
    code.call(0x2010)
    code.emit("C3")
    code.emit(b"\x90" * (0x100 - len(code.bytes)))
    code.pointer(0x3060)
    code.pointer(0x3080)
    code.call(0x2000)
    code.emit("C3")
    blob = code.finish()
    _, _, candidates, _ = analyze_code(blob, runtime=((0x1000, 0x1100), (0x1100, 0x1000 + len(blob))))
    candidate = next(item for item in candidates if item.function_rva == 0x1100)
    assert candidate.decision_type == "return_value_conditional_branch"
    assert any("consumed by caller" in evidence for evidence in candidate.evidence)


def test_inlined_byte_decision_with_outcome_text_is_actionable():
    code = Code()
    code.emit("80 7D FC 41")
    code.jump("75", "failure")
    code.pointer(0x3020)
    code.call(0x2010)
    code.emit("C3")
    code.label("failure")
    code.pointer(0x3000)
    code.call(0x2010)
    code.emit("C3")
    _, _, candidates, _ = analyze_code(code.finish())
    candidate = next(item for item in candidates if item.validation_type == "INLINED_BYTE_COMPARE")
    assert candidate.compare_target["value"] == 0x41
    assert candidate.context_only is False


def test_crt_symbol_context_is_non_actionable():
    context, strings, candidates, _ = analyze_code(
        # Ordinary memcmp-like data decision with no input or outcome references.
        compare_code("memcmp", positive=False),
        api="memcmp",
    )
    function = context.functions[0]
    # Rebuild the same context with an explicit retained runtime symbol.
    from reversehelper.function_index import FunctionIndex
    runtime_context = FunctionIndex(context.records, context.sections, context.image_base, function.rva,
                                    symbols=({"rva": function.rva, "name": "_memcmp"},))
    from reversehelper.instruction_context import find_import_calls
    from reversehelper.validation_analyzer import discover_validation
    imports = [{"dll": "msvcrt.dll", "functions": [{"name": "memcmp", "iat_address": context.image_base + 0x2000}]}]
    instructions = [item for item, _ in context.records]
    calls = find_import_calls(instructions, imports, "x86", context.image_base, runtime_context.records)
    runtime_candidates = discover_validation(runtime_context, calls, strings, "x86")
    assert runtime_candidates and runtime_candidates[0].runtime_noise
    assert runtime_candidates[0].context_only


def test_static_linked_comparator_records_origin_and_caller_decision():
    from reversehelper.disassembler import Disassembler, iter_instruction_details
    from reversehelper.function_index import FunctionIndex
    from reversehelper.validation_analyzer import discover_validation, split_compare_decision_sites

    # caller: call comparator; test eax,eax; jne; ret
    caller = bytes.fromhex("E8 1B 00 00 00 85 C0 75 01 C3 C3")
    body = bytes.fromhex(
        "8B 54 24 04 8B 4C 24 08 8A 02 3A 01 75 0B 84 C0 74 04 "
        "42 41 EB F2 31 C0 C3 B8 01 00 00 00 C3"
    )
    blob = caller + b"\xCC" * (0x20 - len(caller)) + body
    sections = [{"name": ".text", "virtual_address": 0x1000, "raw_address": 0,
                 "raw_size": len(blob), "flags": ["EXECUTE", "READ"]}]
    instructions = Disassembler("x86", 0x400000).disassemble_range(blob, sections, 0x1000, len(blob), skip_invalid=True)
    records = list(iter_instruction_details(instructions, "x86"))
    context = FunctionIndex(records, sections, 0x400000,
                            runtime_functions=((0x1000, 0x100B), (0x1020, 0x103F)))
    candidates = discover_validation(context, [], [], "x86")
    candidate = next(item for item in candidates if item.compare_origin == "STATIC_LINKED_COMPARATOR")
    assert candidate.comparator_function == 0x1020
    assert candidate.decision_type == "return_value_conditional_branch"
    compare_sites, _ = split_compare_decision_sites([candidate])
    assert compare_sites[0].compare_origin == "STATIC_LINKED_COMPARATOR"


def test_plain_counter_loop_is_not_a_static_comparator():
    _, _, candidates, _ = analyze_code(bytes.fromhex("31 C0 40 83 F8 10 75 F9 C3"))
    assert not any(item.compare_origin == "STATIC_LINKED_COMPARATOR" for item in candidates)
