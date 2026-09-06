from dataclasses import replace

import pytest

from reversehelper.findings import Finding
from reversehelper.function_index import FunctionIndex
from reversehelper.string_intelligence import classify_ctf_string
from reversehelper.target_ranker import rank_targets
from reversehelper.validation_analyzer import discover_validation
from p0_support import Code, analyze_code, compare_code


@pytest.mark.parametrize("x64", [False, True])
def test_success_failure_strings(x64):
    context, strings, _, _ = analyze_code(compare_code(x64=x64), x64=x64)
    success = next(s for s in strings if s["category"] == "SUCCESS")
    failure = next(s for s in strings if s["category"] == "FAILURE")
    for item in (success, failure):
        assert item["xref_count"] == 1
        assert item["xref_functions"] == [context.functions[0].name]
        assert item["priority"] == "HIGH"
        assert item["reasons"] and item["xrefs"][0]["nearby_branches"]
    assert failure["value"] == "Wrong flag!"


@pytest.mark.parametrize("text,category", [
    ("incorrect password", "FAILURE"), ("not correct", "FAILURE"), ("try again", "FAILURE"),
    ("flag{demo}", "FLAG"), ("passwd", "PASSWORD"), ("input", "INPUT"), ("key", "KEY"),
    ("fatal error", "ERROR"), ("%06x", "FORMAT"), ("C:\\tmp\\data.bin", "FILE"),
    ("https://example.test", "NETWORK"), ("AES encrypt", "CRYPTO"), ("debugger", "DEBUG"),
    ("monkey keyboard", "GENERIC"),
])
def test_ctf_classification(text, category):
    assert classify_ctf_string(text)[0] == category


def test_unreferenced_keyword_does_not_receive_high_priority():
    _, strings, _, targets = analyze_code(b"\xc3")
    failure = next(s for s in strings if s["category"] == "FAILURE")
    assert failure["score"] == 20 and failure["confidence"] == "low"
    assert not failure["xref_functions"]
    assert not any(t.score > 3 for t in targets)


@pytest.mark.parametrize("x64", [False, True])
def test_strcmp_validation(x64):
    _, _, candidates, targets = analyze_code(compare_code(x64=x64), x64=x64)
    candidate = candidates[0]
    assert candidate.validation_type == "STRCMP"
    assert candidate.success_branch and candidate.failure_branch
    assert candidate.success_branch["successor_rva"] != candidate.failure_branch["successor_rva"]
    assert candidate.input_source["api"] == "fgets"
    assert "unproven" in candidate.input_source["relation"]
    assert candidate.compare_length is None
    assert candidate.compare_target["rva"] == 0x3060
    assert targets[0].target_type == "VALIDATION"
    assert targets[0].score >= 65


@pytest.mark.parametrize("x64", [False, True])
def test_memcmp_validation(x64):
    _, _, candidates, targets = analyze_code(compare_code("memcmp", x64=x64), api="memcmp", x64=x64)
    assert candidates[0].compare_length == 6
    assert candidates[0].compare_target["bytes_hex"] == b"RHdemo".hex(" ")
    assert targets[0].score >= 65


def test_byte_loop_validation():
    c = Code()
    c.call(0x2008)
    c.emit("BE 80 30 40 00 BF 60 30 40 00 B9 06 00 00 00")
    c.label("loop")
    c.emit("8A 06 3A 07")  # mov al,[esi]; cmp al,[edi]
    c.jump("75", "failure")
    c.emit("46 47 49")  # both byte pointers progress
    c.jump("75", "loop")
    c.pointer(0x3020)
    c.emit("C3")
    c.label("failure")
    c.pointer(0x3000)
    c.emit("C3")
    _, _, candidates, targets = analyze_code(c.finish())
    assert len(candidates) == 1
    assert candidates[0].validation_type == "BYTE_COMPARE_LOOP"
    assert candidates[0].loop
    assert candidates[0].failure_branch
    assert targets[0].score >= 65


def test_nul_scan_is_not_byte_validation():
    # cmp byte ptr [esi],0; je end; inc esi; jmp start; ret
    _, _, candidates, _ = analyze_code(bytes.fromhex("80 3E 00 74 03 46 EB F8 C3"))
    assert not candidates


@pytest.mark.parametrize("x64", [False, True])
def test_false_positive_memcmp(x64):
    _, _, candidates, targets = analyze_code(compare_code("memcmp", positive=False, x64=x64), api="memcmp", x64=x64)
    assert candidates and candidates[0].input_source is None
    assert candidates[0].success_branch is None and candidates[0].failure_branch is None
    assert targets[0].score <= 30
    assert targets[0].target_type == "COMPARE"
    assert not any(t.priority == "high" or t.target_type == "VALIDATION" for t in targets)


def test_return_overwrite_does_not_link_comparison_to_outcome():
    _, _, candidates, targets = analyze_code(compare_code(overwrite=True))
    assert candidates[0].branch_rva is None
    assert candidates[0].success_branch is None
    assert candidates[0].failure_branch is None
    assert "outcome_branch" not in {part["rule"] for part in targets[0].score_breakdown}


def test_multiple_candidate_ranking():
    weak = compare_code("memcmp", positive=False)
    strong = compare_code("memcmp")
    # Second code chunk uses absolute x86 addresses, so relocation is unnecessary.
    code = weak + b"\xcc" * (0x100 - len(weak)) + strong
    context, strings, candidates, _ = analyze_code(code, api="memcmp", runtime=((0x1000, 0x1100), (0x1100, 0x1200)))
    strong_candidate = next(c for c in candidates if c.function_rva == 0x1100)
    input_finding = Finding("input-real", "input", "Input Candidate: fgets call site", 0x1100,
                            0x401100, 0x300, ".text", "info", "medium", ("CALL fgets",), "Actual input call", "Inspect its arguments")
    targets = rank_targets([input_finding], context=context, interesting_strings=strings, validation_candidates=candidates)
    assert targets[0].rva == 0x1100
    assert targets[0].score > next(t.score for t in targets if t.rva == 0x1000)
    assert strong_candidate.success_branch and strong_candidate.failure_branch
    assert len({t.rva for t in targets if t.target_kind == "function"}) == 2


def test_corroboration_counts_sources_not_repeated_findings():
    context, strings, candidates, _ = analyze_code(compare_code("memcmp"), api="memcmp")
    only = rank_targets([], context=context, validation_candidates=candidates)
    duplicated = rank_targets([], context=context, validation_candidates=candidates * 50)
    combined = rank_targets([], context=context, validation_candidates=candidates, interesting_strings=strings)
    assert only[0].score == duplicated[0].score <= 30
    assert combined[0].score > only[0].score
    assert any(p["rule"] == "corroboration" for p in combined[0].score_breakdown)
    for target in combined:
        assert target.score == sum(p["points"] for p in target.score_breakdown)


def test_duplicate_string_locations_and_utf16_xrefs_are_preserved():
    c = Code()
    c.pointer(0x30A0)
    c.pointer(0x30C0)
    c.emit("C3")
    _, strings, _, _ = analyze_code(c.finish(), extra_data={0x30A0: b"Wrong flag!\0", 0x30C0: "password".encode("utf-16le") + b"\0\0"})
    duplicates = [s for s in strings if s["value"] == "Wrong flag!"]
    assert len(duplicates) == 2
    assert {s["xref_count"] for s in duplicates} == {0, 1}
    wide = next(s for s in strings if s["encoding"] == "UTF-16LE" and s["value"] == "password")
    assert wide["rva"] == 0x30C0 and wide["xref_count"] == 1


def test_unknown_function_does_not_invent_function_name():
    _, strings, candidates, targets = analyze_code(compare_code(), entry=None)
    assert all(not s["xref_functions"] for s in strings)
    assert all(c.function is None for c in candidates)
    assert all(t.function is None and t.score <= 40 for t in targets)


def test_function_membership_does_not_swallow_unreachable_adjacent_code():
    # A return followed by another function without a seed is not one big function.
    context, _, _, _ = analyze_code(b"\xc3" + compare_code())
    assert context.owner(0x1000)
    assert context.owner(0x1001) is None


def test_function_membership_budget_is_explicit():
    context, _, _, _ = analyze_code(b"\x90" * 20 + b"\xc3")
    limited = FunctionIndex(context.records, context.sections, context.image_base, 0x1000, limit=4)
    assert limited.truncated and limited.functions[0].truncated
    assert len(limited.owners) == 4


def test_length_plus_comparison_retains_explicit_length_evidence():
    c = Code()
    c.call(0x2008)
    c.call(0x2018)
    c.emit("83 F8 06")
    c.jump("75", "failure")
    c.emit("6A 06")
    c.pointer(0x3060)
    c.pointer(0x3080)
    c.call(0x2000)
    c.emit("85 C0")
    c.jump("75", "failure")
    c.pointer(0x3020)
    c.emit("C3")
    c.label("failure")
    c.pointer(0x3000)
    c.emit("C3")
    _, _, candidates, _ = analyze_code(c.finish(), api="memcmp")
    assert candidates[0].validation_type == "LENGTH_AND_COMPARISON"
    assert candidates[0].compare_length == 6
    assert candidates[0].length_check["length"] == 6
    assert "unproven" in candidates[0].length_check["relation"]


def test_checksum_return_comparison():
    c = Code()
    c.call(0x2000)
    c.emit("3D 78 56 34 12")
    c.jump("75", "failure")
    c.pointer(0x3020)
    c.emit("C3")
    c.label("failure")
    c.pointer(0x3000)
    c.emit("C3")
    _, _, candidates, _ = analyze_code(c.finish(), api="crc32")
    assert candidates[0].validation_type == "CHECKSUM_COMPARISON"
    assert candidates[0].compare_target["value"] == 0x12345678


def test_hash_api_boolean_status_is_not_hash_comparison():
    _, _, candidates, _ = analyze_code(compare_code(), api="CryptHashData")
    assert not candidates


def test_hash_output_before_memcmp_is_context_only_candidate():
    c = Code()
    c.call(0x2018)
    c.emit(compare_code("memcmp"))
    context, strings, _, _ = analyze_code(c.finish(), api="memcmp")
    call_rvas = [ins.rva for ins, dec in context.records if dec.mnemonic == "call"]
    calls = [({"source_rva": call_rvas[0]}, "bcrypt.dll", {"name": "BCryptFinishHash"}),
             ({"source_rva": call_rvas[2]}, "msvcrt.dll", {"name": "memcmp"})]
    candidates = discover_validation(context, calls, strings, "x86")
    assert candidates[0].validation_type == "HASH_COMPARISON_CANDIDATE"
    assert any("buffer linkage unproven" in item for item in candidates[0].evidence)
    assert candidates[0].context_only


@pytest.mark.parametrize("operand", ["80 3E 00", "8A 06 3A 06"])
def test_terminator_or_self_compare_loop_is_not_validation(operand):
    c = Code()
    c.label("loop")
    c.emit(operand)
    c.jump("74", "done")
    c.emit("46")
    c.jump("EB", "loop")
    c.label("done")
    c.emit("C3")
    _, _, candidates, _ = analyze_code(c.finish())
    assert not candidates


def test_custom_byte_immediate_comparison_loop():
    c = Code()
    c.label("loop")
    c.emit("80 3E 41")
    c.jump("75", "done")
    c.emit("46")
    c.jump("EB", "loop")
    c.label("done")
    c.emit("C3")
    _, _, candidates, _ = analyze_code(c.finish())
    assert candidates[0].validation_type == "CUSTOM_COMPARE_LOOP"
    assert candidates[0].confidence != "high"


def test_shared_success_text_after_branch_does_not_label_branch_arms():
    c = Code()
    c.call(0x2000)
    c.emit("85 C0")
    c.jump("75", "join")
    c.emit("90")
    c.label("join")
    c.pointer(0x3020)
    c.emit("C3")
    _, _, candidates, _ = analyze_code(c.finish())
    assert candidates[0].success_branch is None
    assert candidates[0].failure_branch is None


def test_all_target_types_are_supported_and_weak_signals_stay_capped():
    context, _, _, _ = analyze_code(b"\x90\xc3")
    for category, expected in (("input", "INPUT"), ("transform", "TRANSFORM"), ("crypto", "CRYPTO"),
            ("anti-debug", "ANTI_DEBUG"), ("packing", "PACKING"), ("control-flow", "SUSPICIOUS_FUNCTION")):
        finding = Finding("test", category, "Local candidate", 0x1000, 0x401000, 0x200, ".text", "info", "low", ("local evidence",), "Local evidence", "Inspect")
        target = rank_targets([finding], context=context)[0]
        assert target.target_type == expected and target.score <= 30
    data = replace(finding, category="crypto", rva=0x3060, va=0x403060, file_offset=0x860, section=".rdata")
    assert rank_targets([data], context=context)[0].target_type == "KEY_TABLE"


def test_call_relationship_is_one_hop_and_never_proves_input_flow():
    code = bytes.fromhex("E8 0B 00 00 00 C3") + b"\xcc" * 10 + compare_code(positive=False)
    context, strings, candidates, _ = analyze_code(code)
    targets = rank_targets([], context=context, interesting_strings=strings, validation_candidates=candidates)
    caller = next(t for t in targets if t.rva == 0x1000)
    assert caller.score == 4
    assert "argument linkage unknown" in caller.reason
    assert caller.evidence_sources == ()
