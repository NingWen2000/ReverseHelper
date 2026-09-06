from reversehelper.function_index import FunctionIndex
from reversehelper.target_ranker import rank_targets
from tests.p0_support import Code, analyze_code


def test_retained_main_symbol_is_a_bounded_controller_target():
    context, _, _, _ = analyze_code(bytes.fromhex("C3"))
    named = FunctionIndex(context.records, context.sections, context.image_base, 0x1000,
                          symbols=({"rva": 0x1000, "name": "_main"},))
    target = rank_targets([], context=named)[0]
    assert target.function == "_main"
    assert target.score == 24
    assert target.score_breakdown[0]["rule"] == "program_entry"


def test_runtime_failure_text_is_not_a_ctf_target_signal():
    code = Code()
    code.pointer(0x30A0)
    code.emit("C3")
    _, strings, _, targets = analyze_code(
        code.finish(), extra_data={0x30A0: b"Mingw runtime failure:\0"},
    )
    runtime = next(item for item in strings if item["value"] == "Mingw runtime failure:")
    assert runtime["runtime_noise"] is True
    assert runtime["priority"] == "LOW"
    assert all(runtime["id"] not in target.finding_ids for target in targets)

