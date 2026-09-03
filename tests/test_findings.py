import json

from reversehelper.findings import Finding, Instruction, ReverseTarget


def test_instruction_serializes_static_location_and_bytes():
    insn = Instruction(
        address=0x401820,
        rva=0x1820,
        file_offset=0xC20,
        size=5,
        raw_bytes=bytes.fromhex("E8 DB 01 00 00"),
        mnemonic="call",
        op_str="0x401a00",
    )

    assert insn.to_dict() == {
        "address": 0x401820,
        "rva": 0x1820,
        "file_offset": 0xC20,
        "size": 5,
        "bytes": "E8 DB 01 00 00",
        "mnemonic": "call",
        "op_str": "0x401a00",
    }


def test_finding_is_json_ready_with_optional_location_fields():
    finding = Finding(
        id="control-transfer-0001",
        category="control-flow",
        title="Indirect call target is unresolved",
        rva=0x1440,
        va=0x401440,
        file_offset=None,
        section=".text",
        severity="info",
        confidence="high",
        evidence=("CALL EAX at RVA 0x1440", "Target comes from a register"),
        reason="The call target is only available at runtime.",
        recommended_action="Inspect EAX immediately before the call.",
    )

    payload = finding.to_dict()
    assert payload["file_offset"] is None
    assert payload["evidence"] == ["CALL EAX at RVA 0x1440", "Target comes from a register"]
    assert json.loads(json.dumps(payload))["confidence"] == "high"


def test_reverse_target_priority_is_separate_from_finding_severity():
    finding = Finding(
        id="validation-0001",
        category="validation",
        title="Possible memcmp validation branch",
        rva=0x1820,
        va=0x401820,
        file_offset=0xC20,
        section=".text",
        severity="low",
        confidence="high",
        evidence=("CALL memcmp", "TEST EAX, EAX", "JNZ RVA 0x1850"),
        reason="The comparison result directly controls a branch.",
        recommended_action="Inspect both comparison buffers and branch targets.",
    )
    target = ReverseTarget(
        category="validation",
        rva=0x1820,
        va=0x401820,
        file_offset=0xC20,
        section=".text",
        priority="high",
        reason=finding.reason,
        recommended_action=finding.recommended_action,
        finding_ids=(finding.id,),
    )

    assert finding.to_dict()["severity"] == "low"
    assert target.to_dict()["priority"] == "high"
    assert target.to_dict()["finding_ids"] == ["validation-0001"]
