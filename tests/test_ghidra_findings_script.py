import runpy
from pathlib import Path

import pytest


SCRIPT = Path(__file__).parents[1] / "scripts" / "ImportReverseHelperFindings.py"
SCRIPT_API = runpy.run_path(str(SCRIPT))


def _payload(rva=0x1820, *, file_name="challenge.exe", sha256="a" * 64):
    return {
        "basic": {"file_name": file_name},
        "hashes": {"sha256": sha256},
        "findings": [
            {
                "id": "validation-branch",
                "category": "validation",
                "title": "Possible Validation Site",
                "rva": rva,
                "confidence": "high",
                "evidence": ["Comparator: memcmp", "Condition: TEST EAX, EAX", "Branch: JNE"],
                "reason": "The comparator result reaches a conditional branch.",
                "recommended_action": "Inspect both branch targets.",
            }
        ],
        "reverse_targets": [
            {
                "category": "validation",
                "rva": rva,
                "priority": "high",
                "reason": "The comparator result reaches a conditional branch.",
                "recommended_action": "Inspect both branch targets.",
                "finding_ids": ["validation-branch"],
            }
        ],
    }


def test_script_compiles_as_python_and_defaults_to_comment_only():
    compile(SCRIPT.read_text(encoding="utf-8"), str(SCRIPT), "exec")

    operations = SCRIPT_API["plan_import"](
        _payload(),
        "challenge.exe",
        "a" * 64,
        [(0x1000, 0x1FFF)],
    )

    assert operations == [
        {
            "rva": 0x1820,
            "comment": (
                "ReverseHelper\n"
                "Category: validation\n"
                "Priority: high\n"
                "Confidence: high\n"
                "Finding IDs: validation-branch\n"
                "Reason: The comparator result reaches a conditional branch.\n"
                "Evidence:\n"
                "- Comparator: memcmp\n"
                "- Condition: TEST EAX, EAX\n"
                "- Branch: JNE\n"
                "Recommended action: Inspect both branch targets."
            ),
            "rename": None,
        }
    ]


def test_program_identity_mismatch_refuses_import():
    with pytest.raises(ValueError, match="SHA-256"):
        SCRIPT_API["plan_import"](
            _payload(),
            "challenge.exe",
            "b" * 64,
            [(0x1000, 0x1FFF)],
        )


def test_file_name_is_used_when_ghidra_hash_is_unavailable():
    operations = SCRIPT_API["plan_import"](
        _payload(),
        "challenge.exe",
        None,
        [(0x1000, 0x1FFF)],
    )

    assert operations[0]["rva"] == 0x1820


def test_out_of_range_rva_is_not_imported():
    operations = SCRIPT_API["plan_import"](
        _payload(rva=0x9000),
        "challenge.exe",
        "a" * 64,
        [(0x1000, 0x1FFF)],
    )

    assert operations == []


def test_rename_requires_explicit_opt_in_and_high_confidence_target():
    default = SCRIPT_API["plan_import"](
        _payload(),
        "challenge.exe",
        "a" * 64,
        [(0x1000, 0x1FFF)],
    )
    opted_in = SCRIPT_API["plan_import"](
        _payload(),
        "challenge.exe",
        "a" * 64,
        [(0x1000, 0x1FFF)],
        True,
    )

    assert default[0]["rename"] is None
    assert opted_in[0]["rename"] == "rh_validation_1820"


def test_script_rebases_rva_from_current_ghidra_image_base():
    source = SCRIPT.read_text(encoding="utf-8")

    assert 'image_base.addNoWrap(operation["rva"])' in source
    assert "memory.contains(address)" in source
