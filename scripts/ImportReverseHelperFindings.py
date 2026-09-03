# Import ReverseHelper findings and ranked targets as conservative comments.
# @author NingWen2000
# @category ReverseHelper
# @keybinding
# @menupath Tools.ReverseHelper.Import Findings
# @toolbar

import json
import os
import re


try:
    INTEGER_TYPES = (int, long)
except NameError:
    INTEGER_TYPES = (int,)

CONFIDENCE_ORDER = {"unknown": -1, "low": 0, "medium": 1, "high": 2}


def validate_program_identity(payload, program_name, program_sha256):
    expected_sha256 = payload.get("hashes", {}).get("sha256")
    expected_name = payload.get("basic", {}).get("file_name")

    if expected_sha256 and program_sha256:
        if str(expected_sha256).lower() != str(program_sha256).lower():
            raise ValueError("SHA-256 does not match the current Ghidra program")
        return "sha256"

    if expected_name:
        left = os.path.basename(str(expected_name)).lower()
        right = os.path.basename(str(program_name)).lower()
        if left != right:
            raise ValueError("File name does not match the current Ghidra program")
        return "file-name"

    raise ValueError("ReverseHelper JSON does not contain usable program identity metadata")


def _record_rva(record):
    value = record.get("rva")
    if isinstance(value, bool) or not isinstance(value, INTEGER_TYPES) or value < 0:
        return None
    return value


def _mapped(rva, mapped_ranges):
    return any(start <= rva <= end for start, end in mapped_ranges)


def _finding_record(finding):
    return {
        "rva": finding.get("rva"),
        "category": finding.get("category", "unknown"),
        "priority": None,
        "confidence": finding.get("confidence", "unknown"),
        "reason": finding.get("reason", ""),
        "evidence": finding.get("evidence", []),
        "recommended_action": finding.get("recommended_action", ""),
        "finding_ids": [finding.get("id", "<missing>")],
        "high_confidence": finding.get("confidence") == "high",
    }


def _records(payload):
    findings = payload.get("findings", [])
    findings_by_id = {item.get("id"): item for item in findings if item.get("id")}
    targets = payload.get("reverse_targets", payload.get("targets", []))
    if not targets:
        return [_finding_record(finding) for finding in findings]

    records = []
    linked_ids = set()
    for target in targets:
        finding_ids = [item for item in target.get("finding_ids", []) if item]
        linked = [findings_by_id[item] for item in finding_ids if item in findings_by_id]
        linked_ids.update(finding_ids)
        evidence = []
        for finding in linked:
            evidence.extend(finding.get("evidence", []))
        confidence = max(
            [item.get("confidence", "unknown") for item in linked] or ["unknown"],
            key=lambda item: CONFIDENCE_ORDER.get(item, -1),
        )
        records.append(
            {
                "rva": target.get("rva"),
                "category": target.get("category", "unknown"),
                "priority": target.get("priority"),
                "confidence": confidence,
                "reason": target.get("reason", ""),
                "evidence": evidence,
                "recommended_action": target.get("recommended_action", ""),
                "finding_ids": finding_ids,
                "high_confidence": any(item.get("confidence") == "high" for item in linked),
            }
        )

    for finding in findings:
        if finding.get("id") not in linked_ids:
            records.append(_finding_record(finding))
    return records


def _comment(record):
    lines = [
        "ReverseHelper",
        "Category: %s" % record["category"],
    ]
    if record["priority"]:
        lines.append("Priority: %s" % record["priority"])
    lines.append("Confidence: %s" % record["confidence"])
    if record["finding_ids"]:
        lines.append("Finding IDs: %s" % ", ".join(record["finding_ids"]))
    if record["reason"]:
        lines.append("Reason: %s" % record["reason"])
    if record["evidence"]:
        lines.append("Evidence:")
        lines.extend("- %s" % item for item in record["evidence"][:8])
    if record["recommended_action"]:
        lines.append("Recommended action: %s" % record["recommended_action"])
    return "\n".join(lines)


def plan_import(
    payload,
    program_name,
    program_sha256,
    mapped_ranges,
    allow_renames=False,
):
    validate_program_identity(payload, program_name, program_sha256)
    operations = {}

    for record in _records(payload):
        rva = _record_rva(record)
        if rva is None or not _mapped(rva, mapped_ranges):
            continue
        rename = None
        if (
            allow_renames
            and record["priority"] == "high"
            and record["confidence"] == "high"
            and record["high_confidence"]
            and record["category"] in {"validation", "crypto", "anti-debug"}
        ):
            category = re.sub(r"[^a-z0-9]+", "_", record["category"].lower()).strip("_")
            rename = "rh_%s_%x" % (category, rva)

        operation = operations.get(rva)
        comment = _comment(record)
        if operation is None:
            operations[rva] = {"rva": rva, "comment": comment, "rename": rename}
        else:
            if comment not in operation["comment"]:
                operation["comment"] += "\n\n" + comment
            if operation["rename"] is None:
                operation["rename"] = rename

    return [operations[rva] for rva in sorted(operations)]


def _mapped_ranges(program):
    image_base = program.getImageBase()
    ranges = []
    for block in program.getMemory().getBlocks():
        try:
            start = block.getStart().subtract(image_base)
            end = block.getEnd().subtract(image_base)
        except Exception:
            continue
        if end >= 0:
            ranges.append((max(0, start), end))
    return ranges


def run_import():
    source = askFile("Select ReverseHelper JSON", "Import")
    reader = open(str(source), "r")
    try:
        payload = json.load(reader)
    finally:
        reader.close()

    allow_renames = "--rename-high-confidence" in list(getScriptArgs())
    try:
        operations = plan_import(
            payload,
            currentProgram.getName(),
            currentProgram.getExecutableSHA256(),
            _mapped_ranges(currentProgram),
            allow_renames,
        )
    except ValueError as error:
        printerr("ReverseHelper import refused: %s" % error)
        return

    image_base = currentProgram.getImageBase()
    memory = currentProgram.getMemory()
    function_manager = currentProgram.getFunctionManager()
    imported = 0
    renamed = 0

    for operation in operations:
        try:
            address = image_base.addNoWrap(operation["rva"])
        except Exception as error:
            printerr("Skipping RVA 0x%X: %s" % (operation["rva"], error))
            continue
        if not memory.contains(address):
            printerr("Skipping unmapped RVA 0x%X" % operation["rva"])
            continue

        existing = getPlateComment(address)
        comment = operation["comment"]
        if existing and comment not in existing:
            comment = existing + "\n\n" + comment
        setPlateComment(address, comment)
        imported += 1

        if operation["rename"]:
            function = function_manager.getFunctionContaining(address)
            if function is not None and function.getName().startswith("FUN_"):
                from ghidra.program.model.symbol import SourceType

                function.setName(operation["rename"], SourceType.USER_DEFINED)
                renamed += 1

    println("ReverseHelper imported %d comment(s), %d conservative rename(s)." % (imported, renamed))


if globals().get("currentProgram") is not None:
    run_import()
