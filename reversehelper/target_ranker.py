"""Function-level, evidence-capped 0–100 reverse target ranking."""

from __future__ import annotations

from collections.abc import Iterable

from .findings import Finding, ReverseTarget


WEIGHTS = {
    "ctf_string": 14, "outcome_pair": 22, "input_call": 18,
    "comparison": 16, "conditional_branch": 8, "loop": 6,
    "length_check": 6, "outcome_branch": 16, "algorithm_constant": 6,
    "sensitive_api": 4, "call_relationship": 4, "packing": 10,
    "transform": 8, "import_only": 3, "unresolved_code": 4,
    "confirmed_input_flow": 38, "likely_input_flow": 28, "possible_input_flow": 12,
    "flow_transform": 18, "return_controls_branch": 10, "unlinked_input_comparison": -15,
    "context_only": -12, "runtime_noise": -25, "pe_structure_penalty": -20,
    "strong_packing": 55, "program_entry": 24,
    "confirmed_static_slice": 40, "likely_static_slice": 30, "possible_static_slice": 12,
    "on_slice_algorithm": 18,
}
TARGET_TYPES = {
    "INPUT", "VALIDATION", "TRANSFORM", "CRYPTO", "COMPARE", "KEY_TABLE",
    "ANTI_DEBUG", "PACKING", "SUSPICIOUS_FUNCTION",
}


def rank_targets(findings: Iterable[Finding], *, image_base=None, merge_distance=0x10,
                 context=None, interesting_strings=(), validation_candidates=(), static_slices=(),
                 algorithm_candidates=(), packed=False):
    # merge_distance remains accepted for callers, but proximity cannot merge functions.
    if merge_distance < 0:
        raise ValueError("Merge distance cannot be negative")
    findings = list(findings)
    groups = {}
    locations = {}
    if context:
        image_base = context.image_base

    def add(rva, kind, source, reason, ids=(), category=None):
        if rva is None or rva < 0:
            return
        fn = context.owner(rva) if context else None
        key = ("function", fn.rva) if fn else ("location", rva)
        group = groups.setdefault(key, {"fn": fn, "signals": {}, "ids": set(), "categories": set(), "outcomes": set()})
        signal = group["signals"].setdefault(kind, {"rule": kind, "points": WEIGHTS.get(kind, -20),
            "source": source, "reason": reason, "evidence_ids": set(), "rvas": set()})
        signal["evidence_ids"].update(ids)
        signal["rvas"].add(rva)
        group["ids"].update(ids)
        if category:
            group["categories"].add(category)
        return group

    for finding in findings:
        if finding.rva is None or (finding.va is None and image_base is None):
            continue
        locations[finding.rva] = finding
        text = (finding.title + " " + finding.reason).lower()
        import_only = "import" in finding.title.lower() and "call" not in finding.title.lower()
        if import_only:
            add(finding.rva, "import_only", "imports", finding.reason, (finding.id,), finding.category)
        elif finding.category == "input":
            add(finding.rva, "input_call", "input", "Contains an input-related API call; user input linkage remains unproven", (finding.id,), "input")
        elif finding.category == "validation":
            add(finding.rva, "comparison", "comparison", "Contains a comparator call or comparison loop", (finding.id,), "compare")
            if "branch" in finding.id or "possible validation site" in text:
                add(finding.rva, "conditional_branch", "comparison", "Comparator result controls a local conditional branch", (finding.id,))
        elif finding.category == "crypto":
            add(finding.rva, "algorithm_constant", "algorithm", finding.reason, (finding.id,), "crypto")
        elif finding.category == "transform":
            add(finding.rva, "transform", "algorithm", finding.reason, (finding.id,), "transform")
        elif finding.category in {"anti-debug", "sensitive-api"}:
            add(finding.rva, "sensitive_api", "api", finding.reason, (finding.id,), finding.category)
        elif finding.category in {"packing", "entry"}:
            add(finding.rva, "packing", "packing", finding.reason, (finding.id,), "packing")
        else:
            add(finding.rva, "unresolved_code", "code", finding.reason, (finding.id,), finding.category)
        if "pe structure" in text or "pe structures" in text:
            add(finding.rva, "pe_structure_penalty", "penalty", "PE structure comparison context reduces CTF relevance", (finding.id,))

    for item in interesting_strings:
        if item.get("runtime_noise"):
            continue
        if not set(item["categories"]) & {"SUCCESS", "FAILURE", "FLAG", "PASSWORD", "INPUT", "KEY"}:
            continue
        for xref in item["xrefs"]:
            group = add(xref["rva"], "ctf_string", "strings", "References CTF-related text in executable code", (item["id"],))
            if group is not None and item.get("outcome"):
                group["outcomes"].add(item["outcome"])
    for group in groups.values():
        if group["outcomes"] == {"SUCCESS", "FAILURE"}:
            signal = group["signals"].pop("ctf_string")
            signal.update(rule="outcome_pair", points=WEIGHTS["outcome_pair"], reason="References both success- and failure-related strings")
            group["signals"]["outcome_pair"] = signal

    for candidate in validation_candidates:
        ids = (candidate.id,)
        add(candidate.rva, "comparison", "comparison", "Contains a comparator call or comparison loop", ids, "compare")
        if candidate.branch_rva is not None:
            add(candidate.rva, "conditional_branch", "comparison", f"Comparison reaches branch RVA 0x{candidate.branch_rva:X}", ids)
        if candidate.loop:
            add(candidate.rva, "loop", "comparison", "Byte comparison loop has a back edge and iterator progress", ids)
        if candidate.length_check:
            add(candidate.rva, "length_check", "comparison", "Same function also checks a string length; same buffer unproven", ids)
        if candidate.success_branch and candidate.failure_branch:
            add(candidate.rva, "outcome_branch", "comparison", "Separate comparison successors reference success/failure text", ids, "validation")
        if any("PE structure" in evidence for evidence in candidate.evidence):
            add(candidate.rva, "pe_structure_penalty", "penalty", "PE structure context reduces CTF relevance", ids)
        if candidate.context_only:
            add(candidate.rva, "context_only", "penalty",
                "Comparison lacks enough independent context to be an actionable validation candidate", ids)
        if candidate.runtime_noise:
            add(candidate.rva, "runtime_noise", "penalty",
                "Compiler/CRT symbol context reduces challenge-validation relevance", ids)
        flow = getattr(candidate, "input_flow_to_validation", "NONE")
        if flow in {"CONFIRMED", "LIKELY", "POSSIBLE"}:
            rule = f"{flow.lower()}_input_flow"
            add(candidate.rva, rule, "dataflow", f"{flow.title()} user-input flow reaches this validation site", ids, "validation")

    for static_slice in static_slices:
        sink = static_slice.validation_sink or {}
        sink_rva = sink.get("rva")
        if sink_rva is not None:
            rule = f"{static_slice.confidence.lower()}_static_slice"
            add(int(sink_rva), rule, "dataflow",
                f"{static_slice.confidence.title()} bounded input-to-validation slice reaches this site",
                (static_slice.id,), "validation")
        for transform in static_slice.transforms:
            transform_rva = transform.get("instruction_rva")
            if transform_rva is not None:
                add(int(transform_rva), "flow_transform", "dataflow",
                    f"{transform.get('type', 'simple')} transform lies on an input-to-validation slice",
                    (static_slice.id,), "transform")
        if sink_rva is not None and static_slice.outcome_branch and static_slice.outcome_branch.get("return_value_controls_branch"):
            add(int(sink_rva), "return_controls_branch", "dataflow",
                "Source-reachable callee return reaches the validation outcome branch", (static_slice.id,), "validation")

    # A structural algorithm signal contributes only when independently linked to
    # the input-to-validation path. LOW and off-slice candidates are report-only.
    for candidate in algorithm_candidates:
        if candidate.confidence not in {"HIGH", "MEDIUM"} or candidate.slice_relation == "OFF_SLICE":
            continue
        add(candidate.function_rva, "on_slice_algorithm", "algorithm",
            f"{candidate.confidence.title()} {candidate.algorithm} candidate is {candidate.slice_relation.lower().replace('_', ' ')}",
            (candidate.id,), "crypto" if candidate.family == "CRYPTO" else "transform")

    for group in groups.values():
        signals = group["signals"]
        if "input_call" in signals and "comparison" in signals and not any(
                key.endswith("_input_flow") for key in signals):
            original = signals["comparison"]
            signals["unlinked_input_comparison"] = {
                "rule": "unlinked_input_comparison", "points": WEIGHTS["unlinked_input_comparison"],
                "source": "penalty", "reason": "Input and comparison share a function but bounded flow does not connect them",
                "evidence_ids": set(original["evidence_ids"]), "rvas": set(original["rvas"]),
            }

    if packed:
        for group in groups.values():
            if "packing" in group["signals"]:
                group["signals"]["packing"].update(
                    rule="strong_packing", points=WEIGHTS["strong_packing"], source="packing",
                    reason="Strong packing indicators make the entry stub the first static review target",
                )

    if context:
        for fn in context.functions:
            normalized = fn.name.casefold().lstrip("_")
            if normalized in {"main", "wmain", "winmain", "wwinmain", "dllmain"}:
                add(fn.rva, "program_entry", "entry",
                    f"Retained symbol identifies {fn.name} as a program-level entry controller",
                    (f"function-{fn.rva:08X}",), "control-flow")
            if fn.runtime_likelihood == "RUNTIME_LIKELY":
                add(fn.rva, "runtime_noise", "penalty",
                    f"Function classification is RUNTIME_LIKELY: {'; '.join(fn.runtime_evidence)}",
                    (f"function-{fn.rva:08X}",))
            elif fn.runtime_likelihood == "THUNK":
                add(fn.rva, "runtime_noise", "penalty",
                    "Forwarding thunk is not a validation body",
                    (f"function-{fn.rva:08X}",))
        # One-hop caller relevance only; no recursive score propagation or data-flow claim.
        relevant_functions = {key[1] for key, group in groups.items() if key[0] == "function"
                              and "comparison" in group["signals"]}
        for source, target in context.calls:
            fn = context.owner(source)
            if fn and fn.rva != target and target in relevant_functions:
                add(source, "call_relationship", "calls", f"Directly calls comparison candidate RVA 0x{target:X}; argument linkage unknown",
                    (f"call-{source:08X}",))

    targets = []
    for (_, location_rva), group in groups.items():
        fn = group["fn"]
        original = locations.get(location_rva)
        if image_base is None and original is None:
            continue
        signals = group["signals"]
        # Derived branch/loop/length signals all belong to the comparison source.
        sources = sorted({s["source"] for s in signals.values() if s["source"] not in {"penalty", "imports", "calls", "code"}})
        breakdown = []
        for key, signal in sorted(signals.items()):
            breakdown.append({**signal, "evidence_ids": sorted(signal["evidence_ids"]), "rvas": sorted(signal["rvas"])})
        bonus = 24 if len(sources) >= 4 else 18 if len(sources) == 3 else 8 if len(sources) == 2 else 0
        if bonus:
            breakdown.append({"rule": "corroboration", "points": bonus, "source": "corroboration",
                              "reason": "Independent evidence families: " + ", ".join(sources), "evidence_ids": [], "rvas": []})
        raw_score = sum(item["points"] for item in breakdown)
        cap = 100 if len(sources) >= 3 else 65 if len(sources) == 2 else 30
        if fn is None:
            cap = min(cap, 40)
        if not (set(sources) & {"strings", "input", "algorithm"}):
            cap = min(cap, 45)
        if "context_only" in signals:
            cap = min(cap, 20)
        if "runtime_noise" in signals:
            cap = min(cap, 8)
        cap_rule = "evidence_cap"
        cap_reason = f"Bounded by evidence independence and function attribution (cap {cap})"
        if packed and "packing" not in signals:
            cap = min(cap, 20)
            cap_rule = "packed_surface_cap"
            cap_reason = "Packed surface caps pre-unpack code claims"
        score = max(0, min(cap, raw_score))
        if score != raw_score:
            breakdown.append({"rule": cap_rule, "points": score - raw_score, "source": "cap",
                              "reason": cap_reason,
                              "evidence_ids": [], "rvas": []})
        if not score:
            continue
        if "comparison" in signals:
            target_type = "VALIDATION" if "context_only" not in signals and (
                "outcome_branch" in signals or any(key.endswith("_input_flow") for key in signals)
                or ("input_call" in signals and set(signals) & {"ctf_string", "outcome_pair"})) else "COMPARE"
        elif "input_call" in signals:
            target_type = "INPUT"
        elif "algorithm_constant" in signals or "on_slice_algorithm" in signals:
            is_data = context is not None and location_rva not in context.by_rva and any(
                "EXECUTE" not in section.get("flags", []) and section["virtual_address"] <= location_rva < section["virtual_address"] + section["raw_size"]
                for section in context.sections)
            target_type = "KEY_TABLE" if is_data else "CRYPTO" if "crypto" in group["categories"] else "TRANSFORM"
        elif "transform" in signals or "flow_transform" in signals:
            target_type = "TRANSFORM"
        elif "anti-debug" in group["categories"]:
            target_type = "ANTI_DEBUG"
        elif "packing" in signals:
            target_type = "PACKING"
        else:
            target_type = "SUSPICIOUS_FUNCTION"
        category = {"ANTI_DEBUG": "anti-debug", "KEY_TABLE": "key-table", "SUSPICIOUS_FUNCTION": "control-flow"}.get(target_type, target_type.lower())
        address = fn.address if fn else original.va if original and original.va is not None else image_base + location_rva
        file_offset = fn.file_offset if fn else original.file_offset if original else context.by_rva[location_rva][0].file_offset if context and location_rva in context.by_rva else None
        section = fn.section if fn else original.section if original else None
        target_kind = "function" if fn else "import" if set(signals) == {"import_only"} else "data" if target_type == "KEY_TABLE" else "code_location"
        actions = {
            "VALIDATION": "inspect the comparison arguments, cited strings and both branch successors",
            "COMPARE": "inspect both comparison operands and check whether the result controls user validation",
            "INPUT": "inspect the input API arguments and destination buffer references",
            "TRANSFORM": "inspect the byte transformations and their callers",
            "CRYPTO": "inspect the cited constants and surrounding operations before naming an algorithm",
            "KEY_TABLE": "inspect code references and establish the constant data's role",
            "ANTI_DEBUG": "inspect the API arguments and surrounding conditions",
            "PACKING": "inspect the entry code and cited section anomalies",
            "SUSPICIOUS_FUNCTION": "inspect the cited string references and local callers",
        }
        action = f"Open {fn.name if fn else f'RVA 0x{location_rva:X}'} in Ghidra/IDA; {actions[target_type]}."
        reason = "; ".join(item["reason"] for item in breakdown if item["points"] > 0)
        target_confidence = ("medium" if packed and target_type == "PACKING" else
                             "high" if fn and score >= 80 and len(sources) >= 3 else
                             "medium" if fn and len(sources) >= 2 else "low")
        targets.append(ReverseTarget(category, location_rva, address, file_offset, section,
            "high" if score >= 65 else "medium" if score >= 35 else "low", reason, action,
            tuple(sorted(group["ids"])), score,
            target_confidence,
            target_type, fn.name if fn else None, tuple(breakdown), tuple(sources), target_kind))
    targets.sort(key=lambda item: (-item.score, item.rva, item.target_type))
    # Keep legacy unresolved-transfer noise bounded without suppressing CTF string targets.
    selected = []
    unresolved_count = 0
    for target in targets:
        if {part["rule"] for part in target.score_breakdown} == {"unresolved_code"}:
            unresolved_count += 1
            if unresolved_count > 4:
                continue
        selected.append(target)
    return selected
