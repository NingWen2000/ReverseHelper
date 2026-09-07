"""Tool-independent high-value annotation export."""


def build_annotations(result):
    annotations = []
    seen = set()

    def add(rva, category, title, comment, confidence="medium", evidence=()):
        if rva is None:
            return
        key = (int(rva), category, title)
        if key in seen:
            return
        seen.add(key)
        annotations.append({"rva": int(rva), "category": category, "title": title,
                            "comment": comment, "confidence": confidence,
                            "evidence": list(evidence), "fact_status": "candidate"})

    summary = result.get("challenge_summary") or {}
    start = summary.get("start_here")
    if start:
        add(start.get("rva"), "RH:START", "START HERE",
            "START HERE\nReason: %s\nSuggested next: %s" % (start.get("reason", ""), start.get("action", "")),
            start.get("confidence", "medium"), (start.get("reason", ""),))
    for source in result.get("input_sources", [])[:8]:
        add(source.get("callsite_rva") if source.get("callsite_rva") is not None else source.get("function_rva"),
            "RH:INPUT", source.get("source_type", "Input source"),
            "Input source candidate: %s" % source.get("source_type", "unknown"),
            str(source.get("confidence", "possible")).lower(), source.get("evidence", []))
    for item in result.get("validation_candidates", [])[:8]:
        if item.get("context_only"):
            continue
        add(item.get("rva"), "RH:VALIDATION", item.get("validation_type", "Validation candidate"),
            "Validation candidate. Review operands and both branch outcomes.",
            str(item.get("confidence", "possible")).lower(), item.get("evidence", []))
    for item in result.get("static_slices", [])[:3]:
        transform = next(iter(item.get("transforms", [])), None)
        if transform:
            add(transform.get("instruction_rva"), "RH:SLICE", "Input-reachable transform",
                "This transform lies on a bounded static input path.",
                str(transform.get("confidence", item.get("confidence", "possible"))).lower(),
                transform.get("evidence", []))
    static = summary.get("static_slice") or {}
    path = static.get("path", [])
    for node in path:
        category = {"INPUT": "RH:INPUT", "VALIDATION": "RH:VALIDATION",
                    "ALGORITHM": "RH:ALGORITHM", "CONTROL_FLOW": "RH:CONTROL_FLOW"}.get(node.get("type"))
        if category:
            add(node.get("rva"), category, node.get("label", node.get("type", "Slice")),
                "Static path: %s" % node.get("label", ""), node.get("confidence", "medium"))
    for item in result.get("static_flow_breaks", [])[:3]:
        add(item.get("break_rva"), "RH:FLOW_BREAK", "Static tracking lost here",
            "Static tracking lost here.\nReason: %s\nSuggestion: inspect the unresolved transfer/value manually." % item.get("reason", ""),
            str(item.get("confidence", "POSSIBLE")).lower(), item.get("evidence", []))
    for item in result.get("algorithm_candidates", []):
        if item.get("confidence") not in {"HIGH", "MEDIUM"}:
            continue
        add(item.get("function_rva"), "RH:ALGORITHM", item.get("algorithm", "Algorithm candidate"),
            "%s candidate (%s). Review constants, widths and data objects manually." %
            (item.get("algorithm"), item.get("confidence")), item.get("confidence", "MEDIUM").lower(),
            ["%s: %s" % (e.get("kind"), e.get("value")) for e in item.get("evidence", [])])
    for item in result.get("control_flow_findings", []):
        if item.get("confidence") == "LOW":
            continue
        rva = item.get("dispatcher_block") or item.get("entry_block")
        category = "RH:" + ("DISPATCHER" if item.get("dispatcher_block") is not None else item.get("kind", "CONTROL_FLOW"))
        add(rva, category, item.get("kind", "Control Flow").replace("_", " ").title(),
            "%s\nSuggested: %s" % (item.get("kind", ""), item.get("suggested_action", "")),
            item.get("confidence", "MEDIUM").lower(),
            ["%s: %s" % (e.get("kind"), e.get("value")) for e in item.get("evidence", [])])
    for item in result.get("decompiler_suggestions", []):
        if item.get("confidence") == "LOW":
            continue
        target = item.get("target", {})
        add(target.get("rva") if target.get("rva") is not None else target.get("function_rva"),
            "RH:SUGGEST_" + item.get("kind", "SEMANTIC"), "Semantic suggestion",
            "Suggested semantic: %s\nReview before applying; no rename is automatic." % item.get("proposed_value"),
            item.get("confidence", "MEDIUM").lower(),
            ["%s: %s" % (e.get("kind"), e.get("value")) for e in item.get("evidence", [])])
    annotations.sort(key=lambda item: (item["rva"], item["category"], item["title"]))
    return annotations
