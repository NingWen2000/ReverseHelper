"""One actionable summary shared by terminal and offline report formats."""

import html


def target_label(target):
    return target.get("function") or {"data": "DAT_", "import": "IAT_"}.get(target.get("target_kind"), "SITE_") + f"{target['va']:X}"


def build_summary(result):
    basic = result["basic"]
    targets = result.get("reverse_targets", [])
    eligible = [target for target in targets if target.get("score", 0) >= 15]
    top = eligible[0] if eligible else None
    packing = result.get("packing", {}).get("verdict", "analysis-unavailable")
    packing_record = result.get("packing", {})
    limited_visibility = packing_record.get("static_visibility") == "limited"
    runner_up_score = eligible[1].get("score", 0) if len(eligible) > 1 else 0
    score_gap = top.get("score", 0) - runner_up_score if top else 0
    decisive_start = bool(top and (
        (limited_visibility and top.get("type") == "PACKING") or
        (top.get("confidence") in {"medium", "high"} and top.get("score", 0) >= 35 and score_gap >= 10) or
        (top.get("confidence") == "high" and top.get("score", 0) >= 65)
    ))
    start = top if decisive_start else None
    slices = result.get("static_slices", [])
    selected_slice = slices[0] if slices else None
    flow_breaks = result.get("static_flow_breaks", [])
    selected_break = flow_breaks[0] if flow_breaks else None
    input_record = (selected_slice["input_source"] if selected_slice else
                    selected_break["input_source"] if selected_break else
                    (result.get("input_sources") or [None])[0])
    static_path = []
    algorithms = [item for item in result.get("algorithm_candidates", [])
                  if item.get("confidence") == "HIGH" or (
                      item.get("confidence") == "MEDIUM" and item.get("slice_relation") != "OFF_SLICE")]
    algorithms_by_function = {}
    for item in algorithms:
        algorithms_by_function.setdefault(item.get("function_rva"), []).append(item)
    control_flow = [item for item in result.get("control_flow_findings", [])
                    if item.get("confidence") == "HIGH" or (
                        item.get("confidence") == "MEDIUM" and item.get("slice_relation") != "OFF_SLICE")]
    control_flow.sort(key=lambda item: (item.get("slice_relation") == "OFF_SLICE",
                       item.get("confidence") != "HIGH", item.get("function_rva", 0)))
    control_flow = control_flow[:5]
    semantic_suggestions = [item for item in result.get("decompiler_suggestions", [])
                            if item.get("confidence") == "HIGH"][:5]
    if selected_slice:
        static_path.append({"type": "INPUT", "label": selected_slice["input_source"]["source_type"]})
        for function_rva in selected_slice.get("nodes", []):
            if function_rva.get("type") == "FUNCTION" and function_rva.get("function_rva") is not None:
                node = {"type": "FUNCTION", "rva": function_rva["function_rva"],
                        "label": f"FUN_{basic['image_base'] + function_rva['function_rva']:X}"}
                if node not in static_path:
                    static_path.append(node)
                    for algorithm in algorithms_by_function.get(function_rva["function_rva"], []):
                        label = algorithm["algorithm"].replace("_", " ").title()
                        if algorithm["confidence"] != "HIGH":
                            label = "Possible " + label
                        static_path.append({"type": "ALGORITHM", "rva": function_rva["function_rva"],
                                            "label": label, "confidence": algorithm["confidence"]})
                    structure = next((item for item in control_flow
                                      if item.get("function_rva") == function_rva["function_rva"]), None)
                    if structure:
                        static_path.append({"type": "CONTROL_FLOW", "rva": structure.get("dispatcher_block") or structure["entry_block"],
                                            "label": structure["kind"].replace("_", " ").title(),
                                            "confidence": structure["confidence"]})
        for transform in selected_slice.get("transforms", []):
            static_path.append({"type": "TRANSFORM", "rva": transform.get("instruction_rva"),
                                "label": transform.get("type", "TRANSFORM"), "confidence": transform.get("confidence")})
        sink = selected_slice.get("validation_sink") or {}
        static_path.append({"type": "VALIDATION", "rva": sink.get("rva"),
                            "label": f"{sink.get('validation_type', 'validation')} @ RVA 0x{sink.get('rva', 0):X}"})
    elif selected_break:
        static_path.append({"type": "INPUT", "label": selected_break["input_source"]["source_type"]})
        if selected_break.get("function_rva") is not None:
            static_path.append({"type": "FUNCTION", "rva": selected_break["function_rva"],
                                "label": f"FUN_{basic['image_base'] + selected_break['function_rva']:X}"})
        static_path.append({"type": "FLOW_BREAK", "rva": selected_break["break_rva"],
                            "label": f"FLOW BREAK @ RVA 0x{selected_break['break_rva']:X}"})
        target = selected_break.get("next_unresolved_target") or {}
        if target.get("function_rva") is not None:
            static_path.append({"type": "UNRESOLVED_TARGET", "rva": target["function_rva"],
                                "label": f"FUN_{basic['image_base'] + target['function_rva']:X}"})

    start_reason = None
    flow_start_rva = None
    if selected_slice and selected_slice.get("status") in {"CONFIRMED_SLICE", "LIKELY_SLICE"}:
        first_transform = next((item for item in selected_slice.get("transforms", [])
                                if item.get("function_rva") is not None), None)
        flow_start_rva = first_transform.get("function_rva") if first_transform else None
        start_reason = "This is the first source-reachable function with a non-trivial transform on the static path."
    elif selected_break and selected_break.get("confidence") in {"CONFIRMED", "LIKELY"}:
        flow_start_rva = selected_break.get("function_rva")
        start_reason = "Input flow is proven up to this function and becomes unresolved at the reported flow break."
    flow_start = next((target for target in eligible if target.get("rva") == flow_start_rva), None)
    can_override_start = (
        start is None
        and selected_break is not None
        and (selected_break.get("next_unresolved_target") or {}).get("function_rva") is not None
        and len(selected_break.get("edges", [])) >= 3
    )
    if flow_start is not None and can_override_start:
        start = flow_start
        decisive_start = True
    elif not can_override_start:
        flow_start = None
    ranked_path = [{"step": i + 1, "label": target_label(target), "rva": target["rva"],
                    "reason": target["reason"], "action": target["recommended_action"]}
                   for i, target in enumerate(eligible[:5])]
    actionable_flow_nodes = [node for node in static_path if node["type"] != "INPUT"]
    flow_path = [{"step": i + 1, "label": node["label"], "rva": node.get("rva"),
                  "reason": (f"{node['type'].title()} on the {selected_slice['confidence'].lower()} input-to-validation slice"
                             if selected_slice else selected_break["reason"]),
                  "action": f"Inspect {node['label']} and follow the next source-reachable use."}
                 for i, node in enumerate(actionable_flow_nodes)]
    if limited_visibility:
        ranked_path = [
            {"step": index + 1, "label": "Post-unpack workflow", "rva": basic["entry_point_rva"],
             "reason": "Current strings and code belong to a packed/obfuscated surface.", "action": action}
            for index, action in enumerate(packing_record.get("recommended_steps", []))
        ]
    return {
        "binary": f"{'PE64' if basic.get('is_64_bit') else 'PE32'} / {basic['architecture']}",
        "packing": ("Packed / obfuscated binary detected; static visibility is limited"
                    if limited_visibility else {"no-obvious-indicators": "No strong packing evidence",
                    "analysis-unavailable": "Packing analysis unavailable"}.get(packing, packing)),
        "packing_guidance": packing_record.get("recommended_steps", []) if limited_visibility else [],
        "static_visibility": packing_record.get("static_visibility", "unknown"),
        "start_here": {"label": target_label(start), "rva": start["rva"], "score": start["score"],
                       "confidence": start["confidence"], "reason": start_reason if flow_start is not None else start["reason"],
                       "action": start["recommended_action"]} if start else None,
        "starting_points": [{"label": target_label(target), "rva": target["rva"], "score": target["score"],
                             "confidence": target["confidence"], "reason": target["reason"],
                             "action": target["recommended_action"]} for target in eligible[:3]] if not start else [],
        "start_selection": {"decisive": decisive_start, "top_score_gap": score_gap,
                            "reason": "bounded static flow selected the first transform or flow break" if flow_start is not None
                            else "single target has sufficient confidence and separation" if decisive_start
                            else "top target is low confidence or insufficiently separated"},
        "fallback": f"No supported critical-function candidate yet. Inspect entry RVA 0x{basic['entry_point_rva']:X} and retained string references in Ghidra/IDA.",
        "suggested_static_path": ranked_path if limited_visibility else flow_path[:5] if flow_path else ranked_path,
        "input_flow": {"source_type": input_record["source_type"], "destination": input_record["destination"],
                       "confidence": input_record["confidence"]} if input_record else None,
        "static_slice": {"id": selected_slice["id"], "confidence": selected_slice["confidence"],
                         "status": selected_slice.get("status", ""),
                         "label": ("Partial Input Flow" if selected_slice.get("status") == "PARTIAL_SLICE" else
                                   "Static Slice" if selected_slice["confidence"] == "CONFIRMED" else "Likely Static Path"),
                         "path": static_path, "warnings": selected_slice.get("warnings", [])} if selected_slice else None,
        "static_flow_break": {**selected_break, "path": static_path} if selected_break else None,
        "algorithms": algorithms,
        "control_flow": control_flow,
        "semantic_suggestions": semantic_suggestions,
        "notice": ("Scores rank review priority, not probability. Pre-unpack strings, validation and ranking have reduced reliability; re-run on an unpacked dump."
                   if limited_visibility else "Scores rank review priority, not probability. Static flow is bounded and path-insensitive; only unique simple indirect targets are propagated, and POSSIBLE segments are not asserted as facts."),
    }


def summary_lines(result, *, detailed=False):
    summary = result.get("challenge_summary") or build_summary(result)
    heading = "START HERE" if summary["start_here"] or not summary.get("starting_points") else "START WITH THESE"
    mode = result.get("analysis_mode", "quick").title()
    lines = [f"ReverseHelper {mode} Analysis", "Challenge Summary", "",
             f"Target: {result.get('basic', {}).get('file_name', 'unknown')}",
             f"Binary: {summary['binary']}", f"Packing: {summary['packing']}",
             f"Static visibility: {summary.get('static_visibility', 'unknown').upper()}", "", heading]
    start = summary["start_here"]
    if start:
        lines.extend([f"{start['label']}  |  {start['score']}/100  |  Confidence: {start['confidence'].upper()}",
                      f"Reason: {start['reason']}", f"Next: {start['action']}"])
    elif summary.get("starting_points"):
        lines.append("No single target has enough confidence and separation for a definitive START HERE.")
        for index, target in enumerate(summary["starting_points"], 1):
            lines.extend([f"{index}. {target['label']}  |  {target['score']}/100  |  Confidence: {target['confidence'].upper()}",
                          f"   Reason: {target['reason']}"])
    else:
        lines.append(summary["fallback"])
    if summary.get("packing_guidance"):
        lines += ["", "Post-Unpack Guidance"]
        lines.extend(f"{index + 1}. {step}" for index, step in enumerate(summary["packing_guidance"]))
    lines += ["", "Input Flow"]
    input_flow = summary.get("input_flow")
    if input_flow:
        destination = input_flow["destination"]
        if destination.get("kind") == "STACK":
            rendered = f"stack[{destination.get('offset', 0):+#x}]"
        elif destination.get("kind") == "REGISTER":
            rendered = destination.get("name", "register").upper()
        else:
            rendered = destination.get("kind", "unknown")
        lines.append(f"{input_flow['source_type']} -> {rendered}  ({input_flow['confidence']})")
    else:
        lines.append("No supported input destination was recovered.")
    static = summary.get("static_slice")
    flow_break = summary.get("static_flow_break")
    lines += ["", static["label"] if static else "Possible Static Path"]
    if static:
        separator = " -> " if static["confidence"] == "CONFIRMED" else " -?-> "
        lines.append(separator.join(node["label"] for node in static["path"]))
        lines.extend(f"Warning: {warning}" for warning in static.get("warnings", []))
    else:
        lines.append("No input-to-validation slice was established within the Quick budgets.")
    if flow_break:
        lines += ["", "FLOW BREAK", flow_break["reason"]]
        target = flow_break.get("next_unresolved_target") or {}
        if target.get("function_rva") is not None:
            lines.append(f"Next unresolved target: FUN_{result['basic']['image_base'] + target['function_rva']:X} via call RVA 0x{target['callsite_rva']:X}")
        lines.extend(f"Evidence: {item}" for item in flow_break.get("evidence", []))
    direct_validation = next((item for item in result.get("validation_candidates", [])
                              if not item.get("context_only") and item.get("confidence") in {"high", "medium"}), None)
    if direct_validation:
        lines += ["", "Likely Validation",
                  f"{direct_validation.get('function') or 'site'} @ RVA 0x{direct_validation['rva']:X}  "
                  f"{direct_validation['validation_type']}  {direct_validation['confidence'].upper()}"]
    lines += ["", "Semantic Suggestions"]
    for item in summary.get("semantic_suggestions", []):
        target = item.get("target", {})
        label = target.get("current_name") or (f"RVA 0x{target['rva']:X}" if target.get("rva") is not None else target.get("kind", "object"))
        proposed = item.get("proposed_value")
        if isinstance(proposed, dict):
            proposed = proposed.get("name") or proposed.get("role") or proposed.get("status")
        lines.append(f"{label} -> {proposed}  {item['confidence']}")
    if not summary.get("semantic_suggestions"):
        lines.append("No high-confidence semantic suggestion.")
    lines += ["", "Control Flow"]
    for item in summary.get("control_flow", []):
        relation = item.get("slice_relation", "OFF_SLICE").replace("_", " ").title()
        lines.append(f"{item['confidence']}  {item['kind'].replace('_', ' ').title()}  {item['function']}  ({relation})")
        if item.get("dispatcher_block") is not None:
            lines.append(f"  Dispatcher: RVA 0x{item['dispatcher_block']:X}")
        lines.append(f"  Suggested: {item['suggested_action']}")
    if not summary.get("control_flow"):
        lines.append("No high or strong on-slice control-flow structure.")
    lines += ["", "Algorithms"]
    for item in summary.get("algorithms", []):
        relation = item.get("slice_relation", "OFF_SLICE").replace("_", " ").title()
        lines.append(f"{item['confidence']}  {item['algorithm']}  {item['function']}  ({relation})")
        if detailed:
            lines.extend(f"  {evidence['kind']}: {evidence['value']}" for evidence in item.get("evidence", []))
    if not summary.get("algorithms"):
        lines.append("No high or strong on-slice algorithm candidate.")
    lines += ["", "Interesting Strings"]
    function_scores = {target.get("function"): target.get("score", 0) for target in result.get("reverse_targets", []) if target.get("function")}
    strings = [s for s in result.get("interesting_strings", []) if s["category"] != "GENERIC"]
    strings.sort(key=lambda s: (-max((function_scores.get(fn, 0) for fn in s["xref_functions"]), default=0), -s["score"], s["id"]))
    for item in strings[:20 if detailed else 6]:
        functions = ", ".join(item["xref_functions"]) or "function unknown"
        lines.append(f"{item['priority']} {item['category']} {item['value'][:160]!r}  -> {functions} ({item['xref_count']} XREFs)")
        if detailed:
            lines.extend([f"  {item['id']} / RVA {item['rva']} / {item['encoding']}", "  Reasons: " + "; ".join(item["reasons"])])
    if not strings:
        lines.append("No classified strings available; check warnings and scan coverage.")
    elif len(strings) > (20 if detailed else 6):
        lines.append(f"Showing {20 if detailed else 6} of {len(strings)} classified strings; JSON retains all available records.")
    lines += ["", "Validation Candidates"]
    candidates = sorted((item for item in result.get("validation_candidates", [])
                         if not item.get("context_only") and item.get("confidence") in {"high", "medium"}),
                        key=lambda item: (-function_scores.get(item.get("function"), 0), item["rva"]))
    for item in candidates[:20 if detailed else 5]:
        label = item.get("function") or f"SITE_{item['address']:X}"
        status = "context only" if item.get("context_only") else "candidate"
        lines.append(f"{label} @ RVA 0x{item['rva']:X}  {item['validation_type']}  {item['confidence'].upper()} ({status})")
        if detailed:
            lines.extend(["  " + text for text in item["evidence"]])
            for field in ("input_flow_to_validation", "input_source", "compare_target", "compare_length", "success_branch", "failure_branch"):
                lines.append(f"  {field}: {item.get(field) if item.get(field) is not None else 'unknown'}")
    if not candidates:
        compare_count = len(result.get("compare_sites", []))
        lines.append(f"No actionable validation candidate; {compare_count} comparison observations remain in JSON for review.")
    elif len(candidates) > (20 if detailed else 5):
        lines.append(f"Showing {20 if detailed else 5} of {len(candidates)} validation candidates; JSON retains all available records.")
    lines += ["", "Top Reverse Targets"]
    for i, target in enumerate(result.get("reverse_targets", [])[:20 if detailed else 5]):
        lines.append(f"#{i + 1} {target['score']:3}/100  {target_label(target)}  {target['type']}  {target['confidence'].upper()}")
        if detailed:
            lines.extend(f"  {part['points']:+}: {part['reason']}" for part in target["score_breakdown"])
            lines.append("  Evidence: " + ", ".join(target["finding_ids"]))
    if not result.get("reverse_targets"):
        lines.append("No ranked targets available.")
    lines += ["", "Suggested Static Path"]
    for step in summary["suggested_static_path"][:3]:
        lines.append(f"{step['step']}. {step['action']}")
    lines += ["", summary["notice"]]
    if result.get("analysis_warnings"):
        lines += ["", "Analysis Warnings"]
        lines.extend(f"{w['module']}: {w['reason']}" for w in result["analysis_warnings"])
    truncated = result.get("truncated_modules", [])
    if truncated:
        lines += ["", "Coverage", "Truncated: " + ", ".join(truncated)]
        if result.get("analysis_mode") == "quick":
            lines.append("Run again with --deep when broader static coverage is worth the extra time.")
    return lines


def markdown_summary(result):
    # Escape arbitrary sample content, including HTML/backticks and table delimiters.
    def escape(line):
        return html.escape(line).replace("\\", "\\\\").replace("`", "\\`").replace("*", "\\*").replace("_", "\\_").replace("|", "\\|").replace("[", "\\[")
    lines = summary_lines(result, detailed=True)
    headings = {"Challenge Summary", "START HERE", "START WITH THESE", "Post-Unpack Guidance", "Input Flow", "Static Slice", "Likely Static Path", "Partial Input Flow", "Possible Static Path", "FLOW BREAK", "Likely Validation", "Semantic Suggestions", "Control Flow", "Algorithms", "Interesting Strings", "Validation Candidates", "Top Reverse Targets", "Suggested Static Path", "Analysis Warnings", "Coverage"}
    return "\n\n".join("# " + line if i == 0 else "## " + line if line in headings else escape(line)
                       for i, line in enumerate(lines) if line) + "\n"


def html_summary(result):
    lines = summary_lines(result, detailed=True)
    headings = {"Challenge Summary", "START HERE", "START WITH THESE", "Post-Unpack Guidance", "Input Flow", "Static Slice", "Likely Static Path", "Partial Input Flow", "Possible Static Path", "FLOW BREAK", "Likely Validation", "Semantic Suggestions", "Control Flow", "Algorithms", "Interesting Strings", "Validation Candidates", "Top Reverse Targets", "Suggested Static Path", "Analysis Warnings", "Coverage"}
    body = []
    for i, line in enumerate(lines):
        tag = "h1" if i == 0 else "h2" if line in headings else "p"
        body.append(f"<{tag}>{html.escape(line)}</{tag}>")
    return '<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ReverseHelper Challenge Summary</title><style>body{max-width:1000px;margin:40px auto;padding:0 24px;font:16px/1.6 system-ui;background:#101723;color:#e4edf7}h1,h2{color:#79d4ff}p{white-space:pre-wrap;overflow-wrap:anywhere}h2{margin-top:32px}</style><body>' + "\n".join(body) + "</body></html>"
