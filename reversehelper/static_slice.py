"""Build explainable input-to-validation slices from bounded flow traces."""

from __future__ import annotations

from dataclasses import replace

from .dataflow_model import StaticFlowBreak, StaticSlice


_CONFIDENCE_ORDER = {"POSSIBLE": 0, "LIKELY": 1, "CONFIRMED": 2}


def _candidate_flow(trace, candidate):
    matches = [binding for binding in trace.call_arguments if binding["callsite_rva"] == candidate.rva]
    if matches:
        return max((binding["confidence"] for binding in matches), key=_CONFIDENCE_ORDER.get)
    matches = [comparison for comparison in trace.comparisons
               if comparison["instruction_rva"] == candidate.rva and comparison["input_flow"] != "NONE"]
    if matches:
        return max((comparison["input_flow"] for comparison in matches), key=_CONFIDENCE_ORDER.get)
    direct_argument = any(binding.get("callee_rva") == candidate.function_rva
                          for binding in trace.call_arguments)
    if direct_argument:
        transformed = any(transform.get("function_rva") == candidate.function_rva
                          for transform in trace.transforms)
        return "LIKELY" if transformed else "POSSIBLE"
    return "NONE"


def _node_type(location):
    return {
        "STACK": "LOCAL", "ARGUMENT": "ARGUMENT", "GLOBAL": "GLOBAL_DATA",
        "RETURN_VALUE": "FUNCTION", "UNKNOWN": "COMPARE",
    }.get(location.get("kind"), "LOCAL")


def _nodes(trace, candidate):
    nodes = []
    seen = set()
    for edge in sorted(trace.edges, key=lambda item: (item.instruction_rva, item.edge_type)):
        for location in (edge.source.to_dict(), edge.destination.to_dict()):
            key = repr(sorted(location.items()))
            if key in seen:
                continue
            seen.add(key)
            nodes.append({"type": _node_type(location), "location": location})
    for function_rva in trace.functions_visited:
        key = f"function:{function_rva}"
        if key not in seen:
            seen.add(key)
            nodes.append({"type": "FUNCTION", "function_rva": function_rva})
    nodes.append({"type": "VALIDATION", "function_rva": candidate.function_rva,
                  "instruction_rva": candidate.rva, "validation_type": candidate.validation_type})
    if candidate.success_branch:
        nodes.append({"type": "SUCCESS_BRANCH", **candidate.success_branch})
    if candidate.failure_branch:
        nodes.append({"type": "FAILURE_BRANCH", **candidate.failure_branch})
    return tuple(nodes)


def build_static_slices(input_sources, flow_result, validation_candidates):
    sources = {source.id: source for source in input_sources}
    slices = []
    strongest = {candidate.id: "NONE" for candidate in validation_candidates}
    for trace in flow_result.traces:
        source = sources.get(trace.input_source_id)
        if source is None:
            continue
        for candidate in validation_candidates:
            flow = _candidate_flow(trace, candidate)
            if flow == "NONE":
                continue
            if _CONFIDENCE_ORDER[flow] > _CONFIDENCE_ORDER.get(strongest[candidate.id], -1):
                strongest[candidate.id] = flow
            relevant_edges = tuple(sorted(trace.edges, key=lambda edge: (edge.instruction_rva, edge.edge_type)))
            confidence = flow
            if confidence == "CONFIRMED" and any(
                edge.edge_type == "RETURN" and edge.confidence != "CONFIRMED"
                for edge in relevant_edges
            ):
                confidence = "LIKELY"
            outcome = None
            if candidate.branch_rva is not None:
                outcome = {"branch_rva": candidate.branch_rva, "success": candidate.success_branch,
                           "failure": candidate.failure_branch,
                           "return_value_controls_branch": any(edge.edge_type == "RETURN" for edge in relevant_edges)}
            warning_items = list(trace.warnings)
            if trace.incomplete:
                warning_items.append("Static slice incomplete: analysis budget reached")
            status = ("PARTIAL_SLICE" if trace.incomplete or confidence == "POSSIBLE" else
                      "CONFIRMED_SLICE" if confidence == "CONFIRMED" else "LIKELY_SLICE")
            slices.append(StaticSlice(
                f"slice-{source.id}-{candidate.id}", source, _nodes(trace, candidate), relevant_edges,
                tuple(trace.transforms), candidate.to_dict(), outcome, confidence,
                tuple(dict.fromkeys(warning_items)), status,
            ))
    enriched = [replace(candidate, input_flow_to_validation=strongest[candidate.id],
                        context_only=(candidate.context_only and not (
                            strongest[candidate.id] in {"CONFIRMED", "LIKELY"}
                            and (candidate.branch_rva is not None or candidate.decision_type is not None))))
                for candidate in validation_candidates]
    slices.sort(key=lambda item: (-_CONFIDENCE_ORDER[item.confidence], item.validation_sink["rva"], item.id))
    return slices, enriched


def build_static_flow_breaks(input_sources, flow_result, context, slices):
    """Publish real source-reachable subchains whose next static edge is unproven."""
    sources = {source.id: source for source in input_sources}
    sliced_sources = {item.input_source.id for item in slices}
    breaks = []
    for trace in flow_result.traces:
        source = sources.get(trace.input_source_id)
        if source is None or source.id in sliced_sources or not trace.edges:
            continue
        # Newly recovered external-boundary sources are useful seeds, but an
        # unresolved continuation alone is not enough to publish an actionable
        # path for them. Wait until a real validation candidate closes the slice.
        if source.source_type.startswith("argv[") or source.source_type == "EXPORTED_ARGUMENT":
            continue
        real_edges = tuple(sorted(trace.edges, key=lambda edge: (edge.instruction_rva, edge.edge_type)))
        if len(real_edges) < 2:
            continue
        unresolved_calls = [item for item in trace.call_arguments if item.get("callee_rva") is None]
        next_target = None
        reason = None
        break_rva = real_edges[-1].instruction_rva
        function = context.owner(break_rva)
        if unresolved_calls:
            call = max(unresolved_calls, key=lambda item: int(item["callsite_rva"]))
            break_rva = int(call["callsite_rva"])
            function = context.owner(break_rva)
            reason = "indirect call target is ambiguous; propagation stops at the proven call argument"
            next_target = {"callsite_rva": break_rva, "function_rva": None, "kind": "INDIRECT_CALL"}
        elif (real_edges[-1].edge_type in {"STORE", "TRANSFORM", "RETURN"}
              and any(edge.edge_type == "TRANSFORM" for edge in real_edges)
              and len(real_edges) >= 3 and function is not None):
            linked_calls = {int(item["callsite_rva"]) for item in trace.call_arguments}
            following = sorted(
                (callsite, target) for callsite, target in context.calls
                if context.owner(callsite) is function and break_rva < callsite <= break_rva + 96
                and callsite not in linked_calls
            )
            if following:
                callsite, target = following[0]
                next_target = {"callsite_rva": callsite, "function_rva": target, "kind": "DIRECT_CALL"}
                reason = "source-reachable value is proven through the last transform/store, but alias recovery into the following call is unresolved"
        if reason is None and trace.incomplete:
            reason = next((warning for warning in trace.warnings if "budget" in warning.casefold()),
                          "bounded flow analysis ended before a validation sink")
        if reason is None:
            continue
        last = max((edge for edge in real_edges if edge.instruction_rva <= break_rva),
                   key=lambda edge: edge.instruction_rva, default=real_edges[-1])
        confidence = "LIKELY" if all(edge.confidence != "POSSIBLE" for edge in real_edges) else "POSSIBLE"
        breaks.append(StaticFlowBreak(
            f"flow-break-{source.id}-{break_rva:08X}", source,
            function.rva if function else None, break_rva, last.destination.to_dict(),
            next_target, reason,
            (f"{len(real_edges)} source-reachable edges recovered",
             f"last proven edge is {last.edge_type} at RVA 0x{last.instruction_rva:X}"),
            confidence, real_edges,
        ))
    breaks.sort(key=lambda item: ({"CONFIRMED": 0, "LIKELY": 1, "POSSIBLE": 2}[item.confidence], item.break_rva))
    return breaks
