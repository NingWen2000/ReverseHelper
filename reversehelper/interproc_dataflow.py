"""Budgeted direct-call propagation for source-focused Quick analysis."""

from __future__ import annotations

import json

from .dataflow_model import (
    ArgumentFlowSummary, ArgumentLocation, DataFlowEdge, FunctionFlowSummary, GlobalLocation, InputSource,
    InterproceduralFlowResult, InterproceduralTrace, RegisterLocation, ReturnSummary, ReturnValueLocation,
    UnknownLocation,
)
from .intra_dataflow import analyze_intra_function
from .input_sources import recover_call_argument
from .value_identity import ValueIdentity, identity_for_source
from capstone.x86 import X86_OP_MEM, X86_REG_INVALID, X86_REG_RIP


def _reads_global(context, function_rva, target):
    for _, decoded in context.function_records.get(function_rva, ()):
        for operand in decoded.operands:
            if operand.type != X86_OP_MEM:
                continue
            if operand.mem.base == X86_REG_RIP:
                address = int(decoded.address + decoded.size + operand.mem.disp)
            elif operand.mem.base == X86_REG_INVALID:
                address = int(operand.mem.disp)
            elif int(operand.mem.disp) >= context.image_base:
                # x86 absolute indexed form such as [eax+0x403078].
                address = int(operand.mem.disp)
            else:
                continue
            if address == target.address:
                return True
    return False


def _unique_dicts(items):
    result = {}
    for item in items:
        result[json.dumps(item, sort_keys=True)] = item
    return list(result.values())


def _unique_edges(items):
    result = {}
    for edge in items:
        result[json.dumps(edge.to_dict(), sort_keys=True)] = edge
    return list(result.values())


def propagate_input_flows(context, input_sources, architecture: str, *, max_call_depth=3,
                          max_functions=48, max_edges=8000, max_instructions=24000, max_sources=32,
                          max_values=256, max_aliases=1024, max_versions=64, max_flow_states=512,
                          max_summary_edges=128):
    """Propagate each input independently through bounded, direct calls and returns."""
    traces = []
    global_warnings = []
    total_edges = 0
    summary_cache = {}
    known_functions = {function.rva: function for function in context.functions}
    selected_sources = list(input_sources)[:max_sources]
    if len(input_sources) > max_sources:
        global_warnings.append(f"Input-source budget retained {max_sources} of {len(input_sources)} sources")
    for root in selected_sources:
        if root.function_rva is None:
            continue
        root_identity = root.value_identity or identity_for_source(root)
        seeds = [root] if root.value_identity else [InputSource(
            root.id, root.function, root.function_rva, root.callsite, root.callsite_rva,
            root.source_type, root.destination, root.size_hint, root.confidence, root.evidence,
            root_identity,
        )]
        # An input API may write through a helper argument. Map that side effect
        # back to direct callers without attempting general alias analysis.
        if isinstance(root.destination, ArgumentLocation):
            for callsite_rva, target_rva in context.calls:
                if target_rva != root.function_rva:
                    continue
                caller = context.owner(callsite_rva)
                if caller is None:
                    continue
                caller_location = recover_call_argument(
                    context, callsite_rva, root.destination.index, architecture,
                )
                if isinstance(caller_location, UnknownLocation):
                    continue
                seeds.append(InputSource(
                    f"{root.id}:caller-sideeffect:{callsite_rva:X}", caller.name, caller.rva,
                    context.image_base + callsite_rva, callsite_rva, root.source_type,
                    caller_location, root.size_hint, "LIKELY",
                    (f"direct callee RVA 0x{root.function_rva:X} writes argument {root.destination.index}",),
                    root_identity,
                ))
        seed_ids = {seed.id for seed in seeds}
        depths = {seed.function_rva: 0 for seed in seeds if seed.function_rva is not None}
        root_callers = {
            owner.rva
            for callsite_rva, target_rva in context.calls
            if target_rva == root.function_rva and (owner := context.owner(callsite_rva)) is not None
        }
        sibling_targets = {
            target_rva
            for callsite_rva, target_rva in context.calls
            if (owner := context.owner(callsite_rva)) is not None and owner.rva in root_callers
        }
        collected_edges = []
        collected_calls = []
        collected_comparisons = []
        collected_transforms = []
        collected_returns = []
        collected_mutations = []
        collected_outputs = []
        warnings = []
        incomplete = False

        for _ in range(max_call_depth + 2):
            remaining_edges = max_edges - total_edges - len(collected_edges)
            if remaining_edges <= 0:
                warnings.append("Interprocedural edge budget reached")
                incomplete = True
                break
            flow = analyze_intra_function(context, seeds, architecture,
                                          max_instructions=max_instructions, max_edges=remaining_edges,
                                          max_values=max_values, max_aliases=max_aliases,
                                          max_versions=max_versions, max_flow_states=max_flow_states)
            collected_edges = _unique_edges([*collected_edges, *flow.edges])
            collected_calls = _unique_dicts([*collected_calls, *flow.call_arguments])
            collected_comparisons = _unique_dicts([*collected_comparisons, *flow.comparisons])
            collected_transforms = _unique_dicts([*collected_transforms, *flow.transforms])
            collected_returns = _unique_dicts([*collected_returns, *flow.returns])
            collected_mutations = _unique_dicts([*collected_mutations, *flow.mutations])
            collected_outputs = _unique_dicts([*collected_outputs, *flow.output_parameters])
            warnings.extend(flow.warnings)
            incomplete |= flow.incomplete
            new_seeds = []

            for binding in flow.call_arguments:
                caller = int(binding["caller_function_rva"])
                if binding.get("callee_rva") is None:
                    continue
                callee = int(binding["callee_rva"])
                depth = depths.get(caller, max_call_depth) + 1
                if callee not in known_functions:
                    warnings.append(f"Direct call target RVA 0x{callee:X} has no bounded function model")
                    continue
                if depth > max_call_depth:
                    warnings.append(f"BUDGET_LIMIT: Call-depth budget stopped propagation into RVA 0x{callee:X}")
                    incomplete = True
                    continue
                if callee not in depths and len(depths) >= max_functions:
                    warnings.append("Interprocedural function budget reached")
                    incomplete = True
                    continue
                depths[callee] = min(depths.get(callee, depth), depth)
                seed_id = f"{root.id}:arg:{binding['callsite_rva']:X}:{binding['argument_index']}"
                if seed_id in seed_ids:
                    continue
                function = known_functions[callee]
                new_seeds.append(InputSource(
                    seed_id, function.name, callee, function.address, callee, root.source_type,
                    ArgumentLocation(callee, int(binding["argument_index"])), root.size_hint,
                    binding["confidence"],
                    (f"propagated from direct call RVA 0x{binding['callsite_rva']:X}",),
                    ValueIdentity.from_dict(binding["value_identity"]),
                ))
                seed_ids.add(seed_id)

            return_by_function = {}
            for returned in flow.returns:
                return_by_function.setdefault(int(returned["function_rva"]), []).append(returned)
            for binding in flow.call_arguments:
                if binding.get("callee_rva") is None:
                    continue
                callee = int(binding["callee_rva"])
                caller = int(binding["caller_function_rva"])
                binding_identity = ValueIdentity.from_dict(binding["value_identity"])
                for returned in return_by_function.get(callee, []):
                    returned_identity = ValueIdentity.from_dict(returned["value_identity"])
                    if returned_identity.id != binding_identity.id:
                        continue
                    if any("indirect-call scalar result" in item for item in returned_identity.provenance):
                        return_kind = "RETURNS_SCALAR_RESULT"
                    elif returned_identity.offset != binding_identity.offset:
                        return_kind = "RETURNS_DERIVED_ARGUMENT"
                    else:
                        return_kind = "RETURNS_ARGUMENT"
                    cache_key = (callee, "return", int(binding["argument_index"]), return_kind,
                                 returned_identity.offset - binding_identity.offset)
                    if len(summary_cache) < max_summary_edges:
                        summary_cache.setdefault(cache_key, ReturnSummary(
                            return_kind, int(binding["argument_index"]),
                            returned_identity.offset - binding_identity.offset,
                            "LIKELY" if return_kind == "RETURNS_SCALAR_RESULT" else returned["confidence"],
                            (f"source-reachable argument {binding['argument_index']} reaches return at RVA 0x{returned['instruction_rva']:X}",),
                        ))
                    seed_id = f"{root.id}:return:{binding['callsite_rva']:X}"
                    if seed_id in seed_ids:
                        continue
                    call_record = context.by_rva.get(int(binding["callsite_rva"]))
                    if call_record is None:
                        continue
                    instruction = call_record[0]
                    destination = ReturnValueLocation(caller, instruction.rva, "a")
                    source_location = next((edge.destination for edge in flow.edges
                                            if edge.destination.to_dict() == returned["source"]),
                                           ArgumentLocation(callee, int(binding["argument_index"])))
                    collected_edges.append(DataFlowEdge(
                        source_location, destination, instruction.address, instruction.rva,
                        "RETURN", "LIKELY", f"source-reachable return from direct callee RVA 0x{callee:X}",
                        returned_identity,
                    ))
                    caller_function = known_functions.get(caller)
                    new_seeds.append(InputSource(
                        seed_id, caller_function.name if caller_function else None, caller,
                        instruction.address, instruction.rva, root.source_type, destination,
                        root.size_hint, "LIKELY", (f"return from RVA 0x{callee:X}",),
                        returned_identity,
                    ))
                    seed_ids.add(seed_id)

                caller_location = next((
                    edge.source for edge in flow.edges
                    if edge.edge_type == "ARGUMENT"
                    and edge.instruction_rva == int(binding["callsite_rva"])
                    and edge.destination == ArgumentLocation(callee, int(binding["argument_index"]))
                ), None)
                if (architecture == "x86-64" and isinstance(caller_location, ArgumentLocation)
                        and int(binding["argument_index"]) < 4):
                    caller_location = RegisterLocation(
                        ("c", "d", "r8", "r9")[int(binding["argument_index"])],
                        caller, int(binding["callsite_rva"]),
                    )
                for mutation in collected_mutations:
                    if (int(mutation["function_rva"]) != callee
                            or int(mutation["argument_index"]) != int(binding["argument_index"])):
                        continue
                    mutated_identity = ValueIdentity.from_dict(mutation["value_identity"])
                    if mutated_identity.id != binding_identity.id:
                        continue
                    cache_key = (callee, "mutate", int(binding["argument_index"]))
                    if len(summary_cache) < max_summary_edges:
                        summary_cache.setdefault(cache_key, ("mutation", int(binding["argument_index"]),
                                                              mutation["confidence"], mutation["instruction_rva"]))
                    seed_id = f"{root.id}:mutation:{binding['callsite_rva']:X}:{binding['argument_index']}"
                    if seed_id in seed_ids or caller_location is None:
                        continue
                    caller_function = known_functions.get(caller)
                    new_seeds.append(InputSource(
                        seed_id, caller_function.name if caller_function else None, caller,
                        context.image_base + int(binding["callsite_rva"]), int(binding["callsite_rva"]),
                        root.source_type, caller_location, root.size_hint, "LIKELY",
                        (f"callee RVA 0x{callee:X} mutates argument {binding['argument_index']}",),
                        mutated_identity,
                    ))
                    seed_ids.add(seed_id)

                for output in collected_outputs:
                    if (int(output["function_rva"]) != callee
                            or int(output["source_argument"]) != int(binding["argument_index"])):
                        continue
                    destination_index = int(output["destination_argument"])
                    output_location = recover_call_argument(
                        context, int(binding["callsite_rva"]), destination_index, architecture,
                    )
                    if isinstance(output_location, UnknownLocation):
                        continue
                    output_identity = ValueIdentity.from_dict(output["value_identity"])
                    if output_identity.id != binding_identity.id:
                        continue
                    cache_key = (callee, "output", int(binding["argument_index"]), destination_index)
                    if len(summary_cache) < max_summary_edges:
                        summary_cache.setdefault(cache_key, ArgumentFlowSummary(
                            "ARGUMENT_TO_OUTPUT", int(binding["argument_index"]), destination_index,
                            output["confidence"],
                            (f"direct store at RVA 0x{output['instruction_rva']:X}",),
                        ))
                    seed_id = f"{root.id}:output:{binding['callsite_rva']:X}:{destination_index}"
                    if seed_id in seed_ids:
                        continue
                    caller_function = known_functions.get(caller)
                    new_seeds.append(InputSource(
                        seed_id, caller_function.name if caller_function else None, caller,
                        context.image_base + int(binding["callsite_rva"]), int(binding["callsite_rva"]),
                        root.source_type, output_location, root.size_hint, "LIKELY",
                        (f"callee RVA 0x{callee:X} derives output argument {destination_index} from argument {binding['argument_index']}",),
                        output_identity,
                    ))
                    seed_ids.add(seed_id)

            # Track source-reachable globals into sibling helpers called by the same
            # controller. This covers common read-wrapper -> global -> checker layouts
            # without scanning every function as a possible consumer.
            globals_reached = {
                location
                for edge in flow.edges
                for location in (edge.source, edge.destination)
                if isinstance(location, GlobalLocation)
            }
            # A source-reachable global is often consumed by a direct helper that
            # receives no tainted argument (read(buf); check_global()). Include
            # only direct callees of functions already on this bounded trace.
            direct_global_consumers = {
                target_rva
                for callsite_rva, target_rva in context.calls
                if (owner := context.owner(callsite_rva)) is not None and owner.rva in depths
            }
            allowed_global_consumers = (
                root_callers | sibling_targets | set(depths) | direct_global_consumers
            ) & set(known_functions)
            for location in sorted(globals_reached, key=lambda item: item.rva):
                for function_rva in sorted(allowed_global_consumers):
                    if not _reads_global(context, function_rva, location):
                        continue
                    seed_id = f"{root.id}:global:{location.rva:X}:{function_rva:X}"
                    if seed_id in seed_ids:
                        continue
                    function = known_functions[function_rva]
                    new_seeds.append(InputSource(
                        seed_id, function.name, function_rva, function.address, function_rva,
                        root.source_type, location, root.size_hint, "POSSIBLE",
                        (f"source-reachable global RVA 0x{location.rva:X} is read by a sibling helper",),
                        next((edge.value_identity for edge in flow.edges
                              if edge.value_identity is not None and location in (edge.source, edge.destination)),
                             root_identity),
                    ))
                    seed_ids.add(seed_id)
                    depths.setdefault(function_rva, min(max_call_depth, 2))

            if not new_seeds:
                break
            seeds.extend(new_seeds)
        else:
            warnings.append("BUDGET_LIMIT: Interprocedural fixed-point iteration budget reached")
            incomplete = True

        traces.append(InterproceduralTrace(
            root.id, tuple(_unique_edges(collected_edges)), tuple(_unique_dicts(collected_calls)),
            tuple(_unique_dicts(collected_comparisons)), tuple(_unique_dicts(collected_transforms)),
            tuple(_unique_dicts(collected_returns)), tuple(sorted(depths)),
            tuple(dict.fromkeys(warnings)), incomplete,
        ))
        total_edges += len(traces[-1].edges)
        if total_edges >= max_edges:
            global_warnings.append("Global interprocedural edge budget reached")
            break
    budgets = {"max_call_depth": max_call_depth, "max_functions": max_functions,
               "max_edges": max_edges, "max_instructions": max_instructions, "max_sources": max_sources,
               "max_values": max_values, "max_aliases": max_aliases,
               "max_versions": max_versions, "max_flow_states": max_flow_states,
               "max_summary_edges": max_summary_edges}
    if len(summary_cache) >= max_summary_edges:
        global_warnings.append("BUDGET_LIMIT: function summary edge budget reached")
    grouped = {}
    for key, item in summary_cache.items():
        grouped.setdefault(int(key[0]), []).append(item)
    summaries = []
    for function_rva, items in sorted(grouped.items()):
        returns = tuple(item for item in items if isinstance(item, ReturnSummary))
        outputs = tuple(item for item in items if isinstance(item, ArgumentFlowSummary))
        mutations = tuple(sorted({item[1] for item in items if isinstance(item, tuple) and item[0] == "mutation"}))
        evidence = tuple(
            [evidence for item in returns + outputs for evidence in item.evidence]
            + [f"argument {index} is mutated in place" for index in mutations]
        )
        summaries.append(FunctionFlowSummary(
            function_rva, returns, mutations, outputs,
            "LIKELY" if any(item.kind == "RETURNS_SCALAR_RESULT" for item in returns) else "CONFIRMED",
            evidence,
        ))
    return InterproceduralFlowResult(
        tuple(traces), budgets, tuple(dict.fromkeys(global_warnings)), tuple(summaries),
    )
