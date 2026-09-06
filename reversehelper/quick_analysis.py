"""Offline P0 pipeline with deterministic scan budgets and independent degradation."""

from bisect import bisect_right
from dataclasses import replace
from datetime import datetime, timezone
from time import perf_counter

from . import algorithm_recognition, control_flow_understanding, crypto_analyzer, decompiler_assistance, input_sources, interproc_dataflow, static_slice, string_intelligence, target_ranker, validation_analyzer
from .analysis_budget import AnalysisBudget
from .annotations import build_annotations
from .dataflow_model import InterproceduralFlowResult
from .addressing import annotate_string_locations, file_offset_to_location
from .anti_debug_analyzer import ANTI_DEBUG_APIS
from .disassembler import Disassembler, iter_instruction_details
from .entry_analyzer import analyze_entry_point
from .findings import Finding
from .function_index import FunctionIndex
from .instruction_context import find_import_calls, section_name
from .packer_detector import detect_packing
from .string_analyzer import extract_strings
from .version import __version__


# Compatibility aliases for callers that previously tuned the Quick profile.
MAX_CODE_BYTES = AnalysisBudget.quick().max_code_bytes
MAX_INSTRUCTIONS = AnalysisBudget.quick().max_instructions
MAX_SCAN_BYTES = AnalysisBudget.quick().max_scan_bytes


def _decode(parser, result, budget):
    basic = result["basic"]
    disassembler = Disassembler(basic["architecture"], basic["image_base"])
    instructions = []
    summaries = []
    remaining_bytes = budget.max_code_bytes
    for section in result["sections"]:
        flags = set(section["flags"])
        entry = int(result["basic"]["entry_point_rva"])
        section_start = int(section["virtual_address"])
        section_end = section_start + int(section["raw_size"])
        code_without_execute = (
            "EXECUTE" not in flags and "CODE" in flags
            and (str(section.get("name", "")).casefold() == ".text" or section_start <= entry < section_end)
        )
        if ("EXECUTE" not in flags and not code_without_execute) or section["raw_size"] <= 0:
            continue
        count = budget.max_instructions - len(instructions)
        size = min(section["raw_size"], remaining_bytes)
        decoded = disassembler.disassemble_range(parser.data, result["sections"], section["virtual_address"], size,
                                                  maximum_instructions=count, skip_invalid=True) if count > 0 and size > 0 else []
        instructions.extend(decoded)
        remaining_bytes -= size
        decoded_bytes = sum(ins.size for ins in decoded)
        summaries.append({"name": section["name"], "raw_size": section["raw_size"], "scanned_bytes": size,
                          "decoded_bytes": decoded_bytes, "instruction_count": len(decoded),
                          "incomplete": size < section["raw_size"] or decoded_bytes < size,
                          "code_without_execute": code_without_execute})
    return instructions, summaries


def _constant_findings(constants, context, result):
    findings = []
    by_offset = sorted((ins.file_offset, ins) for ins, _ in context.records)
    offsets = [offset for offset, _ in by_offset]
    for constant in constants:
        for offset in constant["offsets"]:
            location = file_offset_to_location(offset, result["sections"], context.image_base, result["basic"]["size_of_headers"])
            index = bisect_right(offsets, offset) - 1
            ins = by_offset[index][1] if index >= 0 else None
            sites = []
            if ins and offset < ins.file_offset + ins.size:
                sites.append(ins.rva)
            elif location["va"] is not None:
                sites.extend(context.references.get(location["va"], []))
            if not sites:
                sites = [location["rva"]]
            for rva in sites:
                findings.append(Finding(f"constant-{offset:08X}-{rva}", "crypto", f"Algorithm constant candidate: {constant['algorithm']}",
                    rva, context.image_base + rva if rva is not None else None, offset, location["section"], "info", "low",
                    (f"{constant['constant']} at file offset 0x{offset:X}",),
                    "Known constant bytes or a direct reference; algorithm use and buffer role are unproven.",
                    "Inspect the constant and its code references in Ghidra/IDA."))
    return findings


def analyze_quick(analyzer, path, budget=None):
    from .analyzer import AnalysisError, SCHEMA_VERSION, _optional, _empty_strings, _empty_entry, _empty_packing
    from . import challenge_summary

    if budget is None:
        budget = replace(AnalysisBudget.quick(), max_code_bytes=MAX_CODE_BYTES,
                         max_instructions=MAX_INSTRUCTIONS, max_scan_bytes=MAX_SCAN_BYTES)
    started = perf_counter()
    parser = analyzer._open_parser(path)
    try:
        try:
            result = parser.parse()
        except Exception as error:
            raise AnalysisError(f"Analysis failed: {error}") from error
        warnings = []
        module_timings = {}

        def budgeted(module, fallback, action):
            elapsed = perf_counter() - started
            if elapsed >= budget.hard_timeout_seconds:
                warnings.append({"module": module, "error_type": "BudgetLimit",
                                 "reason": f"Not started after the {budget.hard_timeout_seconds:g}s analysis deadline; result is unavailable."})
                return fallback
            module_started = perf_counter()
            value = _optional(module, warnings, fallback, action)
            module_elapsed = perf_counter() - module_started
            module_timings[module] = round(module_elapsed * 1000, 2)
            if module_elapsed > budget.soft_timeout_seconds:
                warnings.append({"module": module, "error_type": "SoftBudgetExceeded",
                                 "reason": f"Module took {module_elapsed:.2f}s, above the {budget.soft_timeout_seconds:g}s soft budget; bounded output was retained."})
            return value

        basic = result["basic"]
        scan_data = parser.data[:budget.max_scan_bytes]
        result.update({"schema_version": SCHEMA_VERSION, "tool": {"name": "ReverseHelper", "version": __version__},
            "analysis_mode": budget.mode, "analyzed_at_utc": datetime.now(timezone.utc).isoformat(),
            "analysis_modules": ["pe", "entry", "packing", "strings", "xrefs", "functions", "input", "compare", "decision", "validation", "constants", "targets"],
            "analysis_scope": "Static PE triage with bounded analysis; target read but never executed.",
            "analysis_warnings": warnings,
            "analysis_limits": {**budget.to_dict(), "max_strings": analyzer.maximum_strings,
                                 "dataflow_max_values": 256, "dataflow_max_aliases": 1024,
                                 "dataflow_max_versions": 64, "dataflow_max_flow_states": 512,
                                 "dataflow_max_summary_edges": 128},
            "skipped_modules": ["code-caves", "dynamic-advisor"],
        })
        result["packing"] = _optional("packing", warnings, _empty_packing(), lambda: detect_packing(
            parser.pe, result["sections"], basic["entry_point_rva"], result["import_count"], basic["file_size"]))
        limited_static_visibility = result["packing"].get("static_visibility") == "limited"
        result["entry_point_analysis"] = _optional("entry", warnings, _empty_entry(),
            lambda: analyze_entry_point(parser.data, basic, result["sections"]))

        def strings():
            extracted = extract_strings(scan_data, minimum=analyzer.minimum_string_length,
                                        maximum=analyzer.maximum_strings, deduplicate=False)
            annotate_string_locations(extracted, result["sections"], basic["image_base"], basic["size_of_headers"])
            return extracted

        result["strings"] = _optional("strings", warnings, _empty_strings(analyzer.minimum_string_length), strings)
        if result["strings"]["truncated"] or len(scan_data) < len(parser.data):
            warnings.append({"module": "strings", "error_type": "BudgetLimit", "reason": "String count or byte scan budget reached; unscanned strings remain unknown."})
        instructions, sections = _optional("disassembler", warnings, ([], []), lambda: _decode(parser, result, budget))
        result["disassembly"] = {"instruction_count": len(instructions), "sections": sections,
                                  "incomplete": any(section["incomplete"] for section in sections)}
        if result["disassembly"]["incomplete"]:
            warnings.append({"module": "disassembler", "error_type": "PartialCoverage", "reason": "Some executable bytes were skipped, undecodable or outside Quick budgets; absence of findings is not absence of logic."})
        if any(section.get("code_without_execute") for section in sections):
            warnings.append({"module": "disassembler", "error_type": "NonExecutableCodeSection",
                             "reason": "A PE CODE section lacking the EXECUTE bit was decoded because it is .text or contains the entry point; section permissions remain suspicious."})
        records = _optional("instruction-details", warnings, [], lambda: list(iter_instruction_details(instructions, basic["architecture"])))
        empty_context = FunctionIndex([], result["sections"], basic["image_base"])
        runtime_functions = [(entry.struct.BeginAddress, entry.struct.EndAddress)
                             for entry in getattr(parser.pe, "DIRECTORY_ENTRY_EXCEPTION", [])
                             if hasattr(entry.struct, "BeginAddress") and hasattr(entry.struct, "EndAddress")]
        context = _optional("functions", warnings, empty_context, lambda: FunctionIndex(records, result["sections"], basic["image_base"],
            basic["entry_point_rva"], result["exports"], runtime_functions,
            symbols=result.get("coff_function_symbols", ()), limit=budget.function_instruction_limit))
        if context.truncated:
            warnings.append({"module": "functions", "error_type": "BudgetLimit", "reason": f"A function membership walk reached {budget.function_instruction_limit} instructions; remaining membership is unknown."})
        result["functions"] = [fn.to_dict() for fn in context.functions]
        result["function_boundary"] = {
            "version": "2.0",
            "function_count": len(context.functions),
            "ambiguous_instruction_count": len(context.ambiguous_rvas),
            "truncated": context.truncated,
            "secondary_chunk_count": sum(len(fn.chunks) - 1 for fn in context.functions if fn.chunks),
            "shared_epilogue_chunk_count": sum(
                chunk.relation == "SHARED_EPILOGUE" for fn in context.functions for chunk in fn.chunks
            ),
            "lead_sources": {
                source: sum(fn.source == source for fn in context.functions)
                for source in sorted({fn.source for fn in context.functions})
            },
        }
        result["call_relationships"] = [{"id": f"call-{source:08X}", "source_rva": source, "target_rva": target,
            "function_rva": context.owner(source).rva if context.owner(source) else None,
            "relation": "resolved_indirect_call" if source in context.resolved_indirect_calls else "direct_call"}
            for source, target in context.calls]
        import_calls = _optional("import-call-resolution", warnings, [], lambda: find_import_calls(
            instructions, result["imports"], basic["architecture"], basic["image_base"], records))
        result["interesting_strings"] = _optional("string-intelligence", warnings, [],
            lambda: string_intelligence.analyze_interesting_strings(
                result["strings"], context, limited_static_visibility=limited_static_visibility))
        findings = _optional("input", warnings, [], lambda: validation_analyzer.find_input_candidates(
            instructions, result["imports"], result["sections"], basic["architecture"], basic["image_base"],
            instruction_details=records, import_calls=import_calls))
        sources = _optional("input-sources", warnings, [], lambda: input_sources.discover_input_sources(
            context, import_calls, basic["architecture"], result["strings"].get("strings", []),
            include_export_arguments=basic["file_type"] == "DLL",
            allow_unnamed_argv="console" in str(basic.get("subsystem", "")).casefold()))
        result["input_sources"] = [source.to_dict() for source in sources]
        argv_sources = [source for source in sources if source.source_type.startswith("argv[")]
        result["input_source_diagnostics"] = []
        if (basic["file_type"] == "EXE"
                and "console" in str(basic.get("subsystem", "")).casefold()
                and not argv_sources):
            result["input_source_diagnostics"].append({
                "code": "ARGV_SOURCE_UNRESOLVED",
                "confidence": "POSSIBLE",
                "reason": "A reliable CRT-to-user-main argc/argv relationship was not recovered; no argv source was guessed.",
            })
        flow = budgeted("data-flow",
            InterproceduralFlowResult((), {"max_call_depth": budget.dataflow_max_call_depth,
                                           "max_functions": budget.dataflow_max_functions,
                                           "max_edges": budget.dataflow_max_edges,
                                           "max_instructions": budget.dataflow_max_instructions,
                                           "max_sources": budget.dataflow_max_sources,
                                           "max_values": 256, "max_aliases": 1024,
                                           "max_versions": 64, "max_flow_states": 512,
                                           "max_summary_edges": 128},
                                      ("Data-flow analysis unavailable",)),
            lambda: interproc_dataflow.propagate_input_flows(
                context, sources, basic["architecture"],
                max_call_depth=budget.dataflow_max_call_depth,
                max_functions=budget.dataflow_max_functions,
                max_edges=budget.dataflow_max_edges,
                max_instructions=budget.dataflow_max_instructions,
                max_sources=budget.dataflow_max_sources))
        candidates = _optional("validation", warnings, [], lambda: validation_analyzer.discover_validation(
            context, import_calls, result["interesting_strings"], basic["architecture"], parser.data,
            input_sources=sources, limited_static_visibility=limited_static_visibility,
            function_summaries=flow.function_summaries))
        slices, candidates = _optional("static-slice", warnings, ([], candidates),
            lambda: static_slice.build_static_slices(sources, flow, candidates))
        flow_breaks = _optional("static-flow-break", warnings, [],
            lambda: static_slice.build_static_flow_breaks(sources, flow, context, slices))
        result["data_flow"] = flow.to_dict()
        result["static_slices"] = [item.to_dict() for item in slices]
        result["static_flow_breaks"] = [item.to_dict() for item in flow_breaks]
        slice_statuses = [item["status"] for item in result["static_slices"]]
        sliced_candidates = {item.validation_sink.get("id") for item in slices if item.validation_sink}
        result["static_slice_summary"] = {
            "confirmed": slice_statuses.count("CONFIRMED_SLICE"),
            "likely": slice_statuses.count("LIKELY_SLICE"),
            "partial": slice_statuses.count("PARTIAL_SLICE") + len(flow_breaks),
            "unresolved": sum(candidate.id not in sliced_candidates for candidate in candidates),
            "flow_breaks": len(flow_breaks),
        }
        compare_sites, decision_sites = validation_analyzer.split_compare_decision_sites(candidates)
        result["compare_sites"] = [site.to_dict() for site in compare_sites]
        result["decision_sites"] = [site.to_dict() for site in decision_sites]
        result["validation_candidates"] = [candidate.to_dict() for candidate in candidates]
        algorithms, algorithm_budget = budgeted(
            "algorithm-recognition", ([], {**algorithm_recognition.DEFAULT_BUDGETS, "truncated": True}),
            lambda: algorithm_recognition.recognize_algorithms(context, parser.data, slices, budgets={
                "max_algorithm_functions": budget.max_algorithm_functions,
                "max_algorithm_instructions": budget.max_algorithm_instructions,
                "max_table_candidates": budget.max_table_candidates}),
        )
        result["algorithm_candidates"] = [candidate.to_dict() for candidate in algorithms]
        result["algorithm_analysis"] = algorithm_budget
        if algorithm_budget.get("truncated"):
            warnings.append({"module": "algorithm-recognition", "error_type": "BudgetLimit",
                             "reason": "Algorithm analysis truncated; unexamined functions or instructions remain unknown."})
        control_flow, control_flow_budget = budgeted(
            "control-flow-understanding",
            ([], {**control_flow_understanding.DEFAULT_BUDGETS, "truncated": True}),
            lambda: control_flow_understanding.analyze_control_flow(context, parser.data, slices, algorithms, budgets={
                "max_cfg_functions": budget.max_cfg_functions, "max_cfg_blocks": budget.max_cfg_blocks,
                "max_cfg_edges": budget.max_cfg_edges, "max_indirect_targets": budget.max_indirect_targets}),
        )
        result["control_flow_findings"] = [finding.to_dict() for finding in control_flow]
        result["control_flow_analysis"] = control_flow_budget
        if control_flow_budget.get("truncated"):
            warnings.append({"module": "control-flow-understanding", "error_type": "BudgetLimit",
                             "reason": "Control-flow analysis truncated; unexamined functions, blocks or targets remain unknown."})
        suggestions, semantic_budget = budgeted(
            "decompiler-assistance",
            ([], {**decompiler_assistance.DEFAULT_BUDGETS, "truncated": True}),
            lambda: decompiler_assistance.generate_suggestions(
                context, sources, slices, candidates, algorithms, control_flow, flow, budgets={
                    "max_semantic_suggestions": budget.max_semantic_suggestions,
                    "max_objects_per_function": budget.max_objects_per_function,
                    "max_expression_groups": budget.max_expression_groups}),
        )
        result["decompiler_suggestions"] = [suggestion.to_dict() for suggestion in suggestions]
        result["decompiler_assistance"] = semantic_budget
        if semantic_budget.get("truncated"):
            warnings.append({"module": "decompiler-assistance", "error_type": "BudgetLimit",
                             "reason": f"Semantic suggestions truncated; lower-ranked suggestions remain outside the {budget.mode.title()} output limits."})
        for candidate in candidates:
            findings.append(Finding(candidate.id, "validation", f"Possible {candidate.validation_type.lower()} site", candidate.rva,
                candidate.address, context.by_rva[candidate.rva][0].file_offset, section_name(candidate.rva, result["sections"]),
                "info", candidate.confidence, candidate.evidence, "Contextual comparison candidate; flag-checker identity is not established.",
                "Inspect the comparison arguments, cited strings and both branch successors in Ghidra/IDA."))
        result["crypto_constants"] = _optional("crypto-constants", warnings, [], lambda: crypto_analyzer.find_crypto_constants(scan_data))
        findings.extend(_optional("constant-context", warnings, [], lambda: _constant_findings(result["crypto_constants"], context, result)))
        for transfer, dll, imported in import_calls:
            if not imported.get("suspicious") and imported["name"].lower() not in ANTI_DEBUG_APIS:
                continue
            rva = transfer["source_rva"]
            category = "anti-debug" if imported["name"].lower() in ANTI_DEBUG_APIS else "sensitive-api"
            findings.append(Finding(f"api-{rva:08X}", category, f"API call: {imported['name']}", rva,
                transfer["source_address"], transfer["file_offset"], section_name(rva, result["sections"]), "info", "low",
                (f"Call resolves to {dll}!{imported['name']}",), "Sensitive API is called here; purpose is unproven.",
                "Inspect arguments and surrounding conditions in Ghidra/IDA."))
        if result["packing"]["indicators"]:
            findings.append(Finding("packing-entry", "packing", "Packing/entry review candidate", basic["entry_point_rva"], basic["entry_point_va"],
                basic["entry_point_offset"], result["packing"].get("entry_point_section"), "info", "low",
                tuple(item["evidence"] for item in result["packing"]["indicators"]),
                "Structural packing indicators justify reviewing the entry point; packing is not proven.", "Inspect the entry point and cited section indicators."))
        result["findings"] = [finding.to_dict() for finding in findings]
        targets = _optional("target-ranking", warnings, [], lambda: target_ranker.rank_targets(findings, context=context,
            interesting_strings=result["interesting_strings"], validation_candidates=candidates, static_slices=slices,
            algorithm_candidates=algorithms, packed=limited_static_visibility))
        result["reverse_targets"] = [target.to_dict() for target in targets]
        result["target_ranking"] = {
            "version": "2.2",
            "score_range": [0, 100],
            "policy": "function-level evidence families with corroboration bonuses and explicit caps",
            "weights": dict(target_ranker.WEIGHTS),
        }
        result["challenge_summary"] = _optional("summary", warnings, {}, lambda: challenge_summary.build_summary(result))
        result["annotations"] = _optional("annotations", warnings, [], lambda: build_annotations(result))
        result["truncated_modules"] = sorted({warning["module"] for warning in warnings
                                               if warning.get("error_type") in {"BudgetLimit", "PartialCoverage"}})
        result["result_status"] = {
            "facts": "directly parsed or decoded observations",
            "candidates": "ranked static hypotheses requiring review",
            "suggestions": "optional names/comments that are never applied automatically",
            "unavailable": [warning["module"] for warning in warnings
                            if warning.get("error_type") not in {"BudgetLimit", "PartialCoverage"}],
            "truncated": result["truncated_modules"],
        }
        result["module_timings_ms"] = module_timings
        elapsed_ms = round((perf_counter() - started) * 1000, 2)
        result["analysis_elapsed_ms"] = elapsed_ms
        result[f"{budget.mode}_elapsed_ms"] = elapsed_ms
        return result
    finally:
        parser.close()
