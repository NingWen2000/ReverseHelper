# Competition workflow

## Product Workflow Audit

The audited primary path is:

`challenge PE -> reversehelper challenge.exe -> Challenge Summary -> Ghidra/IDA -> manual reversing`

The default command is Quick. It shows target identity, architecture, packing/static visibility, START HERE or conservative starting points, input flow, likely static path/FLOW BREAK, likely validation, algorithm/control-flow candidates and the next action. Section/import/raw evidence detail remains in JSON or explicit reports so the first screen stays actionable.

Use `--deep` only when Quick is truncated or does not expose enough static evidence. Deep calls the same analyzers and emits the same schema; it only raises explicit decode, function, data-flow, algorithm, CFG and semantic budgets. It does not silently switch to a different legacy pipeline.

Use `--report` for Markdown/HTML/JSON, `--json` for automation, and `--ghidra` for the same stable JSON plus unified annotations. `--verbose` prints profile and coverage details. Legacy `--only` modes remain available for diagnosis but are not the product entry point.

## Ghidra handoff

The top-level `annotations` array is tool-independent. The bundled importer adds comments and bookmarks such as `RH:START`, `RH:INPUT`, `RH:SLICE`, `RH:VALIDATION`, `RH:ALGORITHM`, `RH:FLOW_BREAK`, dispatcher/control-flow markers and `RH:SUGGEST_*`. It validates program identity and does not rename by default. Existing JSON without `annotations` still uses the earlier findings/targets compatibility path.

IDA-specific deep integration is deferred: shipping a second importer without real end-to-end validation would increase maintenance more than TTCF value. The generic annotation schema is the future integration boundary.

## Solver decision

Automatic solver skeleton generation is deferred. Current public algorithm ground truth is too small and static-slice recall is still limited, so generated solvers would risk presenting hypotheses as executable truth. ReverseHelper exports evidence and next actions instead.
