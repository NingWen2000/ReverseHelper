# Limitations and trust boundary

- Windows PE x86/x64 is the supported competition target. ELF, managed assemblies and arbitrary firmware are outside this release.
- Analysis is static, bounded and path-insensitive. It does not execute, emulate, unpack, symbolically solve or recover runtime-generated code.
- Packing detection is heuristic. When visibility is limited, pre-unpack strings, ranking and validation are explicitly downgraded; re-run on an authorized unpacked dump.
- Function boundaries, input provenance, validation, algorithms, control-flow structures and semantic names are candidates unless the individual evidence says otherwise.
- `result_status` distinguishes parsed/decoded facts, review candidates, optional suggestions, unavailable modules and truncation. Unknown means unknown—not safe, absent or false.
- Quick and Deep have finite budgets. `truncated_modules` and warnings identify incomplete coverage; Deep improves breadth, not certainty.
- The Ghidra importer checks identity and defaults to comments/bookmarks. It cannot prove that a mapped RVA is semantically correct.
- Malformed inputs return a concise error. Failure in an optional module is isolated and retained in `analysis_warnings` when parsing can continue.
- No human TTCF result is claimed until the recorded protocol has real participant data.
