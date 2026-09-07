# Phase 3C Decompiler Assistance Report

## Result and model

Phase 3C adds a bounded suggestion layer over existing evidence. It does not implement a decompiler, rewrite expressions or automatically modify analyst databases.

`DecompilerSuggestion` records `id`, suggestion kind, structured target, proposed value, HIGH/MEDIUM/LOW confidence, typed evidence, source modules, scope, safety and reverse value. Safety is `SAFE_TO_APPLY`, `REVIEW_RECOMMENDED` or `COMMENT_ONLY`; all rename suggestions currently require review.

Supported kinds are function/variable/global rename, type/array/object-role hints, temporary groups and comments. The default budget is 20 suggestions per sample, eight objects per relevant function and eight expression groups. Challenge Summary shows at most five HIGH suggestions.

## Semantic roles and rename rules

Supported roles include INPUT, POSSIBLE_KEY, LOOKUP_TABLE, DISPATCH_STATE, STRUCT_LIKE_OBJECT and conservative function roles such as input_reader, input_transform, validation_check, state_dispatcher, algorithm_transform, checksum_calc, decode_transform and table_lookup.

Function suggestions prioritize validation, on-slice algorithms, dispatchers and input provenance. Combined input plus algorithm evidence becomes `input_transform` instead of two competing names. Existing non-generated symbols are preserved and receive a COMMENT explaining the inferred role. Runtime-likely functions are excluded. Suggested names never claim password, flag, license or correct key semantics.

Variable/global suggestions are limited to proven input destinations and state-machine/indirect-dispatch state. A plain switch selector is not renamed to `state`. Algorithm data objects can become POSSIBLE_KEY or LOOKUP_TABLE only when the algorithm candidate already carries that relationship.

## Type, pointer, array and struct-like hints

Input API/provenance distinguishes pointer-like buffers from scalar register inputs and supports byte/wide-character hints. Algorithm object extent can produce conservative arrays such as `uint32_t[4]`; it does not invent context structures.

Repeated `base + index * scale` access in a relevant function produces an ARRAY_HINT with element width, index expression, unknown bounds and conservative access status. Length is never invented. Three or more stable fixed offsets on one non-stack base produce a COMMENT_ONLY STRUCT_LIKE_OBJECT with observed offsets and widths, not a generated C struct.

## Temporary and expression hints

Only an adjacent four-instruction shift-left, shift-right, XOR, add/sub region without calls or jumps is grouped. The hint explicitly retains 32-bit-like unsigned wraparound semantics and says “semantic group,” not recovered source. Calls, branches, multi-region chains and unsupported side effects prevent grouping. No constant propagation through unknown memory or algebraic overflow rewrite is performed.

## Merge, conflicts and ordering

Suggestions are deduplicated by kind and logical target. The strongest confidence, reverse value and evidence count wins. Compatible input-reader plus algorithm-transform evidence is merged into input_transform. Other uncertain roles retain conservative names or COMMENT_ONLY status rather than fabricating business semantics. Ordering is confidence, reverse value, evidence count and stable ID; it is independent of ReverseTarget Ranking 2.2.

## Ghidra and application boundary

The importer emits `RH:SUGGEST_*` bookmarks and plate comments containing proposed semantics and machine-readable evidence. Even when the user enables the pre-existing high-confidence target rename option, decompiler suggestions remain comment/bookmark-only. Existing symbols are not overwritten. The schema is Ghidra-independent and can later support IDA without a separate semantic model.

## Tests and fixture metrics

Deterministic tests cover input+algorithm role merging, validation/state roles, trusted-symbol preservation, 16-byte key typing, indexed uint32 arrays, fixed-offset struct-like hints, shift/XOR/add grouping, side-effect and scalar-pointer negatives, budget truncation and Ghidra non-application. The named C fixture covers every requested semantic family and builds under `-O1`/`-O2` when MinGW is available.

Fixture checks:

- Pointer/array: one indexed uint32 positive recognized; scalar arithmetic negative not recognized.
- Struct-like: one three-field positive recognized; scalar negative not recognized.
- Temporary reduction: one adjacent shift/XOR/add positive; one call/side-effect negative; width semantics preserved.
- Joint evidence: input+algorithm merges to input_transform; state-machine evidence produces state; algorithm object evidence produces a bounded key array.

Full result: **318 passed, 87% coverage**. The decompiler-assistance module has 97% statement coverage in the last measured run before the final two focused tests; overall coverage remains 87%.

## Public benchmark

Ground truth is sourced from the xorkey challenge author's source/writeup and the official Flare-On 2016 challenge 5 solution. Evaluation compares semantic roles, not exact stylistic spelling.

| Metric | Result |
|---|---:|
| Semantic Role TP / FP / FN | 3 / 0 / 0 |
| Semantic Role precision / recall | 100% / 100% |
| Function Rename Role TP / FP | 2 / 0 |
| Rename precision | 100% |
| Type EXACT / COMPATIBLE / WRONG / UNKNOWN | 1 / 0 / 0 / 0 |

The three roles are xorkey's validation function plus smokestack's dispatcher function and global program-counter state. The exact type is the WORD-sized dispatcher state. This is only two adjudicated samples and is not presented as broad accuracy.

Stage benefit accounting: semantic roles `+3 TP / +0 FP`; type hints `+1 exact / +0 wrong`; pointer/array and temporary reductions currently have fixture evidence only.

## Regression and performance

Phase 2 remains Top-1/3/5 **56.67% / 60.00% / 60.00%**, START precision **100%**, Validation **8 TP / 3 FP / 14 FN**, Complete Slice **6 TP / 0 FP / 16 FN**, and Actionable Slice **8 TP / 0 FP / 14 FN**.

Phase 3A remains **2 TP / 0 FP / 0 FN** and On-Slice Algorithm Precision **100% (1/1)**. Phase 3B remains **1 TP / 0 FP / 0 FN**, dispatcher **1/1 exact**, state **1 exact**.

The final public run measured median/P90/max Quick at approximately **246 / 1,304 / 2,241 ms**, versus Phase 3B's 222 / 1,236 / 2,170 ms. The semantic pass primarily consumes existing evidence; the approximately 24 ms median increase includes normal run variance and bounded local pattern collection.

## False-positive controls and withdrawn suggestions

- Plain switch selectors were withdrawn from state renaming.
- Register input is no longer automatically typed as a pointer unless provenance indicates argv or a buffer destination.
- Off-slice algorithm roles remain MEDIUM and use `possible_`.
- One indexed access is insufficient for an array hint.
- Fewer than three fixed offsets cannot produce struct-like output.
- Temporary grouping does not cross calls/jumps and remains COMMENT_ONLY.
- Trusted symbols and runtime functions are never overwritten.

Main remaining misses are values whose provenance is lost before the decompiler-visible object, arrays with only one static access, indirect base recovery, signedness, optimized expressions reordered beyond the strict local pattern and conflicts requiring richer object identity.

## Phase 3 gate

Phase 3A can identify selected transformations with real TP and zero adjudicated FP. Phase 3B can identify and localize a real indirect dispatcher/state. Phase 3C converts those facts into a small set of verified roles/types without changing ranking or applying destructive edits. All Phase 2 protection metrics remain stable.

**Phase 3 complete enough. Proceed to Phase 4.** Phase 4 has not been started.
