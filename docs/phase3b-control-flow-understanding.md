# Phase 3B Control Flow Understanding Report

## Result

Phase 3B adds bounded function-level CFG explanations for CTF reverse engineering. It detects and annotates structures; it does not rewrite control flow, patch binaries, prove predicates, devirtualize VMs or execute samples.

## Implementation audit and model

Reusable foundations were direct transfer extraction, FunctionIndex/chunks, direct call relationships, conservative single-target indirect-call resolution, validation branch successors, StaticSlice and runtime likelihood. The missing layer was a shared function-local basic-block/successor view and a structured explanation model.

`ControlFlowFinding` records function identity, kind, confidence, entry and related blocks, dispatcher, state variable, jump-table details, typed evidence, structural features, slice relation, state updates and a suggested manual action. Supported kinds are `SWITCH`, `JUMP_TABLE`, `STATE_MACHINE`, `INDIRECT_JUMP`, `INDIRECT_CALL_CLUSTER`, `FLATTENING_LIKE` and LOW-only `OPAQUE_LIKE_CANDIDATE`.

## Supported structures

| Structure | Required evidence and output |
|---|---|
| Switch / jump table | computed jump; 4/8-byte table; absolute VA, RVA or relative entries; at least three executable instruction targets; optional range check and selector |
| State machine / dispatcher | validated switch target set, identifiable state location, multiple state writes and multiple returns to dispatcher |
| Indirect call structure | multiple indirect calls, or register call proven to come from indexed function-table access with an indexed selector source |
| Flattening-like | state-machine evidence plus at least four dispatch targets, three state writes, three returns and a minimum back-to-dispatch ratio; remains MEDIUM by default |
| Opaque-like | repeated constant-heavy condition shape only; always LOW and never shown on the homepage |

The state location may be a register, stack local or global. State updates retain their block/instruction RVA and constant or `computed` value. Ordinary branch complexity, one callback, an invalid integer table, or a large direct-branch function does not produce a flattening claim.

## Integration

Each finding has `ON_CONFIRMED_SLICE`, `ON_LIKELY_SLICE`, `ON_PARTIAL_SLICE` or `OFF_SLICE`. Challenge Summary shows at most five HIGH or on-slice MEDIUM structures and inserts a control-flow node into the static path without replacing algorithm information. Ranking remains **2.2** and control-flow findings do not currently alter START HERE.

The Ghidra importer adds plate comments and bookmarks such as `RH:SWITCH`, `RH:STATE_MACHINE`, `RH:INDIRECT_JUMP` and `RH:FLATTENING_LIKE`. Comments include dispatcher, state, typed evidence and the suggested manual action. It does not modify instructions or CFG edges, and renaming remains separately opt-in under the existing policy.

## Quick budgets

Quick prioritizes StaticSlice and algorithm functions, then functions containing indirect transfers, then remaining non-runtime functions. Defaults are 96 functions, 4,096 blocks, 12,000 edges and 64 recovered indirect targets. Exhaustion emits `control-flow analysis truncated`. Phase 2's unique-target indirect-call resolver is unchanged.

## Tests and fixtures

The deterministic tests cover x86 four-byte and x64 eight-byte jump tables, selector/case recovery, dispatcher re-entry, state writes, flattening-like thresholds, invalid table, indirect call cluster, runtime downgrade, LOW opaque-like output and budget truncation. A named C fixture contains simple/large switches, state globals/locals, dispatcher loops, function tables, flattening-like and false-positive shapes; MinGW builds it at `-O1` and `-O2` when available. Ghidra bookmark/comment planning is tested.

Full result: **306 passed, 87% coverage**. The new control-flow module has 95% statement coverage.

## Public CTF benchmark

The first control-flow ground truth comes from the official Flare-On 2016 challenge 5 solution. It independently identifies `sub_401540` (RVA `0x1540`) as the VM opcode/function-table dispatcher and global RVA `0xDF1E` as its program-counter state. No detector output was used to create the annotation.

| Metric | Result |
|---|---:|
| Control Flow TP / FP / FN | 1 / 0 / 0 |
| Precision / Recall | 100% / 100% |
| Indirect Dispatch | 1 TP / 0 FP / 0 FN |
| Dispatcher localization | 1 / 1 exact |
| State variable localization | 1 exact / 0 same-base / 0 wrong / 0 unknown |
| On-Slice Control Flow Precision | unavailable: no adjudicated on-slice prediction |
| Switch / Jump Table | 0 / 0 / 0, no adjudicated public sample |
| State Machine | 0 / 0 / 0, no adjudicated public sample |
| Flattening-like | 0 / 0 / 0, no adjudicated public sample |

Six other MEDIUM/HIGH structures in that sample are explicitly reported as unadjudicated rather than incorrectly counted as false positives. The one-sample result is evidence of a real TP, not a general precision estimate.

Stage benefit accounting on adjudicated public data: Switch `+0 TP / +0 FP`; State Machine `+0 / +0`; Indirect Dispatch `+1 / +0`; Flattening-like `+0 / +0`.

## Regression and performance

Phase 2 remains unchanged: Top-1/3/5 **56.67% / 60.00% / 60.00%**, START precision **100%**, Validation **8 TP / 3 FP / 14 FN**, Complete Slice **6 TP / 0 FP / 16 FN**, Actionable Slice **8 TP / 0 FP / 14 FN**. Phase 3A remains **2 TP / 0 FP / 0 FN** with **100% (1/1)** On-Slice Algorithm Precision.

The final public run measured median/P90/max Quick at approximately **222 / 1,236 / 2,170 ms**, versus Phase 3A's approximately 190 / 1,258 / 1,856 ms. The median increased by about 32 ms; P90 remained in the same range, while the single-run maximum increased. All analysis remained bounded.

## Known limitations and detector decisions

Main misses are compiler switch lowering without a direct table operand, split dispatch across functions, register-derived relative table bases, state values propagated through long alias chains and exception-handler CFG. State-machine and flattening recall cannot yet be estimated from public data.

The following tempting rules were deliberately rejected or downgraded:

- high branch count or cyclomatic complexity alone does not imply flattening;
- one unresolved callback does not imply a function table;
- an indirect jump without three validated executable targets remains LOW;
- flattening-like remains MEDIUM even with complete structural evidence;
- repeated predicate shape remains LOW because reachability is not proven;
- runtime-likely and heuristic-boundary functions are confidence-capped.

## Gate

There is one official-solution-backed real TP with exact dispatcher and state localization, no adjudicated FP, useful Ghidra guidance and no Phase 2/3A regression. Public switch/state-machine/flattening evidence remains too small for broad claims, but those detectors are conservative and fixture-covered.

**Proceed to Phase 3C.** Phase 3C has not been started.
