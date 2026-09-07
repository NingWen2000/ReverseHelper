# Phase 2.7A Static Slice Failure Audit Report

## Scope and method

This audit covers the **19 unresolved actionable-slice false-negative validation sinks in 14 challenges** from `phase26-final`. The already-actionable `flareon2017-03` checksum sink at RVA `0x11E6` is intentionally excluded. The unit is a ground-truth validation sink, not a binary: `flareon2018-10` contributes four sinks, while `flareon2015-02` and `flareon2016-04` contribute two each.

Each sink was rechecked against the current Phase 2.6 input sources, function ranges/chunks, trace edges, CompareSites, DecisionSites, ValidationCandidates, StaticFlowBreaks, START HERE, and frozen public-source ground truth. No sample was executed. No production rule, ranking weight, validation threshold, or analysis budget was changed.

The audit dataset is [`benchmarks/analysis/phase27_slice_failure_audit.json`](../benchmarks/analysis/phase27_slice_failure_audit.json). `phase27_raw_slice_diagnostics.json` is a current-output evidence snapshot; it contains 20 complete-slice misses because the actionable Partial hit at `flareon2017-03:0x11E6` remains a complete-slice miss. This report uses the required actionable-FN denominator of 19.

Ground-truth ambiguous count is **0**, but 17/19 sink records still rely on a single-maintainer address review. Official or author sources reduce uncertainty but do not replace an independent second reviewer.

## Executive findings

| Measure | Result |
| --- | ---: |
| Audited challenges | 14 |
| Unresolved actionable Slice FN sinks | 19 |
| Ground-truth ambiguous | 0 |
| Fully visible | 15 |
| Partially visible | 3 |
| Packed/transformed | 1 |
| Static-visible sinks | 18 |
| Realistically fixable static-visible FN | 15 |
| Low-repairability static-visible FN | 3 |
| Packed/out-of-scope FN | 1 |
| Validation FN among audited Slice FN | 17 |
| Threshold-only publication blocks | 0 |
| Slice FN with useful START HERE | 7 |
| Slice FN without a useful START | 12 |

The dominant problem is not generic data flow. Correct ground-truth input provenance is absent in 10 static-visible sinks; nine are `INPUT_SOURCE_MISSED` and one is `INPUT_WRAPPER_MISSED`. Five more sinks reach the validation neighborhood but fail before a CompareSite is produced. Only three fail primarily after a correct input seed and before the validation neighborhood because of function identity or global propagation.

## Primary and secondary failure frequency

| Primary failure | Count |
| --- | ---: |
| `INPUT_SOURCE_MISSED` | 9 |
| `STATIC_LINKED_COMPARE` | 3 |
| `FUNCTION_BOUNDARY` | 2 |
| `OPTIMIZED_COMPARE` | 2 |
| `STATIC_NOT_VISIBLE` | 1 |
| `GLOBAL_FLOW` | 1 |
| `INPUT_WRAPPER_MISSED` | 1 |

| Secondary failure | Count |
| --- | ---: |
| `ARGUMENT_MAPPING` | 5 |
| `OPTIMIZATION_ARTIFACT` | 5 |
| `COMPARE_NOT_DETECTED` | 5 |
| `X64_REGISTER_ARGUMENT` | 5 |
| `RETURN_FLOW` | 4 |
| `POINTER_ALIAS` | 2 |
| `INDIRECT_CALL` | 2 |
| all other secondary categories | 1 each |

Secondary counts must not be read as independent FN counts. In particular, the four `flareon2018-10` sinks repeat one early-argv discovery failure and its downstream x64 argument/compare consequences.

## Tier distribution

| Primary failure | Tier A | Tier B | Tier C | Total |
| --- | ---: | ---: | ---: | ---: |
| `INPUT_SOURCE_MISSED` | 0 | 8 | 1 | 9 |
| `STATIC_LINKED_COMPARE` | 2 | 1 | 0 | 3 |
| `FUNCTION_BOUNDARY` | 1 | 1 | 0 | 2 |
| `OPTIMIZED_COMPARE` | 0 | 1 | 1 | 2 |
| `STATIC_NOT_VISIBLE` | 0 | 0 | 1 | 1 |
| `GLOBAL_FLOW` | 0 | 1 | 0 | 1 |
| `INPUT_WRAPPER_MISSED` | 0 | 1 | 0 | 1 |
| **Total** | **3** | **13** | **3** | **19** |

The concentration in Tier B is not just difficulty: four entries are the four sinks of one binary and two are exports in another. Challenge-level and sink-level impacts should both be considered before implementation.

## Failure funnel

The required A–G split is:

```text
All unresolved actionable Slice FN (19)
|
+-- A. Correct input not found                         10
|   +-- INPUT_SOURCE_MISSED                             9
|   +-- INPUT_WRAPPER_MISSED                            1
|
+-- B. Input found, propagation/function identity broke 3
|   +-- FUNCTION_BOUNDARY                               2
|   +-- GLOBAL_FLOW                                     1
|
+-- C. Flow reached validation area, CompareSite missed 5
|   +-- STATIC_LINKED_COMPARE                           3
|   +-- OPTIMIZED_COMPARE                               2
|
+-- D. Compare found, Decision not linked                0
+-- E. Validation found, Slice graph not closed          0
+-- F. Real graph exists, publication threshold blocked  0
+-- G. Static validation code not visible                1
```

This directly answers the publication question: **the analyzer did not produce the required semantic edges; the publication gate did not suppress any otherwise-complete audited chain.** Lowering thresholds would change confidence policy without repairing a single first broken edge.

## Input and validation funnels

For the 19 audited FN sinks:

```text
Ground-truth input/validation sink                         19
|- static-visible                                         18
|- correct ground-truth input source detected              8
|- at least one relevant real flow edge recovered           8
|- CompareSite detected at the ground-truth sink            2
|- DecisionSite detected at the ground-truth sink           2
|- ValidationCandidate promoted at the ground-truth sink    2
|- input provenance linked to that promoted validation      0
`- actionable Slice published for the audited sink          0
```

The two promoted-but-unlinked validation sinks are `flareon2016-03:0x27A0` and `aviv-re-challenge-01:0x1350`. Together they show a clean source-side opportunity: validation is already correct, but the real argv object is not seeded.

Across the full Phase 2.6 benchmark there are 22 ground-truth validation sinks. Exact scoring reports 4 matched ValidationCandidates, 2 complete Slice TP, and one additional actionable Partial TP. The raw output reports 3 flow-linked validations, but this output count is not itself a ground-truth-matched funnel layer. The actionable Partial at `flareon2017-03:0x11E6` deliberately bypasses ValidationCandidate promotion, so the full benchmark is not a strictly linear promotion funnel.

Seventeen of the 19 audited Slice FN are also Validation FN. The exceptions are the two promoted-but-unlinked sinks above. Validation recognition is therefore a major downstream gap, but for 10 static-visible sinks the earlier ground-truth input source is already missing; the audit does not justify treating all 17 as a Validation-only problem.

## Function-boundary funnel

| Function-boundary checkpoint | Sinks passing | Sinks failing at/before checkpoint |
| --- | ---: | ---: |
| Ground-truth function exists in FunctionIndex | 17 | 2 |
| Boundary represents the logical function correctly | 15 | 4 |
| Required chunk is complete | 15 | 4 |
| Runtime likelihood does not wrongly reject it | 15 | 4 |
| Eligible for current ranking/candidate processing | 15 | 4 |

The two absent functions are packed `flareon2015-04:0x1442` and `flareon2017-06:0x5A50`. The two additional logical-boundary failures are `flareon2015-02:0x1000` and `flareon2017-03:0x1000`; both split a small entry range from the body that owns the useful semantics. By contrast, all four `flareon2018-10` checker ranges and their direct-call relationships are correct. The old `FUNCTION_CHUNK` primary label for those four sinks is rejected.

## StaticFlowBreak quality

`NEAR` means the emitted break is in the same ground-truth logical function or at an immediately adjacent critical call, but is not the exact first broken edge. `WRONG` means it follows a different input/object path or points outside that neighborhood.

| Quality | Count | Cases |
| --- | ---: | --- |
| Exact | 0 | none among unresolved sinks |
| Near | 1 | `flareon2017-03:0x1000` |
| Wrong | 1 | `flareon2017-04:0x14E20` |
| No break emitted | 17 | all remaining sinks |

The exact `0x1040 -> 0x11E6` Flow Break belongs to the already-actionable checksum sink and is not an unresolved FN. For the remaining `0x1000` controller sink it is only NEAR. `flareon2017-04` emits a break at GUI-path indirect call `0x234F`, but the ground-truth failure concerns a different file/global object reaching `0x14E20`, so it is WRONG for that sink.

## START HERE on Slice FN

Seven sink records still have a useful START HERE under a manual “true critical region” rule: both `flareon2015-02` sinks, `flareon2015-04`, `flareon2015-05`, `flareon2015-09`, `flareon2016-01`, and the remaining `flareon2017-03:0x1000` sink. Twelve have no useful emitted start. The two exact-address benchmark misses at `flareon2015-02:0x1001` and `flareon2017-03:0x1008` are manually useful because they land in the split logical controller body.

This means Slice failure is not always total workflow failure, but START HERE does not compensate for 12/19 unresolved sinks.

## Priority matrix and Pareto analysis

| Failure | Count | Static-visible | Repairability | Complexity | Product value |
| --- | ---: | ---: | --- | --- | --- |
| `INPUT_SOURCE_MISSED` | 9 | 9 | HIGH overall | S–M | HIGH |
| `STATIC_LINKED_COMPARE` | 3 | 3 | HIGH | M | HIGH |
| `FUNCTION_BOUNDARY` | 2 | 2 | MEDIUM | M | MEDIUM |
| `OPTIMIZED_COMPARE` | 2 | 2 | MEDIUM/LOW | L–XL | HIGH/LOW |
| `GLOBAL_FLOW` | 1 | 1 | LOW | XL | MEDIUM |
| `INPUT_WRAPPER_MISSED` | 1 | 1 | LOW | XL | MEDIUM |
| `STATIC_NOT_VISIBLE` | 1 | 0 | OUT_OF_SCOPE | XL | LOW |

“Realistically fixable” is defined as FULLY/PARTIALLY_VISIBLE plus HIGH or MEDIUM repairability. That yields **15/19 FN sinks**. The other four are one runtime-unpacked sink and three static-visible but low-repairability cases (`flareon2016-05`, `flareon2017-04`, and `replay-level-01`).

The top three categories by repairable impact—`INPUT_SOURCE_MISSED`, `STATIC_LINKED_COMPARE`, and `FUNCTION_BOUNDARY`—cover **14/15 = 93.33%** of realistically fixable static-visible FN. This is sink-level coverage; because `flareon2018-10` contributes four sinks, the same categories cover 9 of the 11 affected fixable challenge/sink groups after collapsing repeated causes.

## Phase 2.7B recommended targets

At most three targets are justified:

1. **Correct input-source seeding at the real use site.** Start with early/optimized argv loads and exported-function parameters. The clean acceptance cases are `aviv-re-challenge-01`, `flareon2016-03`, `flareon2016-04`, and the four direct checker calls in `flareon2018-10`. Date-derived input should be a bounded follow-up, not an open-ended semantic source framework.
2. **Bounded static-linked comparator/thunk recognition.** Target the three source-reachable, static-visible comparator misses in `flareon2015-02`, `flareon2015-09`, and `flareon2016-01`. Require operand provenance and an outcome branch to control false positives.
3. **Entry/body logical-boundary reconciliation.** Limit this to the two one-entry/split-body cases at RVA `0x1000`. Do not reopen general chunk recovery without evidence from additional challenges.

These are recommendations only. No repair was implemented in Phase 2.7A.

## Not recommended for Phase 2.7B

- Runtime unpacking for `flareon2015-04` is outside the current offline static workbench boundary.
- General VM semantics for `flareon2016-05` has XL cost and low expected reusable value.
- Broad global/object alias recovery for infected `flareon2017-04` has XL cost and high false-positive risk.
- General GUI callback plus indirect-call reconstruction for the large `replay-level-01` MSVC binary should wait for narrower evidence; the real input wrapper is missing before indirect resolution matters.
- Lowering publication or Validation thresholds is not supported by this audit: threshold-only blocks are zero.

## Per-sink appendix

### flareon2015-02 — sink 0x1000

Ground truth: `ReadFile -> global buffer -> controller 0x1000`. ReverseHelper recovers two relevant edges in body `0x1001`, but splits the one-byte `0x1000` entry from that body. First broken edge: `0x1000 entry -> 0x1001 input-owning body`. Primary: `FUNCTION_BOUNDARY`; secondary: `STATIC_LINKED_COMPARE`. Repairability/complexity/value: MEDIUM/M/MEDIUM. START HERE `0x1001` is useful; no Flow Break is emitted.

### flareon2015-02 — sink 0x1084

Ground truth: `ReadFile/global -> direct arg1 -> custom compare 0x1084`. The trace visits the helper and observes its raw `CMP` at `0x1093`, but emits no CompareSite. First broken edge: `helper argument -> comparison result`. Primary: `STATIC_LINKED_COMPARE`; secondary: `ARGUMENT_MAPPING`. HIGH/M/HIGH. No Flow Break; START HERE at the controller remains useful.

### flareon2015-04 — sink 0x1442

Ground truth: `runtime unpack -> password check 0x1442`. The validation implementation is not reliably in the original static image. First broken edge: `packed image -> runtime-unpacked code`. Primary: `STATIC_NOT_VISIBLE`. OUT_OF_SCOPE/XL/LOW. The packed-stub START is useful, but a static Slice would be false evidence.

### flareon2015-05 — sink 0x1100

Ground truth: `ReadFile stack input -> 0x1250 -> 0x12A0 -> optimized constraints in 0x1100`. Input and two relevant edges exist; six raw comparisons in the controller do not become a CompareSite. First broken edge: `optimized constraint operands -> semantic compare`. Primary: `OPTIMIZED_COMPARE`; secondary: `OPTIMIZATION_ARTIFACT`. MEDIUM/L/HIGH. START HERE is useful; no Flow Break.

### flareon2015-09 — sink 0x1495

Ground truth: `ReadFile/global -> direct checker arg -> custom validation 0x1495`. The correct function and a source call edge exist, but the custom comparison is not recognized. First broken edge: `checker argument -> custom comparison result`. Primary: `STATIC_LINKED_COMPARE`; secondary: `GLOBAL_FLOW`, `OPTIMIZATION_ARTIFACT`. HIGH/M/HIGH. START HERE is useful; no Flow Break.

### flareon2016-01 — sink 0x1420

Ground truth: `ReadFile -> modify_password 0x1260 -> strcmp/outcome in 0x1420`. Eight relevant trace edges reach the transform/controller; the static comparator/thunk call is not a CompareSite. First broken edge: `transformed password -> strcmp result`. Primary: `STATIC_LINKED_COMPARE`; secondary: `THUNK_CHAIN`, `RETURN_FLOW`. HIGH/M/HIGH. START HERE is useful; no Flow Break.

### flareon2016-03 — sink 0x27A0

Ground truth: `command-line password -> hash -> comparison loops 0x2A10/0x2A8A`. Both CompareSites, Decisions, and the ValidationCandidate are present, but only unrelated sources in `0x5C78` are emitted. First broken edge: `CRT argv -> password object in 0x27A0`. Primary: `INPUT_SOURCE_MISSED`; secondary: `ARGUMENT_MAPPING`, `OPTIMIZATION_ARTIFACT`. HIGH/S/HIGH. No useful START or Flow Break.

### flareon2016-04 — sink 0x2F50

Ground truth: `external caller arg -> ordinal 50 crypto/validation export 0x2F50`. The function exists, but exported parameters are not input seeds. First broken edge: `module boundary -> ordinal 50 parameter`. Primary: `INPUT_SOURCE_MISSED`; secondary: `ARGUMENT_MAPPING`, `RETURN_FLOW`. HIGH/S/HIGH. No START or Flow Break.

### flareon2016-04 — sink 0x2E70

Ground truth: `external caller arg -> ordinal 51 crypto/validation export 0x2E70`. The function exists, but exported parameters are not input seeds. First broken edge: `module boundary -> ordinal 51 parameter`. Primary: `INPUT_SOURCE_MISSED`; secondary: `ARGUMENT_MAPPING`, `RETURN_FLOW`. HIGH/S/HIGH. No START or Flow Break.

### flareon2016-05 — sink 0x2F30

Ground truth: `argv[1] -> VM 0x1610 -> MD5/RC4 -> controller 0x2F30`. Input and four relevant edges exist, but VM/optimized semantics do not yield a CompareSite. First broken edge: `source-reachable VM arguments -> validation compare`. Primary: `OPTIMIZED_COMPARE`; secondary: `POINTER_ALIAS`, `OPTIMIZATION_ARTIFACT`. LOW/XL/LOW. No useful START or Flow Break.

### flareon2017-03 — sink 0x1000

Ground truth: `recv 0x1121 -> controller body 0x1008 -> XOR 0x103B -> ADD 0x103D -> store 0x1040 -> branch/checks`. The transform edges are real, but the `0x1000` entry and `0x1008` body are separate functions. First broken edge: `0x1000 entry -> 0x1008 logical body`. Primary: `FUNCTION_BOUNDARY`; secondary: `STACK_ALIAS`, `COMPARE_NOT_DETECTED`. MEDIUM/M/MEDIUM. The emitted `0x1040 -> 0x11E6` break is NEAR for this controller sink and exact for the already-fixed checksum sink.

### flareon2017-04 — sink 0x14E20

Ground truth: `filename/file object -> derived registry-key path -> scanner 0x14E20`. The relevant object is not carried to its distant consumer. First broken edge: `file/global object -> checker consumer`. Primary: `GLOBAL_FLOW`; secondary: `INDIRECT_CALL`, `POINTER_ALIAS`. LOW/XL/MEDIUM. The emitted GUI-buffer break at `0x234F` is WRONG for this sink.

### flareon2017-06 — sink 0x5A50

Ground truth: `date-derived input 0x4710 -> setup/decryption 0x5D30 -> XOR 0x5C40 -> exported logic 0x5A50`. Only unrelated command-line sources at `0xAC3C` are emitted. First broken edge: `system date result -> challenge date object`. Primary: `INPUT_SOURCE_MISSED`; secondary: `RETURN_FLOW`, `FUNCTION_BOUNDARY`. MEDIUM/M/MEDIUM. No useful START or Flow Break.

### flareon2018-10 — sink 0x1E40

Ground truth: `early argv[1] -> direct CALL 0x1D3A -> checker 0x1E40`. The direct call and confirmed checker boundary exist, but ReverseHelper detects only a later argv load at `0x1E15`, after the checker calls. First broken edge: `early argv load -> call argument`. Primary: `INPUT_SOURCE_MISSED`; secondary: `X64_REGISTER_ARGUMENT`, `COMPARE_NOT_DETECTED`. HIGH/S/HIGH. The old `FUNCTION_CHUNK` label is incorrect.

### flareon2018-10 — sink 0x1F20

Ground truth: `early argv[1] -> direct CALL 0x1D5B -> checker 0x1F20`. The only detected source is post-checker `0x1E15`. First broken edge: `early argv load -> call argument`. Primary: `INPUT_SOURCE_MISSED`; secondary: `X64_REGISTER_ARGUMENT`, `COMPARE_NOT_DETECTED`. HIGH/S/HIGH. Boundary `0x1F20-0x1FEF` is correct.

### flareon2018-10 — sink 0x2000

Ground truth: `early argv[1] -> direct CALL 0x1D7C -> checker 0x2000`. The only detected source is post-checker `0x1E15`. First broken edge: `early argv load -> call argument`. Primary: `INPUT_SOURCE_MISSED`; secondary: `X64_REGISTER_ARGUMENT`, `COMPARE_NOT_DETECTED`. HIGH/S/HIGH. Boundary `0x2000-0x20CF` is correct.

### flareon2018-10 — sink 0x20E0

Ground truth: `early argv[1] -> direct CALL 0x1D9D -> checker 0x20E0`. The only detected source is post-checker `0x1E15`. First broken edge: `early argv load -> call argument`. Primary: `INPUT_SOURCE_MISSED`; secondary: `X64_REGISTER_ARGUMENT`, `COMPARE_NOT_DETECTED`. HIGH/S/HIGH. Boundary `0x20E0-0x21AF` is correct.

### aviv-re-challenge-01 — sink 0x1350

Ground truth: `argv password -> MD5/hex decode -> four strcmp decisions in _main 0x1350`. Four CompareSites, Decisions, and ValidationCandidates are correct, but the optimized argv access produces no InputSource. First broken edge: `CRT argv -> password object in _main`. Primary: `INPUT_SOURCE_MISSED`; secondary: `ARGUMENT_MAPPING`, `OPTIMIZATION_ARTIFACT`. HIGH/S/HIGH. This is the cleanest next source-side acceptance case.

### replay-level-01 — sink 0x1E260

Ground truth: `GUI/license input -> callback/wrapper path -> authentication 0x1E260`. The only detected input is unrelated argv at `0x60D0`; therefore the real GUI wrapper is missing before downstream indirect calls matter. First broken edge: `GUI control/callback -> application license value`. Primary: `INPUT_WRAPPER_MISSED`; secondary: `INDIRECT_CALL`, `BUDGET_LIMIT`, `X64_REGISTER_ARGUMENT`. LOW/XL/MEDIUM. No useful START or Flow Break.

## Final conclusion

What actually blocks Static Slice? Missing correct input provenance first (10/19), then missing CompareSite semantics (5/19); thresholds block 0.

Fix next: bounded real-use argv/export input seeding, static-linked comparator/thunk recognition, and two entry/body boundary cases.

Realistically fixable: 15/19 static-visible FN sinks.

Phase 3 should remain blocked until those bounded Phase 2.7B targets are measured; do not pursue packed/VM/general heap or GUI alias expansion now.
