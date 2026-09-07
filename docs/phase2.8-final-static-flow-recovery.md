# Phase 2.8 Final Static Flow Recovery

## Scope and gate result

Phase 2.8 was the last Static Flow development round. It changed only bounded interprocedural provenance and the audited Golf return/decision shape. Ranking remains 2.2; no Slice publication threshold, benchmark denominator, ground truth, dynamic execution, solver, generic ABI inference, or Phase 3 feature changed.

Final gate: **Outcome A**.

```text
Phase 2 complete enough.
Proceed to Phase 3.
```

This closes Phase 2.x. Phase 3 is permitted for the next user-directed round but was not started here. There will be no Phase 2.9.

## Phase 2.8 Target Audit

The 14 remaining realistically fixable FN from Phase 2.7B were classified by their first gate, exclusively:

```text
PARAMETER_PROVENANCE       3
RETURN_PROVENANCE          1
INPLACE_OBJECT_PROVENANCE  1
DERIVED_RETURN             0
COMPARESITE_GOLF           4
OTHER                      5
```

Only 5/14 were primarily ordinary argument/return/in-place provenance. Four more belonged to one Golf return-semantics family. This did not justify a larger SSA, memory SSA, alias, or function-summary system. The machine-readable audit is [`benchmarks/analysis/phase28_target_audit.json`](../benchmarks/analysis/phase28_target_audit.json).

## Implemented bounded recovery

- x64 entry-RSP stack slots are canonicalized across fixed `sub/add rsp` and push/pop changes, so argument spills and reloads keep the same base object and `ValueIdentity`.
- x86 cdecl/stdcall-style PUSH arguments and the existing limited register conventions continue through the same engine.
- Direct returns are summarized as `RETURNS_ARGUMENT`, `RETURNS_DERIVED_ARGUMENT`, or `RETURNS_SCALAR_RESULT`; overwritten return registers remain killed.
- Direct writes through an argument advance the existing object version. Simple arg0-derived stores through arg1 create a bounded output-parameter relation and are mapped back to the caller.
- `FunctionFlowSummary` results are cached per analyzed function relation. The existing call-depth, function, instruction, edge, value, alias, version and state caps remain; summary edges have an additional cap of 128 and report `BUDGET_LIMIT`.
- Repeated loads of the same `argv[n]` are retained as reactivation sites but share one canonical `ValueIdentity`. This fixes cases where string instructions or calls kill an earlier register definition.

No generic heap, alias, ABI, arithmetic-comparator, generated-code, or solver framework was added.

## Golf CompareSite root cause

Ground truth labels the four validation wrappers at `0x1E40`, `0x1F20`, `0x2000`, and `0x20E0`; it does not identify a static `cmp` instruction inside them. The actual sequence is:

```text
main 0x1D36 reloads argv[1] -> CALL 0x1E40 at 0x1D3A
wrapper spills arg0, reloads it, invokes a local non-RIP function pointer
wrapper stores AL, later reloads AL, and returns it
main executes MOVZX EAX,AL -> TEST EAX,EAX -> Jcc
```

The other three calls repeat the same shape at `0x1D5B`, `0x1D7C`, and `0x1D9D`. The wrapper prepares and invokes runtime-generated code; therefore there is no honest static `xor/test` or `sub/jz` comparison to detect inside the generated body.

The prior detector path covered imported comparators, static byte/custom loops and inline byte-immediate comparisons. Its first broken chain was the deduplicated early `argv[1]` register definition being killed before later reloads; after that, entry-RSP spill identity, local-indirect scalar return, and caller `movzx/test/jcc` semantics were also missing.

Classification: **RETURN_SEMANTICS + FUNCTION_BOUNDARY**. The minimal general fix recognizes only a source-reachable argument entering a local (non-IAT/RIP) indirect checker whose scalar result survives to the wrapper return and is immediately consumed by a caller branch/setcc/cmovcc. It reports the wrapper as the validation function and does not claim knowledge of generated comparison instructions.

All four Golf sinks now produce `RETURN_SEMANTICS` CompareSites, actionable ValidationCandidates, and `LIKELY_SLICE` results.

## Real benchmark gains

| Feature | Fixed FN |
|---|---:|
| Parameter provenance | 0 |
| Return provenance outside Golf | 0 |
| In-place/output provenance | 0 |
| Golf minimal return-semantics fix | 4 |

The first three mechanisms are covered by positive and negative fixtures but did not close another frozen public sink. They are not reported as benchmark capability gains. Golf accounts for the entire measured improvement.

Of the 14 audited fixable FN: **4 fixed, 10 still fixable, 0 reclassified out of scope**. Across the broader 18-FN baseline, the final 14 FN comprise those 10 fixable cases, 3 previously classified low-repairability static-visible cases, and 1 packed/out-of-scope case.

## Final metrics

Denominators remain 30 completed/rankable samples, 22 validation/slice sinks, and 21 static-visible sinks.

| Metric | Phase 2.7B | Phase 2.8 |
|---|---:|---:|
| Top-1 / Top-3 / Top-5 | 53.33 / 60.00 / 60.00% | **56.67 / 60.00 / 60.00%** |
| START coverage / precision | 43.33 / 100.00% | **46.67 / 100.00%** |
| Validation TP / FP / FN | 4 / 3 / 18 | **8 / 3 / 14** |
| Validation precision / recall | 57.14 / 18.18% | **72.73 / 36.36%** |
| Actionable Slice TP / FP / FN | 4 / 0 / 18 | **8 / 0 / 14** |
| Actionable Slice recall | 18.18% | **36.36%** |
| Complete Slice TP / FP / FN | 2 / 0 / 20 | **6 / 0 / 16** |
| Complete Slice recall | 9.09% | **27.27%** |
| Static-visible Actionable recall | 19.05% | **38.10%** |

New Validation FP: **0**. New actionable/complete Slice FP: **0**. START precision remains **100%**. Ranking stays at 2.2; Top-1 and START improve naturally from the new slices, not from weight changes.

## Performance and verification

Five equivalent final runs with source hash prefix `9c44761fb1e5` are saved as `benchmarks/results/phase28-final-v2-run1` through `phase28-final-v2-run5`.

| Run | Median | P90 | Max |
|---:|---:|---:|---:|
| 1 | 187.72 ms | 1183.84 ms | 1929.62 ms |
| 2 | 191.58 ms | 1179.31 ms | 1902.60 ms |
| 3 | 192.55 ms | 1184.53 ms | 1907.13 ms |
| 4 | 188.95 ms | 1162.69 ms | 1908.59 ms |
| 5 | 195.14 ms | 1179.15 ms | 1933.95 ms |

Median of medians: **191.58 ms**. P90 range: **1162.69–1184.53 ms**. No performance regression is observed against the Phase 2.7B repeated-run range; timing still includes ordinary host variance.

The suite contains 285 tests, including all 14 requested Phase 2.8 fixtures: x64/x86 argument identity, same/derived/overwritten returns, in-place mutation, output parameters, recursion budget, the Golf wrapper, bounded arithmetic evidence/negatives, cross-block live flags, and flags-killed rejection. Final statement coverage is **86%**.

## Remaining failures and marginal-return judgment

The remaining fixable cases are heterogeneous: optimized constraints, an obfuscated/static-linked comparator, incomplete exported-function validation semantics, date/argv provenance, and controller/object-flow closure. The additional non-fixable group remains packed/runtime-only or high-cost global/GUI/VM aliasing.

Phase 2.8 doubled actionable recall and tripled complete recall without new FP, so the round is a clear improvement. The gain is nevertheless concentrated in four sinks from one repeated Golf shape; the remaining cases no longer offer a comparable bounded, shared repair. Static Flow is complete enough for the product's static core, and further Phase 2.x work now has lower expected return than entering Phase 3.
