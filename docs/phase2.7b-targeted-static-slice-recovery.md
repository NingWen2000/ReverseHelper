# Phase 2.7B Targeted Static Slice Recovery Report

## Scope and result

Phase 2.7B implemented only the three repair families selected by Phase 2.7A: bounded `argv`/DLL-export sources, bounded static-linked comparators/thunks, and the two observed entry/body layouts. Ranking remains **2.2**. The manifest, ground truth, denominators, and budgets are unchanged from Phase 2.6 Final.

One actionable Slice FN was closed with no new Slice FP:

```text
Fixable static-visible FN: 15
Fixed:                     1
Remaining:                14
Repair rate:          1 / 15 = 6.67%

Actionable Slice TP: 3 -> 4
Actionable Slice FP: 0 -> 0
Actionable Slice FN: 19 -> 18
```

The repaired sink is `flareon2015-02:0x1084`. It required both the static comparator observation and the `0x1000` entry-prefix to `0x1001` body relationship. Other recovered sources and CompareSites remain intermediate evidence because their downstream provenance is incomplete.

## The 15 fixable FN

| Challenge / sink | Phase 2.7A cause | Phase 2.7B result |
|---|---|---|
| `flareon2015-02:0x1000` | Function boundary | ENTRY_STUB/BODY repaired; Slice still open |
| `flareon2015-02:0x1084` | Static comparator | **Fixed actionable Partial Slice** |
| `flareon2015-05:0x1100` | Optimized compare | Unchanged; outside selected causes |
| `flareon2015-09:0x1495` | Static comparator | Unresolved; no bounded two-stream shape |
| `flareon2016-01:0x1420` | Comparator/thunk | `0x2C30` CompareSite recovered; return provenance open |
| `flareon2016-03:0x27A0` | argv source | `argv[0]`/`argv[1]` recovered; Slice open |
| `flareon2016-04:0x2F50` | Export argument | DLL export arguments recovered; Slice open |
| `flareon2016-04:0x2E70` | Export argument | DLL export boundary recovered; Slice open |
| `flareon2017-03:0x1000` | Function boundary | `0x1000` stub + `0x1008` body repaired; Slice open |
| `flareon2017-06:0x5A50` | Date input | Unchanged; date sources not added |
| `flareon2018-10:0x1E40` | Early argv source | Early `argv[1]` recovered; CompareSite open |
| `flareon2018-10:0x1F20` | Early argv source | Early `argv[1]` recovered; CompareSite open |
| `flareon2018-10:0x2000` | Early argv source | Early `argv[1]` recovered; CompareSite open |
| `flareon2018-10:0x20E0` | Early argv source | Early `argv[1]` recovered; CompareSite open |
| `aviv-re-challenge-01:0x1350` | argv source | Still outside bounded CRT/main recovery |

The selected groups contain 9 input-source sinks, 3 comparator/thunk sinks, and 2 boundary sinks. The fifteenth case is the optimized constraint controller.

## 2.7B-1 — argv and export sources

The argv model supports x86 `[ebp+0xC]`, x64 ABI arguments saved and reloaded across RSP adjustment, fixed `argv[n]`, and dynamic `argv[*]`. Small constant index expressions are evaluated. Fixed indexes are `CONFIRMED`; dynamic indexes are `LIKELY`. Every source receives a dedicated `ValueIdentity` with `ARGV / ArgvObject#n` as its base object, and repeated loads of the same element in one function are deduplicated.

The x64 rule accepts a saved argc/argv main frame or a retained `main`/`wmain` identity. This excludes WinMain-family parameters and ordinary two-argument functions. CRT recovery is bounded to ABI argument structure, stack-slot normalization, calls, and function boundaries; it does not decompile CRT startup. If the structure is absent, no argv source is guessed.

DLL exports are eligible for `EXPORTED_ARGUMENT` only when a parameter is consumed by pointer-like or arithmetic validation/transform use. Scalar values that are only tested as handles/flags are not promoted. Export values use `ExportArgObject#function:index` identities and `CONFIRMED`/`LIKELY` confidence. Existing wrapper propagation is reused.

Audited-sink source coverage improved for 5 argv sinks (`flareon2016-03` plus four Golf sinks) and 2 export sinks (`flareon2016-04`). One Golf `argv[1]` source serves four calls, so this is sink coverage rather than seven unique source objects. The benchmark has no exhaustive InputSource TP/FP corpus; no synthetic source precision is claimed. Downstream safeguards stayed at 0 new Validation FP, 0 new actionable Slice FP, and unchanged START precision at this stage.

Saved stage: `benchmarks/results/phase27b-1-input-source-precision`.

```text
Top-1/3/5:              46.67 / 56.67 / 56.67%
START coverage/precision: 36.67 / 84.62%
Validation TP/FP/FN:     4 / 3 / 18
Actionable Slice:        3 TP / 0 FP / 19 FN
Quick median/P90/max: 269.47 / 1354.63 / 2660.14 ms
```

Final precision guards reduced the source inventory from that snapshot's 77 to 35 without removing the recovered audited evidence.

## 2.7B-2 — static comparator and thunk

The detector requires two memory streams (or x86 LODS/SCAS implicit streams), equal-width byte semantics, iterator progress, a bounded back edge, mismatch/equality exits, and a caller decision consuming the return where `STATIC_LINKED_COMPARATOR` is assigned. Wide loads feeding byte subregister comparisons are accepted only with a zero/nonzero return shape and caller decision.

Static comparator output records:

```text
compare_origin: STATIC_LINKED_COMPARATOR
comparator_function: <RVA>
thunk_chain: [<RVA> ...]
```

A direct-jump thunk can connect callers to the body but is not independently promoted. Comparator recognition creates comparison evidence; Validation still requires Compare → Decision → input provenance.

Audited CompareSite result: 2/3 repaired—`flareon2015-02:0x1084` and `flareon2016-01:0x2C30`; `flareon2015-09:0x1495` remains unresolved. The exhaustive benchmark does not have CompareSite ground truth, so the honest TP/FP statement is 2 audited TP, 0 observed new fixture FP, and 1 audited FN. A deliberately saved broad trial fell to 23.53% Validation precision; restricting wide-load recovery restored the baseline 57.14%.

Saved accepted stage: `benchmarks/results/phase27b-2-comparator-precision`.

```text
Validation TP/FP/FN:   4 / 3 / 18
Validation P/R:        57.14 / 18.18%
Actionable Slice:      3 TP / 0 FP / 19 FN
Static Slice emitted:  Confirmed 1 / Likely 2 / Partial 3
Quick median/P90/max: 209.70 / 1235.63 / 2635.63 ms
```

## 2.7B-3 — entry/body relations

| Case | Truth entry | Body | First wrong boundary | Minimal repair |
|---|---:|---:|---|---|
| `flareon2015-02` | `0x1000` | `0x1001` | `POP EAX` prefix split from adjacent prologue | Merge one return-register pop with the following heuristic prologue |
| `flareon2017-03` | `0x1000` | `0x1008` | Tiny PE entry call stub split from called body | Relate `CALL body; constant return` stub to a called frame-prologue body |

Both now use one existing `Function` with `ENTRY_STUB` and `BODY` chunks at `LIKELY` confidence. The body is removed as a separate owner; an internal stub-to-body call is removed from interprocedural propagation. No overlap or ambiguous ownership is added. A negative fixture keeps an entry call with subsequent non-constant computation separate.

Both logical boundary cases are repaired. Their combined downstream result is one new actionable Slice (`flareon2015-02:0x1084`), two new Top-1 hits (`flareon2015-02`, `flareon2017-03`), and no ranking pollution in the full benchmark.

## Baseline → stage → final

Denominators remain 30 ranking samples, 22 overall validation/slice sinks, and 21 static-visible slice sinks.

| Metric | Phase 2.6 | 2.7B-1 | 2.7B-2 | 2.7B-3 | Final |
|---|---:|---:|---:|---:|---:|
| Top-1 | 46.67% | 46.67% | 46.67% | 53.33% | 53.33% |
| Top-3 | 56.67% | 56.67% | 56.67% | 60.00% | 60.00% |
| Top-5 | 56.67% | 56.67% | 56.67% | 60.00% | 60.00% |
| START coverage | 36.67% | 36.67% | 36.67% | 43.33% | 43.33% |
| START precision | 84.62% | 84.62% | 84.62% | 100.00% | 100.00% |
| Validation TP/FP/FN | 4/3/18 | 4/3/18 | 4/3/18 | 4/3/18 | 4/3/18 |
| Validation P/R/F1 | 57.14/18.18/27.59% | same | same | same | same |
| Actionable Slice TP/FP/FN | 3/0/19 | 3/0/19 | 3/0/19 | 4/0/18 | 4/0/18 |
| Actionable recall | 13.64% | 13.64% | 13.64% | 18.18% | 18.18% |
| Complete Slice TP/FP/FN | 2/0/20 | 2/0/20 | 2/0/20 | 2/0/20 | 2/0/20 |
| Complete recall | 9.09% | 9.09% | 9.09% | 9.09% | 9.09% |
| Static-visible actionable recall | 14.29% | 14.29% | 14.29% | 19.05% | 19.05% |
| Static-visible complete recall | 9.52% | 9.52% | 9.52% | 9.52% | 9.52% |
| Packed visibility accuracy | 86.67% | 86.67% | 86.67% | 86.67% | 86.67% |
| Quick median ms | 212.70 | 269.47 | 209.70 | 217.75 | 306.81 |
| Quick P90 ms | 1145.96 | 1354.63 | 1235.63 | 1215.67 | 1517.66 |
| Quick max ms | 2080.94 | 2660.14 | 2635.63 | 2620.30 | 2321.60 |

Final output is `benchmarks/results/phase27b-final-regression-v10`:

```text
Static Slice emitted: Confirmed 1 / Likely 2 / Partial 4 / Unresolved 144
Actionable scoring:   TP 4 / FP 0 / FN 18
Complete scoring:     TP 2 / FP 0 / FN 20
Input sources:        35
Quick:                median 306.81 / P90 1517.66 / max 2321.60 ms
```

The latest run is +44.25% median, +32.44% P90, and +11.56% max versus the historical Phase 2.6 run. Repeated equivalent final runs were unstable: median 200.70–306.81 ms, P90 1211.28–1517.66 ms, and ordinary max 1996.07–2489.12 ms. Another run contained a 437-second system outlier; immediate replay of that sample completed in 123.92 ms. Candidate caches, Console-subsystem filtering, and source deduplication reduced sources from 43 to 35, and one final run beat the Phase 2.6 median/max, so there is no consistent analyzer-cost regression. The cross-run noise prevents claiming a measured speed improvement and makes the latest-run Quick guard inconclusive.

## Tests, coverage, and files

Final regression: **271 passed**, **86% statement coverage**.

Coverage includes x86/x64 argv, fixed/dynamic indexes, DLL export buffer/transform parameters, scalar export flags negative, static strcmp structure, ordinary counter-loop negative, comparator caller decisions, thunk metadata, both entry/body layouts, and a boundary negative. `tests/fixtures/phase27_targeted_recovery.c` contains all requested named shapes and is compiled as PE at `-O1` and `-O2`.

Console EXEs that do not yield a reliable argv seed now emit `ARGV_SOURCE_UNRESOLVED` in `input_source_diagnostics`; the diagnostic does not participate in Ranking, Validation, or Slice publication.

Production files modified for this phase:

- `reversehelper/input_sources.py`
- `reversehelper/validation_analyzer.py`
- `reversehelper/findings.py`
- `reversehelper/function_index.py`
- `reversehelper/static_slice.py`
- `reversehelper/quick_analysis.py`

Tests modified: `tests/test_input_sources.py`, `tests/test_validation_decision_v2.py`, and `tests/test_function_boundary_v2.py`.

Files added: `tests/fixtures/phase27_targeted_recovery.c`, `tests/test_phase27_targeted_compiled_fixtures.py`, and this report. Stage and precision-trial benchmark directories are also retained. The existing `ValueIdentity` and InputWrapper systems were reused rather than replaced.

## Remaining FN and Phase 3 gate

The final 18 actionable FN are 14 remaining realistically fixable static-visible cases, 3 low-repairability static-visible cases, and 1 packed/out-of-scope case. No new Validation FP, actionable Slice FP, START FP, or benchmark FN was introduced.

The strongest remaining fixable blockers are return/argument provenance into recovered comparators, missing CompareSites in the four Golf checkers, the obfuscated arithmetic body at `flareon2015-09`, the optimized constraint controller at `flareon2015-05`, and unclosed controller semantics behind the repaired entry/body relations.

Ranking stays at 2.2: the ranking gain comes from real function identity and Slice evidence, not weight changes.

Phase 3 remains **FROZEN**. Only 1/15 fixable Slice FN was closed, Complete Slice recall did not improve, and Validation recall remains 18.18%. A future narrow recovery phase should first prove it can close return/argument provenance and the four bounded Golf checker compares without broad algorithm recognition.
