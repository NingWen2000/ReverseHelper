# Phase 4 — Competition-Grade Integration & Productization

Date: 2026-09-06  
Candidate: `0.2.0b1`  
Final gate: **Outcome B — Core workflow is strong enough, but real-user / real-environment validation is still needed.**

## 1. Product Workflow Audit

The shipped primary path is now one command:

`challenge.exe -> reversehelper challenge.exe -> Challenge Summary -> Ghidra/IDA -> manual reversing`

Before Phase 4 the default already called Quick, but help and front-page documentation described older phases, there was no Deep profile, reports were easier to discover than the actual handoff, and Ghidra annotations were assembled by multiple independent paths. The first screen also omitted the filename, explicit static visibility, a direct validation line and a clear truncation/Deep decision.

The corrected first screen keeps START/input/slice or FLOW BREAK/validation/algorithm/control-flow/next action. Raw sections, imports, low-confidence observations, scoring internals and full evidence remain in explicit reports or verbose output. Legacy `--only` is retained for diagnosis and compatibility, not promoted as the normal workflow.

## 2. Integration decisions

- Default and `--quick` use the same bounded pipeline.
- `--deep` invokes the same analyzers and Schema 1.5, with a central `AnalysisBudget`: larger byte/instruction/function/data-flow/algorithm/CFG/semantic caps, 8 s per-stage soft budget and 30 s whole-analysis start deadline. Quick uses 2 s/8 s. In-stage count limits are hard bounds; the deadline prevents later expensive stages from starting after the limit.
- Optional stage failures remain isolated. `module_timings_ms`, `truncated_modules`, `analysis_warnings` and `result_status` expose coverage honestly.
- Ranking stays at 2.2. No result supports a ranking-policy change.
- Stable JSON retains existing fields and adds `annotations`, generic `analysis_elapsed_ms`, coverage status and explicit fact/candidate/suggestion definitions.
- `--ghidra [FILE]` writes the same complete JSON. The importer prefers unified annotations and falls back to legacy findings/targets for older reports.
- Unified markers cover `RH:START`, `RH:INPUT`, `RH:SLICE`, `RH:VALIDATION`, `RH:ALGORITHM`, `RH:FLOW_BREAK`, control-flow/dispatcher markers and `RH:SUGGEST_*`. Import remains identity-checked and comment/bookmark-only by default.
- IDA-specific deep integration is deferred. A second unvalidated importer would add maintenance without demonstrated TTCF gain; the generic annotation schema is the intended boundary.
- Solver skeleton generation is deferred. Public algorithm adjudication covers only one sample and actionable slice recall remains 36.36%; generating runnable-looking guesses would be misleading.

## 3. Benchmark

All five Quick runs and the Deep run use source snapshot `adf02d37df6b`, the same frozen manifest and 31 available records. Each run completed 30 normal samples and isolated the intentional corrupt-signature parser case. Nine fixed slots remain pending; no low-quality samples were added to reach 40.

| Run | Median | P90 | Max |
|---|---:|---:|---:|
| Quick 1 | 265.13 ms | 1504.22 ms | 2457.98 ms |
| Quick 2 | 294.66 ms | 1462.05 ms | 2333.45 ms |
| Quick 3 | 285.11 ms | 1447.57 ms | 2523.03 ms |
| Quick 4 | 276.72 ms | 1378.31 ms | 2600.92 ms |
| Quick 5 | 289.22 ms | 1506.12 ms | 2668.88 ms |
| Deep | 302.29 ms | 6090.92 ms | 9754.87 ms |

Quick median-of-medians is **285.11 ms**; P90 range is **1378.31–1506.12 ms**. Quick accuracy was stable in all five runs: Top-1/3/5 **56.67% / 60.00% / 60.00%**, START HERE emitted precision **100%**, Validation **8/3/14**, Actionable Slice **8/0/14**, Algorithm **2/0/0**, control flow **1/0/0**, semantic roles **3/0/0**.

Deep kept Top-1/3/5 and Slice results unchanged, improved adjudicated function-start recall from 83.64% to 85.45%, but changed Validation to **8/4/14** and raised P90 to 6.09 s. This is direct evidence for keeping Quick as the default and describing Deep as broader coverage, not higher accuracy.

Full records are in `benchmarks/results/phase4-quick-run-{1..5}` and `benchmarks/results/phase4-deep`.

## 4. Product validation

- **Automated tests:** 324 passed; source coverage 87%.
- **Offline regression:** a socket-denial test completed Quick and JSON export with no connection attempt.
- **Malformed input:** portable CLI returned a concise missing-MZ error and exit code 2 without traceback.
- **Packed behavior:** existing strategy keeps limited-visibility warnings and post-unpack guidance; benchmark packed detection remains 2/6 recall, so this limitation is prominent.
- **Portable build:** PyInstaller Windows x64 one-file build succeeded. The executable ran `--version` and analyzed a real frozen public PE to JSON without Python installation through the packaged entry point.
- **Package size:** final executable 14,313,899 bytes; ZIP 14,047,913 bytes (SHA-256 `FE3995C92A49926BD5DE8204ECE3B3B9BF8404B093A7D02B09A11D7668C2DD9F`). Five `--version` process starts were 694.99–889.26 ms on the build host.
- **Ghidra:** importer compilation, identity, mapping, rebasing, unified annotation and no-auto-rename behavior are automated. Actual Ghidra CodeBrowser UI import remains a clean-environment manual gate.
- **TTCF:** protocol and CSV schema exist; no participant rows were fabricated. Median TTCF and reduction remain pending.

## 5. Release checklist

| Check | Status |
|---|---|
| Default Quick and explicit Deep | PASS |
| Same analyzers/schema; Ranking 2.2 | PASS |
| JSON/report/Ghidra export | PASS (automated/import planner) |
| Offline core and report generation | PASS (network-denial regression) |
| Malformed input graceful failure | PASS |
| Packed limited-visibility behavior | PASS with low-recall limitation |
| Windows x64 portable build and local smoke | PASS |
| Clean Windows machine without Python | PENDING external machine |
| Actual Ghidra UI import/re-import | PENDING external application validation |
| IDA deep integration | DEFERRED by product decision |
| Solver skeleton | DEFERRED by evidence gate |
| Human TTCF experiment | PENDING participants |

## 6. Gate and version recommendation

The core competition workflow is integrated, documented, bounded, reproducible and locally portable. However, a 1.0 or “ready for real competition use” claim would overstate the evidence because the portable artifact has not been exercised on a separate clean Windows machine, the Ghidra workflow lacks real UI validation, packed recall is low, and TTCF has no human measurements.

Therefore Phase 4 closes with **Outcome B** and the recommended version is **`0.2.0b1`**. Phase 5 is not started.
