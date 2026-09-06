# Phase 3A Algorithm Recognition Report

## Result

Phase 3A adds a bounded, offline and evidence-based algorithm pass. It recognizes a deliberately small CTF-oriented set, attaches candidates to functions and static slices, and keeps Ranking at 2.2. It does not generate solvers or execute samples.

## Implementation audit

Reusable components were the existing constant scanner, Capstone instruction details, FunctionIndex/runtime classification, StaticSlice model, DataObject-compatible location records, Ranking 2.2 and Challenge Summary. The old TEA detector could only establish a family and the RC4 heuristic only recognized a permutation loop. There was no unified candidate, machine-readable evidence, explicit budget, slice relation or benchmark score.

The new `AlgorithmCandidate` records `id`, function identity, algorithm/family, HIGH/MEDIUM/LOW confidence, typed evidence, constants, structural features, related data objects and one of four slice relations. Evidence kinds include `MAGIC_CONSTANT`, `ROUND_COUNT`, `SHIFT_PATTERN`, `STATE_ARRAY`, `TABLE_SIZE`, `LOOP_STRUCTURE`, `OP_SEQUENCE` and `KEY_ACCESS_PATTERN`.

## Supported recognition

| Family | Published labels | Main evidence |
|---|---|---|
| Basic transform | SINGLE_XOR, REPEATING_KEY_XOR, ROLLING_XOR, XOR_CHAIN | loop, memory/index use, repeated XOR, key access/feedback |
| TEA family | TEA, XTEA, TEA_FAMILY, POSSIBLE_XXTEA | delta, round loop/count, shifts, add/XOR mix, indexed key/state structure |
| RC4 | RC4_KSA_CANDIDATE, RC4 | 256-byte state, modular index, indexed swap loop; PRGA/XOR raises confidence |
| Base64 | STANDARD_BASE64, CUSTOM_BASE64_ALPHABET | referenced 64-symbol alphabet plus 6-bit and 4:3 loop structure |
| Checksum | CRC32 | polynomial plus shift/XOR byte or bit loop |
| Other | TABLE_TRANSFORM, LCG, CUSTOM_WORD_TRANSFORM | indexed table flow; known multiplier/increment plus feedback; rotate/arithmetic/XOR loop |

A magic constant by itself remains LOW. Runtime-likely implementations are capped at LOW. Name strings are not used by production recognition.

## Slice, key/table and ranking integration

Candidate evidence locations are compared with transform instructions on StaticSlice. This avoids marking unrelated logic in a large inlined controller as on-slice merely because it shares a function. Related static tables are emitted with RVA, file offset, size, semantic and evidence; current semantics include `BASE64_ALPHABET`. No data is described as a correct flag key.

Challenge Summary shows HIGH candidates and on-slice MEDIUM candidates. Static paths insert algorithm nodes after their function. Ranking 2.2 receives an 18-point algorithm family only for MEDIUM/HIGH on-slice candidates; LOW and off-slice candidates are report-only, and existing runtime/evidence caps still apply.

## Quick strategy and budgets

Slice functions are analyzed first, followed by non-runtime functions. Defaults are 96 functions, 24,000 instructions and 32 table candidates. Truncation is explicit in `algorithm_analysis` and `analysis_warnings`. The pass remains static and uses already-decoded function instructions.

## Tests and false-positive controls

Phase 3A adds focused tests for TEA evidence thresholds, XOR classification, CRC constant false positives, RC4 KSA structure, ordinary 256 constants, XOR-heavy straight-line code, LCG constants/state feedback, custom rotate/add/XOR and budget truncation. Existing optimized fixture regression remains active. Full result: **294 passed, 86% coverage**; the new module has 83% statement coverage.

False-positive controls that materially changed during implementation:

- Generic `imul + add` LCG output was withdrawn; known multiplier/increment and loop feedback are now required.
- Generic three-index table output was withdrawn; direct static data evidence, at least four indexed accesses and no competing CRC structure are required.
- Function-level slice membership was downgraded to instruction-evidence proximity, preventing an off-path CRC in an inlined validation controller from being presented as on-slice.

## Public CTF benchmark

Only `xorkey-crackme` currently has algorithm ground truth precise enough for scoring. It is backed by author source/writeup and independently mapped static addresses. Other technique mentions without a confirmed algorithm address remain unscored.

| Metric | Result |
|---|---:|
| Algorithm TP / FP / FN | 2 / 0 / 0 |
| Algorithm precision / recall | 100% / 100% |
| On-Slice Algorithm precision | 100% (1 / 1) |
| XOR | 1 TP / 0 FP / 0 FN |
| CRC32 | 1 TP / 0 FP / 0 FN |

These percentages have a one-sample denominator and must not be generalized. Main remaining misses are algorithms without exact structural patterns, split KSA/PRGA across functions, optimized forms whose round count disappears, and custom transforms whose table address is indirect. The principal remaining false-positive risk is a large mixed-purpose function satisfying several independent but unrelated local patterns; instruction-level slice linkage limits homepage and ranking impact.

## Phase 2 regression and performance

The 30 successfully parsed public samples retain Top-1/3/5 **56.67% / 60.00% / 60.00%**, START coverage/precision **46.67% / 100%**, Validation **8 TP / 3 FP / 14 FN**, Complete Slice **6 TP / 0 FP / 16 FN**, and Actionable Slice **8 TP / 0 FP / 14 FN**. Ranking remains 2.2.

The final run measured median/P90/max Quick at approximately **190 / 1,258 / 1,856 ms**, compared with the Phase 2.8 five-run median-of-medians of 192 ms and P90 range 1,163–1,185 ms. Median is unchanged within normal run variance; the higher single-run P90 is not treated as a statistically stable regression claim.

## Gate

There are real public-CTF TP, no scored algorithm FP, 100% on-slice precision on the currently adjudicated sample, and no Phase 2 metric regression. The evidence is narrow but sufficient for the conservative first release.

**Proceed to Phase 3B.** Phase 3B has not been started.
