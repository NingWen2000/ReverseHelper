# TTCF experiment protocol

TTCF is the elapsed wall time from revealing a challenge and its allowed tools to the participant identifying the first ground-truth critical function with an address and one-sentence rationale.

Use a small randomized crossover study. Each participant solves comparable unseen challenges in two conditions: normal Ghidra/IDA workflow and ReverseHelper Quick followed by the same reverse-engineering tool. Counterbalance condition order, keep hardware and time limit fixed, and exclude challenges the participant has previously solved.

Record participant pseudonym, challenge id, condition, start/end timestamps or elapsed seconds, success, submitted RVA, ground-truth match, tool version, interruptions and notes. Keep failures/timeouts in the denominator. Report sample count, median and distribution for each condition plus paired deltas; do not infer a reduction from analyzer runtime.

The repository contains only the empty recording template. Phase 4 has no human observations, so Median TTCF and TTCF reduction remain pending.
