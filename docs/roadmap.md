# ReverseHelper roadmap

This file records work deliberately left outside v0.1.0. It is not a release commitment.

## Interoperability verification

- Run `ImportReverseHelperFindings.py` across supported Ghidra/Jython environments and record actual Comment/RVA behavior.
- Load generated scripts in both x64dbg and x32dbg and verify module-name edge cases.

## Candidate quality

- Explore lightweight compiler/runtime identification so ranked targets can prefer application code without hiding complete control-transfer records.
- Evaluate additional argument evidence for Input/Validation linkage without claiming full data flow.

## Deferred analysis

CFG, SSA, taint analysis, symbolic execution, automatic unpacking and automatic patching remain out of scope until a concrete use case justifies their cost and data-model impact.
