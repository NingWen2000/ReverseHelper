# ReverseHelper

> Offline-first static reverse-engineering workbench for CTF competitors.

[![Tests](https://github.com/NingWen2000/ReverseHelper/actions/workflows/tests.yml/badge.svg)](https://github.com/NingWen2000/ReverseHelper/actions/workflows/tests.yml)
[![Version](https://img.shields.io/badge/version-0.2.0b1-blue.svg)](https://github.com/NingWen2000/ReverseHelper/releases/tag/v0.2.0b1)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Current release: **0.2.0b1 (Beta)**. Phase 1–4 are complete and closed; Phase 5 is not required to use this version.

ReverseHelper turns an unknown Windows PE into an actionable first-pass map: where input enters, where it may be transformed or validated, what algorithm/control-flow evidence exists, and where to start in Ghidra or IDA. It reads the target locally and never executes or uploads it.

## Start in one command

```powershell
reversehelper .\challenge.exe
```

The default is bounded Quick Analysis. Its first screen prioritizes:

- target, architecture, packing and static visibility;
- `START HERE` or several honest starting points;
- input flow, static path or `FLOW BREAK`, and likely validation;
- algorithm/control-flow candidates and concrete next actions;
- coverage warnings and a `--deep` prompt only when useful.

Use Deep for broader static coverage through the same analyzers and JSON contract:

```powershell
reversehelper .\challenge.exe --deep
```

Generate artifacts explicitly:

```powershell
reversehelper .\challenge.exe --report .\reports
reversehelper .\challenge.exe --ghidra
reversehelper .\challenge.exe --json .\reports\challenge.json
```

`--ghidra` writes `reports\challenge.reversehelper.json`. Run the bundled `ImportReverseHelperFindings.py` in the matching Ghidra program to add identity-checked comments/bookmarks. No rename is automatic.

See [Quick Start](QUICKSTART.md), [full user manual](docs/ReverseHelper-0.2.0b1-User-Manual.md), [Word manual](docs/ReverseHelper-0.2.0b1-User-Manual.docx), [competition workflow](docs/workflow.md), [usage](docs/usage.md), and [limitations](docs/limitations.md).

## What it can do

- parse PE32/PE32+ identity, sections, imports/exports and entry point;
- classify useful strings and connect XREFs to functions;
- recover bounded function boundaries and logical chunks;
- identify common input sources, comparison/decision sites and conservative input-to-validation slices;
- report the last proven point as `FLOW BREAK` when static tracking is lost;
- rank review targets with evidence families, caps and runtime/packed penalties (Ranking 2.2);
- recognize bounded XOR/rolling transforms, CRC/TEA-family/RC4/AES/Base64/table evidence;
- explain selected switch tables, dispatchers, state-machine and indirect-control structures;
- emit review-only semantic suggestions for decompiler cleanup;
- export Markdown, HTML, stable JSON, Ghidra annotations and ASLR-safe x64dbg suggestions.

These are static candidates, not solved challenges. Missing output is not proof of absence.

## Windows x64 portable package

Download `ReverseHelper-0.2.0b1-win-x64.zip` from the [v0.2.0b1 release](https://github.com/NingWen2000/ReverseHelper/releases/tag/v0.2.0b1), verify the published SHA-256 when practical, and extract the ZIP to a writable folder. No Python installation is required.

Open PowerShell in the extracted folder and confirm the version:

```powershell
.\ReverseHelper.exe --version
.\ReverseHelper.exe "C:\CTF\Challenges\challenge.exe"
```

The package also contains `QUICKSTART.md` and the Ghidra importer `ImportReverseHelperFindings.py`.

### Previous releases

Older versions remain available for reproducing earlier write-ups, testing compatibility, or comparing behavior:

| Version | Download |
|---|---|
| `v0.1.0` | [Release page and source archives](https://github.com/NingWen2000/ReverseHelper/releases/tag/v0.1.0) |
| `v0.0.2` | [Windows ZIP](https://github.com/NingWen2000/ReverseHelper/releases/download/v0.0.2/ReverseHelper-v0.0.2.zip) · [Release page](https://github.com/NingWen2000/ReverseHelper/releases/tag/v0.0.2) |
| `v0.0.1` | [Windows ZIP](https://github.com/NingWen2000/ReverseHelper/releases/download/v0.0.1/ReverseHelper-v0.0.1.zip) · [Release page](https://github.com/NingWen2000/ReverseHelper/releases/tag/v0.0.1) |

The complete archive is available on the [GitHub Releases page](https://github.com/NingWen2000/ReverseHelper/releases). Existing release tags and downloadable files are retained.

## Install from source

Python 3.10+ is required:

```powershell
git clone https://github.com/NingWen2000/ReverseHelper.git
cd ReverseHelper
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\reversehelper.exe .\challenge.exe
```

For a release build:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[release]"
.\scripts\build-portable.ps1
```

The resulting Windows x64 ZIP contains a single executable, quick start, license and Ghidra importer. Runtime installation, account, API key, network and LLM are not required.

## Measured status

The public benchmark has 40 fixed slots: 31 available/frozen and 9 honestly pending. The latest pre-productization Phase 3 baseline completed 30 analyzable entries plus one intentional malformed parser case:

| Metric | Result |
|---|---:|
| Top-1 / Top-3 / Top-5 critical function | 56.67% / 60.00% / 60.00% |
| START HERE emitted precision | 100% |
| Validation TP / FP / FN | 8 / 3 / 14 |
| Actionable Slice TP / FP / FN | 8 / 0 / 14 |
| Algorithm TP / FP / FN | 2 / 0 / 0 |
| Control-flow TP / FP / FN | 1 / 0 / 0 |
| Semantic role TP / FP / FN | 3 / 0 / 0 |

Algorithm/control-flow/semantic denominators are too small for broad accuracy claims. Human TTCF has not yet been measured; the [protocol and empty template](benchmarks/ttcf_protocol.md) are ready, but no reduction is claimed. Full definitions, strata, failures and historical runs are in the [benchmark documentation](benchmarks/README.md).

## Scope and safety

Core analysis is offline and static. ReverseHelper does not unpack, emulate, symbolically execute, auto-solve, patch, or replace the reverser. Dynamic observation belongs to TraceInfer. IDA-specific deep integration and solver generation are deliberately deferred until evidence shows they reduce TTCF without misleading users.

Development status: **v0.2.0b1 Beta**. Phase 1–4 are complete and closed. This is a usable beta, not a 1.0 claim; independent clean-Windows validation, real Ghidra UI re-import validation and human TTCF measurements remain evidence to collect.

## Development

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [roadmap](docs/roadmap.md), and [CHANGELOG.md](CHANGELOG.md). Licensed under [MIT](LICENSE).
