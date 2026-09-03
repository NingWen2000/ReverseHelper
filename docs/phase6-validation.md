# Phase 6 validation

This record covers the completed local v0.1.0 product. All PE targets were opened as data and were not executed.

## Automated regression

- Windows Python 3.13.5
- 136 tests passed
- 79% package coverage
- `compileall` passed for `reversehelper` and `scripts`
- `pip check`: no broken requirements
- sdist and wheel built as v0.1.0; the wheel installed in a separate environment and completed `--version` plus x86 quick-analysis smoke tests
- CLI smoke: default, quick, all seven `--only` values, report bundle and x64dbg export returned exit code 0
- Report smoke: Markdown, JSON and standalone HTML written; JSON reported Schema 1.2

## Local sample matrix

| Role | Architecture | SHA-256 | Observed result |
|---|---|---|---|
| Minimal HelloWorld | x86 | `e0b681459fa367db72f4fd2000da45ac099d41acb07aa6971adb00f5d86f5be` | Parsed and disassembled without warnings; MessageBoxA/ExitProcess imports retained |
| HelloWorld | x64 | `f9a3022d0bf803ff495a09616d62c985fe1399e3914defb5e2249761c2aab9a7` | Parsed and disassembled without warnings; no HIGH Validation/Anti-Debug/Crypto or HIGH target |
| Validation | x64 | `aab2e4d8a899e270216f59a4ad1fb1e590150908da6cc1c8f826a2b2b840f37d` | `ReadConsoleA` input at RVA `0x14D1`; user `strcmp` at RVA `0x1511` reached a HIGH Possible Validation Site and dynamic buffer question |
| Anti-Debug API | x64 | `b4d568a3505bdf50f9bdb3b2f073158a74d0b98eb6dc9040dbd478795765ab14` | `IsDebuggerPresent` call at RVA `0x1454` combined with TEST/Jcc into a HIGH candidate |
| PEB access | x64 | `a2cf29176040efe567f65f73d7ce4900f7202bece5aa8bf710d1b4a9ae397bd8` | GS-based PEB access remained LOW by itself; BeingDebugged and NtGlobalFlag reads were MEDIUM and their direct branches HIGH |
| TEA routine | x64 | `ef80ada85f51d0faa3cd231109f47f574e29744c3ee1f6f7fd421e7d9802fcfe` | Delta plus shifts/XOR/add/loop evidence produced a HIGH TEA-family candidate at RVA `0x146A` |
| UPX-packed HelloWorld | x64 | `b3b48d7c7aa4f834e97e36be68a24fc5a3c699a37b0661b4438a58b7f55913f8` | `UPX0/UPX1/UPX2` and entropy/permission evidence produced `likely-packed`; no virtual tail was disassembled |
| Indirect call/jump | x64 | `ef5f46c7addd787cd6d1decc9dbd0438a18ebc1fc91758b2f8b4db72cd6b8504` | Runtime-dependent call at RVA `0x1467` remained unresolved and produced a dynamic observation question |

The x64 C samples use the MinGW runtime. Its own PE-section `strncmp` chain was initially a HIGH false positive. A general MZ/PE structure-context rule now labels it `PE Structure Comparator Branch Candidate`, keeps it MEDIUM and prevents a HIGH target. Generic CRT indirect calls remain visible in `control_transfers`, while the ranked list caps control-flow-only targets to keep console and reports usable.

The UPX sample was produced from the local HelloWorld with the official UPX 5.2.0 Windows release. The downloaded archive SHA-256 was `b471ebf1b7f20f4a89150264ed9a008a2a5bfd247f3c6d1184a75bb59ca08f5d`.

## Public unknown samples

Two educational binaries were downloaded from public MIT-licensed repositories and were not executed:

| Source | Architecture | SHA-256 | Static result |
|---|---|---|---|
| `AvivShabtay/ReverseEngineering-challenge-1`, `setup_files/challenge.exe` | x86 | `d13c567583a5ecbc930d4673ceb0d4bd7345f0660c9ed675f448cc0053c474e0` | Four HIGH Possible Validation Sites at RVAs `0x19A9`, `0x19CE`, `0x19F3`, `0x1A18`; no module warnings |
| `PUXSY/Reverse-Engineering-CTF`, `Executables/CTF_Level8.exe` | x64 | `107db72033cadc03d9d06559b86544ee336f382b80d0b6b110b15b85d6b10525` | Actual `IsDebuggerPresent` call at RVA `0x2791`; runtime PE-structure `strncmp` at `0x3B15` correctly down-ranked; `memcmp` remains a MEDIUM call-site candidate; no module warnings |

Sources: <https://github.com/AvivShabtay/ReverseEngineering-challenge-1> and <https://github.com/PUXSY/Reverse-Engineering-CTF>.

Independent `objdump` inspection corroborated the local chains: all four x86 sites are `CALL strcmp → TEST EAX,EAX → JNE`; the x64 anti-debug site loads the IAT slot, calls through RAX and tests the return value; RVA `0x3B15` is followed by `TEST EAX,EAX → JNE`. This is static corroboration, not a runtime observation.

## Performance

The same Windows Python PE was analyzed five times through the Python API; medians are wall-clock values and include file parsing but not CLI process startup.

| Version/path | quick median | default median |
|---|---:|---:|
| v0.0.2 baseline | 0.074 s | 0.094 s |
| v0.1.0 local product | 0.074 s | 1.164 s |

The full path is intentionally heavier because it disassembles executable raw sections and runs instruction analyzers. quick did not regress and remains the structure-only path. Sharing Capstone details and import-call resolution reduced v0.1.0's measured full-analysis median from 1.50 s to 1.16 s on this target.

## Tool interoperability status

- x64dbg exporter: automated and CLI smoke tests passed; output uses `module:$RVA` and contains no Preferred ImageBase.
- Ghidra importer: automated tests passed for identity mismatch, filename fallback, current-image-base rebasing, default comments and out-of-range rejection.
- Ghidra/x64dbg live test: not performed because neither application was installed or registered on this host. No runtime breakpoint or CodeBrowser observation is claimed.

## Release gate

Code, tests, sample analysis, reports, package metadata and documentation are complete for v0.1.0. Live Ghidra import and x64dbg/x32dbg script loading remain explicitly documented external-tool validation limitations rather than unfinished source work.
