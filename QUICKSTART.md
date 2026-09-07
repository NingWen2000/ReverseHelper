# ReverseHelper Quick Start

ReverseHelper is an offline static triage tool for Windows PE CTF challenges. It reads the target; it never runs or uploads it.

## Portable Windows build

1. Extract the release ZIP.
2. Open PowerShell in the extracted folder.
3. Run:

```powershell
.\ReverseHelper.exe C:\path\to\challenge.exe
```

The first lines identify the target, architecture, packing/static visibility and the best supported place to start. Use a larger bounded pass only when Quick reports truncation or the result is insufficient:

```powershell
.\ReverseHelper.exe C:\path\to\challenge.exe --deep
```

Generate files only when needed:

```powershell
.\ReverseHelper.exe C:\path\to\challenge.exe --report reports
.\ReverseHelper.exe C:\path\to\challenge.exe --ghidra
```

For Ghidra, copy `ImportReverseHelperFindings.py` into a Ghidra script directory, open the matching binary, then run the script and select the generated `.reversehelper.json`. Import is comment/bookmark-only by default and checks SHA-256 or filename identity.

## Source install

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\reversehelper.exe C:\path\to\challenge.exe
```

Use only on files you are authorized to inspect. Packed, runtime-generated, managed, non-PE and heavily optimized code can exceed the static model; warnings and missing results must not be read as proof of absence.
