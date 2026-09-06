"""ASCII/UTF-16LE extraction and rule-based triage."""

from __future__ import annotations

import re
from heapq import merge
from collections import Counter
from typing import Any


STRING_RULES: dict[str, tuple[re.Pattern[str], ...]] = {
    "url": (re.compile(r"https?://", re.I), re.compile(r"ftp://", re.I)),
    "command": (
        re.compile(r"\b(?:cmd\.exe|powershell(?:\.exe)?|wscript(?:\.exe)?|cscript(?:\.exe)?)\b", re.I),
        re.compile(r"\b(?:whoami|ipconfig|tasklist|netstat|certutil|bitsadmin)\b", re.I),
    ),
    "credential": (re.compile(r"\b(?:password|passwd|credential|secret|token|api[_-]?key)\b", re.I),),
    "debug": (re.compile(r"\b(?:debugger|isdebuggerpresent|ollydbg|x32dbg|x64dbg|windbg)\b", re.I),),
    "registry": (re.compile(r"HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)", re.I),),
    "file-path": (re.compile(r"[a-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\?)+", re.I),),
    "network": (
        re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        re.compile(r"\b(?:socket|user-agent|wininet|winsock)\b", re.I),
    ),
    "ctf": (re.compile(r"\b(?:flag|ctf|crackme|serial|license[_ -]?key)\b", re.I),),
}


def classify_string(value: str) -> list[str]:
    return [category for category, patterns in STRING_RULES.items() if any(p.search(value) for p in patterns)]


def _iter_ascii(data: bytes, minimum: int):
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % minimum)
    for match in pattern.finditer(data):
        yield match.start(), match.group().decode("ascii", errors="replace"), "ASCII"


def _iter_utf16le(data: bytes, minimum: int):
    # The boundary check avoids treating the last byte of a preceding ASCII
    # string as the first UTF-16LE character when the strings are adjacent.
    pattern = re.compile(rb"(?<![\x20-\x7e])(?:[\x20-\x7e]\x00){%d,}" % minimum)
    for match in pattern.finditer(data):
        yield match.start(), match.group().decode("utf-16le", errors="replace"), "UTF-16LE"


def extract_strings(data: bytes, minimum: int = 4, maximum: int = 2000, *, deduplicate: bool = True) -> dict[str, Any]:
    if minimum < 3:
        raise ValueError("minimum string length must be at least 3")
    if maximum < 1:
        raise ValueError("maximum string count must be positive")

    combined = merge(_iter_ascii(data, minimum), _iter_utf16le(data, minimum), key=lambda item: item[0])
    strings: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    category_counts: Counter[str] = Counter()
    truncated = False

    for offset, value, encoding in combined:
        key = (encoding, value)
        if deduplicate and key in seen:
            continue
        if len(strings) >= maximum:
            truncated = True
            break
        seen.add(key)
        categories = classify_string(value)
        category_counts.update(categories)
        strings.append(
            {
                "offset": offset,
                "encoding": encoding,
                "value": value,
                "categories": categories,
                "suspicious": bool(categories),
            }
        )

    interesting = [item for item in strings if item["suspicious"]]
    return {
        "minimum_length": minimum,
        "count": len(strings),
        "interesting_count": len(interesting),
        "category_counts": dict(sorted(category_counts.items())),
        "truncated": truncated,
        "items": strings,
        "interesting": interesting,
    }
