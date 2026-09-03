"""Generate ASLR-safe x64dbg breakpoint suggestions."""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from .findings import ReverseTarget


_MODULE_NAME = re.compile(r"[A-Za-z0-9_.-]+")


def generate_x64dbg_script(
    targets: Iterable[ReverseTarget],
    module_name: str,
    architecture: str,
) -> str:
    if architecture not in {"x86", "x86-64"}:
        raise ValueError(f"Unsupported x64dbg target architecture: {architecture}")
    if not _MODULE_NAME.fullmatch(module_name):
        raise ValueError("Module name contains characters unsafe for an x64dbg module expression")

    lines = [
        f"// ReverseHelper breakpoint suggestions for {module_name}",
        "// Module-relative RVAs keep these breakpoints valid when ASLR changes the load base.",
    ]
    seen_rvas: set[int] = set()
    for target in targets:
        if target.priority not in {"high", "medium"}:
            continue
        if target.rva is None or target.rva < 0 or target.rva in seen_rvas:
            continue
        seen_rvas.add(target.rva)
        expression = f"{module_name}:${target.rva:X}"
        category = re.sub(r"[^A-Za-z0-9]+", "_", target.category).strip("_") or "target"
        name = f"RH_{target.priority.upper()}_{category}_{target.rva:X}"
        comment = f"ReverseHelper {target.priority} {target.category} target"
        lines.append(f'bp {expression}, "{name}"')
        lines.append(f'cmt {expression}, "{comment}"')

    return "\n".join(lines) + "\n"


def write_x64dbg_script(
    targets: Iterable[ReverseTarget],
    module_name: str,
    architecture: str,
    path: str | Path,
) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        generate_x64dbg_script(targets, module_name, architecture),
        encoding="utf-8",
    )
    return target.resolve()
