"""Rich terminal presentation."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .version import __version__


def _hex(value: int | None) -> str:
    return "N/A" if value is None else f"0x{value:X}"


def _print_finding_group(
    result: dict[str, Any],
    categories: set[str],
    title: str,
    console: Console,
    limit: int = 8,
) -> None:
    confidence_order = {"high": 0, "medium": 1, "low": 2}
    findings = [
        finding
        for finding in result.get("findings", [])
        if finding["category"] in categories and finding["confidence"] in {"high", "medium"}
    ]
    findings.sort(
        key=lambda item: (
            confidence_order[item["confidence"]],
            item["rva"] is None,
            item["rva"] or 0,
        )
    )
    if not findings:
        return

    table = Table(title=title, border_style="magenta")
    table.add_column("Confidence")
    table.add_column("RVA", justify="right")
    table.add_column("Section")
    table.add_column("Candidate", overflow="fold", max_width=72)
    for finding in findings[:limit]:
        table.add_row(
            finding["confidence"].upper(),
            _hex(finding["rva"]),
            finding.get("section") or "-",
            finding["title"],
        )
    console.print(table)
    if len(findings) > limit:
        console.print(f"[dim]Showing {limit} of {len(findings)} candidates; reports contain all findings.[/dim]")


def _print_reverse_guidance(result: dict[str, Any], console: Console) -> None:
    targets = [
        target
        for target in result.get("reverse_targets", [])
        if target["priority"] in {"high", "medium"}
    ]
    if targets:
        table = Table(title="Recommended Reverse Targets", border_style="cyan")
        table.add_column("Priority")
        table.add_column("RVA", justify="right")
        table.add_column("Category")
        table.add_column("Reason", overflow="fold", max_width=70)
        for target in targets[:10]:
            table.add_row(
                target["priority"].upper(),
                _hex(target["rva"]),
                target["category"],
                target["reason"],
            )
        console.print(table)
        if len(targets) > 10:
            console.print(f"[dim]Showing 10 of {len(targets)} HIGH/MEDIUM targets.[/dim]")

    questions = result.get("unresolved_questions", [])
    if questions:
        table = Table(title="Unresolved Questions", border_style="yellow")
        table.add_column("RVA", justify="right")
        table.add_column("Question", overflow="fold", max_width=84)
        for item in questions[:8]:
            table.add_row(_hex(item["related_rva"]), item["question"])
        console.print(table)
        if len(questions) > 8:
            console.print(f"[dim]Showing 8 of {len(questions)} unresolved questions.[/dim]")

    warnings = result.get("analysis_warnings", [])
    if warnings:
        table = Table(title="Analysis Warnings", border_style="yellow")
        table.add_column("Module")
        table.add_column("Error")
        table.add_column("Reason", overflow="fold", max_width=80)
        for warning in warnings:
            table.add_row(warning["module"], warning["error_type"], warning["reason"])
        console.print(table)


def print_analysis(result: dict[str, Any], console: Console | None = None) -> None:
    console = console or Console()
    basic = result["basic"]
    risk = result["risk"]
    risk_color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}[risk["level"]]

    console.print(
        Panel.fit(
            f"[bold cyan]ReverseHelper[/bold cyan] [dim]v{__version__}[/dim]\n"
            "[dim]Static Windows PE triage - target is never executed[/dim]",
            border_style="cyan",
        )
    )

    overview = Table(title="Basic information", show_header=False, border_style="blue")
    overview.add_column("Field", style="bold")
    overview.add_column("Value")
    for label, value in (
        ("File", f"{basic['file_name']} ({basic['file_size']} bytes)"),
        ("Type", basic["file_type"]),
        ("Architecture", basic["architecture"]),
        ("ImageBase", _hex(basic["image_base"])),
        (
            "EntryPoint",
            f"RVA {_hex(basic['entry_point_rva'])} / VA {_hex(basic['entry_point_va'])} / "
            f"RAW {_hex(basic['entry_point_offset'])}",
        ),
        ("Subsystem", basic["subsystem"]),
        ("SHA-256", result["hashes"]["sha256"]),
    ):
        overview.add_row(label, str(value))
    console.print(overview)

    entry = result.get("entry_point_analysis")
    if entry and (entry["pattern"] or entry["indicators"]):
        details = [f"Bytes: {entry['bytes_hex']}"]
        if entry["pattern"]:
            details.append(f"Pattern: {entry['pattern']}")
        if entry["control_transfer_target_va"] is not None:
            details.append(
                f"First transfer: RVA {_hex(entry['control_transfer_target_rva'])} / "
                f"VA {_hex(entry['control_transfer_target_va'])}"
            )
        details.extend(item["evidence"] for item in entry["indicators"])
        console.print(Panel("\n".join(details), title="Entry-point review", border_style="yellow"))

    sections = Table(title="Sections", border_style="blue")
    sections.add_column("Name")
    sections.add_column("RVA", justify="right")
    sections.add_column("Raw size", justify="right")
    sections.add_column("Perms", justify="center")
    sections.add_column("Entropy", justify="right")
    sections.add_column("Flags")
    for section in result["sections"]:
        flags = []
        if section["high_entropy"]:
            flags.append("[yellow]HIGH-ENTROPY[/yellow]")
        if section["rwx"]:
            flags.append("[red]RWX[/red]")
        sections.add_row(
            section["name"],
            _hex(section["virtual_address"]),
            _hex(section["raw_size"]),
            section["permissions"],
            f"{section['entropy']:.3f}",
            " ".join(flags) or "-",
        )
    console.print(sections)

    caves = result.get("code_caves", [])
    if caves:
        cave_table = Table(title="Executable-section padding (manual review)", border_style="yellow")
        cave_table.add_column("Section")
        cave_table.add_column("File", justify="right")
        cave_table.add_column("RVA", justify="right")
        cave_table.add_column("VA", justify="right")
        cave_table.add_column("Size", justify="right")
        cave_table.add_column("Fill")
        for cave in caves[:10]:
            cave_table.add_row(
                cave["section"],
                _hex(cave["file_offset"]),
                _hex(cave["rva"]),
                _hex(cave["va"]),
                _hex(cave["size"]),
                cave["fill_byte"],
            )
        console.print(cave_table)
        console.print("[dim]Padding is only a patch candidate; verify references and mapped size before use.[/dim]")

    imported_libraries = len(result["imports"])
    console.print(
        f"\n[bold]Imports:[/bold] {result['import_count']} functions from {imported_libraries} libraries / "
        f"[bold]Exports:[/bold] {result['export_count']}"
    )
    if result["suspicious_imports"]:
        suspicious = Table(title="Rule-matched APIs", border_style="yellow")
        suspicious.add_column("DLL")
        suspicious.add_column("API")
        suspicious.add_column("Category")
        suspicious.add_column("Severity")
        for item in result["suspicious_imports"]:
            suspicious.add_row(item["dll"], item["name"], item["category"], item["severity"])
        console.print(suspicious)

    interesting = result["strings"]["interesting"]
    if interesting:
        string_table = Table(title=f"Interesting strings ({len(interesting)})", border_style="yellow")
        string_table.add_column("File / RVA", justify="right")
        string_table.add_column("Section")
        string_table.add_column("Type")
        string_table.add_column("Value", overflow="fold", max_width=90)
        for item in interesting[:30]:
            string_table.add_row(
                f"{_hex(item['offset'])} / {_hex(item.get('rva'))}",
                item.get("section") or "overlay",
                ",".join(item["categories"]),
                item["value"][:300],
            )
        console.print(string_table)
        if len(interesting) > 30:
            console.print(f"[dim]Showing 30 of {len(interesting)} interesting strings. Reports contain up to 100.[/dim]")

    if result["crypto_constants"]:
        crypto = Table(title="Cryptographic constants", border_style="magenta")
        crypto.add_column("Algorithm")
        crypto.add_column("Constant")
        crypto.add_column("Confidence")
        crypto.add_column("Offsets")
        for item in result["crypto_constants"]:
            crypto.add_row(
                item["algorithm"],
                item["constant"],
                item["confidence"],
                ", ".join(_hex(offset) for offset in item["offsets"]),
            )
        console.print(crypto)

    _print_finding_group(result, {"anti-debug"}, "Anti-Debug Findings", console)
    _print_finding_group(result, {"crypto"}, "Crypto Candidates", console)
    _print_finding_group(result, {"validation", "input"}, "Validation Candidates", console)
    _print_reverse_guidance(result, console)

    packing = result["packing"]
    if packing["indicators"]:
        console.print("\n[bold]Packing/anomaly indicators[/bold]")
        for item in packing["indicators"]:
            color = "red" if item["severity"] == "high" else "yellow"
            console.print(f"  [{color}]-[/{color}] {item['evidence']}")
    else:
        console.print("\n[green]No obvious packing indicators detected.[/green]")

    summary = Text()
    summary.append("Risk score  ", style="bold")
    summary.append(f"{risk['score']}/10  {risk['level']}", style=risk_color)
    summary.append("\nTriage only - verify findings manually in Ghidra/x64dbg.", style="dim")
    if result.get("debugger_export_notice"):
        summary.append(f"\n{result['debugger_export_notice']}", style="dim")
    console.print(Panel(summary, border_style=risk_color.split()[-1]))


def print_quick_analysis(result: dict[str, Any], console: Console | None = None) -> None:
    console = console or Console()
    basic = result["basic"]
    packing = result["packing"]
    risk = result["risk"]

    console.print(
        Panel.fit(
            f"[bold cyan]ReverseHelper[/bold cyan] [dim]v{__version__}[/dim]\n"
            "[dim]Quick structural PE triage - strings, crypto and code caves skipped[/dim]",
            border_style="cyan",
        )
    )
    overview = Table(title="Quick analysis", show_header=False, border_style="blue")
    overview.add_column("Field", style="bold")
    overview.add_column("Value")
    overview.add_row("File", f"{basic['file_name']} ({basic['file_size']} bytes)")
    overview.add_row("Type", basic["file_type"])
    overview.add_row("Architecture", basic["architecture"])
    overview.add_row("EntryPoint", f"RVA {_hex(basic['entry_point_rva'])} / VA {_hex(basic['entry_point_va'])}")
    overview.add_row("Sections", str(len(result["sections"])))
    overview.add_row("Imports / Exports", f"{result['import_count']} / {result['export_count']}")
    overview.add_row("Packing verdict", packing["verdict"])
    overview.add_row("Structural risk", f"{risk['score']}/10 {risk['level']}")
    overview.add_row("SHA-256", result["hashes"]["sha256"])
    console.print(overview)

    if packing["indicators"]:
        indicators = Table(title="Packing/anomaly indicators", border_style="yellow")
        indicators.add_column("Severity")
        indicators.add_column("Type")
        indicators.add_column("Evidence", overflow="fold")
        for item in packing["indicators"]:
            indicators.add_row(item["severity"], item["type"], item["evidence"])
        console.print(indicators)
    else:
        console.print("[green]No obvious packing indicators detected.[/green]")


def print_module_analysis(result: dict[str, Any], module: str, console: Console | None = None) -> None:
    console = console or Console()
    console.print(
        Panel.fit(
            f"[bold cyan]ReverseHelper[/bold cyan] [dim]v{__version__}[/dim]\n"
            f"[dim]Single-module analysis: {module} - target is never executed[/dim]",
            border_style="cyan",
        )
    )

    if module in {"antidebug", "validation", "crypto", "targets"}:
        console.print(
            f"[bold]Decoded instructions:[/bold] {result.get('disassembly', {}).get('instruction_count', 0)}"
        )
        categories = {
            "antidebug": {"anti-debug"},
            "validation": {"validation", "input"},
            "crypto": {"crypto"},
            "targets": {"anti-debug", "crypto", "validation", "input", "control-flow", "entry"},
        }[module]
        _print_finding_group(result, categories, f"{module.title()} Findings", console, limit=12)
        if module == "targets":
            _print_reverse_guidance(result, console)
        elif result.get("analysis_warnings"):
            _print_reverse_guidance(result, console)
        return

    if module == "imports":
        imports = Table(title=f"Imports ({result['import_count']})", border_style="blue")
        imports.add_column("DLL")
        imports.add_column("API")
        imports.add_column("IAT", justify="right")
        imports.add_column("Rule match")
        for library in result["imports"]:
            for item in library["functions"]:
                rule = item.get("category", "-") if item["suspicious"] else "-"
                imports.add_row(library["dll"], item["name"], _hex(item["iat_address"]), rule)
        console.print(imports)
        return

    if module == "strings":
        strings = result["strings"]
        table = Table(title=f"Extracted strings ({strings['count']})", border_style="blue")
        table.add_column("File / RVA", justify="right")
        table.add_column("Section")
        table.add_column("Encoding")
        table.add_column("Categories")
        table.add_column("Value", overflow="fold", max_width=90)
        for item in strings["items"][:100]:
            table.add_row(
                f"{_hex(item['offset'])} / {_hex(item.get('rva'))}",
                item.get("section") or "overlay",
                item["encoding"],
                ",".join(item["categories"]) or "-",
                item["value"][:300],
            )
        console.print(table)
        if strings["count"] > 100:
            console.print(f"[dim]Showing 100 of {strings['count']} retained strings.[/dim]")
        return

    packing = result["packing"]
    console.print(
        f"[bold]Verdict:[/bold] {packing['verdict']}  "
        f"[bold]Confidence:[/bold] {packing['confidence_score']}/10"
    )
    if packing["possible_packers"]:
        console.print(f"[bold]Possible packers:[/bold] {', '.join(packing['possible_packers'])}")
    if packing["indicators"]:
        indicators = Table(title="Packing/anomaly indicators", border_style="yellow")
        indicators.add_column("Severity")
        indicators.add_column("Type")
        indicators.add_column("Evidence", overflow="fold")
        for item in packing["indicators"]:
            indicators.add_row(item["severity"], item["type"], item["evidence"])
        console.print(indicators)
    else:
        console.print("[green]No obvious packing indicators detected.[/green]")


def print_written_reports(paths: list[Any], console: Console | None = None) -> None:
    console = console or Console()
    console.print("\n[bold green]Reports written:[/bold green]")
    for path in paths:
        console.print(f"  - {path}")


def print_x64dbg_script(path: Any, console: Console | None = None) -> None:
    console = console or Console()
    console.print(f"\n[bold green]x64dbg script written:[/bold green] {path}")
    console.print("[dim]Breakpoints are suggested analysis targets, not guaranteed solution points.[/dim]")
