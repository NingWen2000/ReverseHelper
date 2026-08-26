"""Rich terminal presentation."""

from __future__ import annotations

from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def _hex(value: int | None) -> str:
    return "N/A" if value is None else f"0x{value:X}"


def print_analysis(result: dict[str, Any], console: Console | None = None) -> None:
    console = console or Console()
    basic = result["basic"]
    risk = result["risk"]
    risk_color = {"LOW": "green", "MEDIUM": "yellow", "HIGH": "red", "CRITICAL": "bold red"}[risk["level"]]

    console.print(
        Panel.fit(
            "[bold cyan]ReverseHelper[/bold cyan] [dim]v1.0.0[/dim]\n"
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
        ("EntryPoint", f"RVA {_hex(basic['entry_point_rva'])} / VA {_hex(basic['entry_point_va'])}"),
        ("Subsystem", basic["subsystem"]),
        ("SHA-256", result["hashes"]["sha256"]),
    ):
        overview.add_row(label, str(value))
    console.print(overview)

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
        string_table.add_column("Offset", justify="right")
        string_table.add_column("Type")
        string_table.add_column("Value", overflow="fold", max_width=90)
        for item in interesting[:30]:
            string_table.add_row(_hex(item["offset"]), ",".join(item["categories"]), item["value"][:300])
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
    console.print(Panel(summary, border_style=risk_color.split()[-1]))


def print_written_reports(paths: list[Any], console: Console | None = None) -> None:
    console = console or Console()
    console.print("\n[bold green]Reports written:[/bold green]")
    for path in paths:
        console.print(f"  - {path}")
