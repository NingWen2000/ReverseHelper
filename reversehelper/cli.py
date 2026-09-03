"""Command-line interface for ReverseHelper."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from rich.console import Console

from . import __version__
from .analyzer import AnalysisError, ReverseHelperAnalyzer
from .console import (
    print_analysis,
    print_module_analysis,
    print_quick_analysis,
    print_written_reports,
    print_x64dbg_script,
)
from .findings import ReverseTarget
from .reporting import write_html, write_json, write_markdown, write_report_bundle
from .x64dbg_exporter import write_x64dbg_script


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reversehelper",
        description="Static Windows PE triage for reverse engineering and CTF learning.",
        epilog=(
            "examples:\n"
            "  reversehelper sample.exe\n"
            '  reversehelper "C:\\path with spaces\\sample.exe"\n'
            "  reversehelper sample.exe --quick\n"
            "  reversehelper sample.exe --only anomaly\n"
            "  reversehelper sample.exe --only targets\n"
            "  reversehelper sample.exe --only strings\n"
            "  reversehelper sample.exe --only imports\n"
            "  reversehelper sample.exe --report\n"
            "  reversehelper sample.exe --x64dbg-script breakpoints.x64dbg"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", type=Path, help="Path to an EXE, DLL, SYS or other PE file")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--quick",
        action="store_true",
        help="Run fast structural triage without instruction analyzers or deep byte scans",
    )
    mode.add_argument(
        "--only",
        choices=("anomaly", "strings", "imports", "antidebug", "validation", "crypto", "targets"),
        metavar="MODULE",
        help="Run one module: anomaly, strings, imports, antidebug, validation, crypto or targets",
    )
    parser.add_argument(
        "--report",
        nargs="?",
        const="reports",
        metavar="DIR",
        help="Write Markdown, JSON and standalone HTML reports (default directory: reports)",
    )
    parser.add_argument("--json", dest="json_path", metavar="FILE", help="Write a JSON report")
    parser.add_argument("--html", dest="html_path", metavar="FILE", help="Write a standalone HTML report")
    parser.add_argument("--markdown", dest="markdown_path", metavar="FILE", help="Write a Markdown report")
    parser.add_argument(
        "--x64dbg-script",
        metavar="FILE",
        help="Write HIGH/MEDIUM reverse targets as an ASLR-safe .txt or .x64dbg script",
    )
    parser.add_argument("--min-string-length", type=int, default=4, metavar="N", help="Minimum extracted string length (default: 4)")
    parser.add_argument("--max-strings", type=int, default=2000, metavar="N", help="Maximum unique strings retained (default: 2000)")
    parser.add_argument("--quiet", action="store_true", help="Suppress console tables")
    parser.add_argument("--version", action="version", version=f"ReverseHelper {__version__}")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = Console(stderr=True)

    if args.min_string_length < 3:
        parser.error("--min-string-length must be at least 3")
    if args.max_strings < 1:
        parser.error("--max-strings must be positive")
    if (args.quick or args.only) and (args.report or args.json_path or args.html_path or args.markdown_path):
        parser.error("report options require the default full analysis mode")
    if args.x64dbg_script:
        if args.quick or (args.only and args.only != "targets"):
            parser.error("--x64dbg-script requires default analysis or --only targets")
        if Path(args.x64dbg_script).suffix.lower() not in {".txt", ".x64dbg"}:
            parser.error("--x64dbg-script output must end in .txt or .x64dbg")

    analyzer = ReverseHelperAnalyzer(args.min_string_length, args.max_strings)
    try:
        if args.quick:
            result = analyzer.analyze_quick(args.target)
        elif args.only:
            result = analyzer.analyze_module(args.target, args.only)
        else:
            result = analyzer.analyze(args.target)
    except AnalysisError as exc:
        console.print(f"[bold red]Analysis failed:[/bold red] {exc}")
        return 2

    if not args.quiet:
        if args.quick:
            print_quick_analysis(result)
        elif args.only:
            print_module_analysis(result, args.only)
        else:
            print_analysis(result)

    written = []
    try:
        if args.report:
            written.extend(write_report_bundle(result, args.report))
        if args.json_path:
            written.append(write_json(result, args.json_path))
        if args.html_path:
            written.append(write_html(result, args.html_path))
        if args.markdown_path:
            written.append(write_markdown(result, args.markdown_path))
    except OSError as exc:
        console.print(f"[bold red]Could not write report:[/bold red] {exc}")
        return 3

    if written:
        print_written_reports(written)
    if args.x64dbg_script:
        try:
            targets = [
                ReverseTarget(
                    category=item["category"],
                    rva=item["rva"],
                    va=item["va"],
                    file_offset=item["file_offset"],
                    section=item["section"],
                    priority=item["priority"],
                    reason=item["reason"],
                    recommended_action=item["recommended_action"],
                    finding_ids=tuple(item["finding_ids"]),
                )
                for item in result.get("reverse_targets", [])
            ]
            script_path = write_x64dbg_script(
                targets,
                result["basic"]["file_name"],
                result["basic"]["architecture"],
                args.x64dbg_script,
            )
        except (OSError, ValueError) as exc:
            console.print(f"[bold red]Could not write x64dbg script:[/bold red] {exc}")
            return 3
        print_x64dbg_script(script_path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
