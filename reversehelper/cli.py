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
from .localization import Language, message
from .localized_annotations import annotation_export
from .reporting import write_html, write_json, write_markdown, write_report_bundle
from .x64dbg_exporter import write_x64dbg_script


def build_parser(lang=Language.EN) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reversehelper",
        description="Offline CTF Quick Analysis: find interesting strings, validation candidates and where to start.",
        epilog=(
            "examples:\n"
            "  reversehelper sample.exe\n"
            '  reversehelper "C:\\path with spaces\\sample.exe"\n'
            "  reversehelper sample.exe --deep\n"
            "  reversehelper sample.exe --ghidra\n"
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
        help="Run bounded P0 Quick Analysis with Challenge Summary (default)",
    )
    mode.add_argument(
        "--deep",
        action="store_true",
        help="Run the same static analyzers with larger budgets",
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
    parser.add_argument(
        "--ghidra",
        nargs="?",
        const="__AUTO__",
        metavar="FILE",
        help="Write annotation JSON for the bundled Ghidra importer",
    )
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
    parser.add_argument("-v", "--verbose", action="store_true", help="Show budget and coverage details")
    parser.add_argument("--version", action="version", version=f"ReverseHelper {__version__}")
    parser.add_argument("--lang", choices=[value.value for value in Language], default="en", help=message("help.language", lang))
    if Language(lang) == Language.ZH_CN:
        from .localization_cli import localize_parser
        localize_parser(parser)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    language_parser = argparse.ArgumentParser(add_help=False)
    language_parser.add_argument("--lang", default="en")
    selected, _ = language_parser.parse_known_args(argv)
    if selected.lang not in {value.value for value in Language}:
        from .localization_cli import prepare_streams
        prepare_streams()
        language_parser.error(message("error.language", Language.ZH_CN, selected.lang))
    lang = Language(selected.lang)
    if lang == Language.ZH_CN:
        from .localization_cli import prepare_streams
        prepare_streams()
    parser = build_parser(lang)
    args = parser.parse_args(argv)
    localized = {"lang": lang} if lang != Language.EN else {}
    console = Console(stderr=True)

    if args.min_string_length < 3:
        parser.error("--min-string-length must be at least 3")
    if args.max_strings < 1:
        parser.error("--max-strings must be positive")
    if args.only and (args.report or args.json_path or args.html_path or args.markdown_path or args.ghidra):
        parser.error("report options require Quick Analysis; omit --only")
    if args.x64dbg_script:
        if args.only and args.only != "targets":
            parser.error("--x64dbg-script requires default analysis or --only targets")
        if Path(args.x64dbg_script).suffix.lower() not in {".txt", ".x64dbg"}:
            parser.error("--x64dbg-script output must end in .txt or .x64dbg")

    analyzer = ReverseHelperAnalyzer(args.min_string_length, args.max_strings)
    try:
        if args.deep:
            result = analyzer.analyze_deep(args.target)
        elif args.quick:
            result = analyzer.analyze_quick(args.target)
        elif args.only:
            result = analyzer.analyze_module(args.target, args.only)
        else:
            result = analyzer.analyze(args.target)
    except AnalysisError as exc:
        if lang == Language.EN:
            console.print(f"[bold red]Analysis failed:[/bold red] {exc}")
        else:
            from .localization_cli import analysis_error
            console.print(analysis_error(exc), markup=False)
            if args.verbose:
                console.print(str(exc), markup=False)
        return 2

    if not args.quiet:
        try:
            if args.only:
                print_module_analysis(result, args.only)
            else:
                print_quick_analysis(result, **localized)
                if args.verbose:
                    console.print("\nAnalysis profile:", result.get("analysis_mode", "quick"), markup=False)
                    console.print("Limits:", str(result.get("analysis_limits", {})), markup=False)
                    console.print("Truncated modules:", ", ".join(result.get("truncated_modules", [])) or "none", markup=False)
        except Exception as exc:
            warning = {"module": "report-console", "error_type": type(exc).__name__,
                       "reason": " ".join(str(exc).split())[:240]}
            result.setdefault("analysis_warnings", []).append(warning)
            console.print(message("warning.console", lang), markup=False)

    written = []
    jobs = []
    if args.report:
        jobs.append(("bundle", lambda: write_report_bundle(result, args.report, **localized)))
    if args.html_path:
        jobs.append(("html", lambda: [write_html(result, args.html_path, **localized)]))
    if args.markdown_path:
        jobs.append(("markdown", lambda: [write_markdown(result, args.markdown_path, **localized)]))
    if args.json_path:
        jobs.append(("json", lambda: [write_json(result, args.json_path)]))
    if args.ghidra:
        ghidra_path = (Path("reports") / (args.target.stem + ".reversehelper.json")
                       if args.ghidra == "__AUTO__" else Path(args.ghidra))
        jobs.append(("ghidra", lambda: [write_json(annotation_export(result, lang), ghidra_path)]))
    report_failed = False
    for name, job in jobs:
        try:
            written.extend(job())
        except Exception as exc:
            result.setdefault("analysis_warnings", []).append({"module": "report-" + name,
                "error_type": type(exc).__name__, "reason": " ".join(str(exc).split())[:240]})
    for warning in result.get("analysis_warnings", []):
        if warning["module"].startswith("report"):
            if lang == Language.EN:
                console.print(f"Warning: {warning['module']}: {warning['reason']}", markup=False)
            else:
                key = "error.ghidra" if warning["module"] == "report-ghidra" else "error.report"
                console.print(message(key, lang) + "（" + warning["module"] + "）。", markup=False)
                if args.verbose:
                    console.print(warning["reason"], markup=False)
            report_failed = True

    if written:
        if lang == Language.EN:
            print_written_reports(written)
        else:
            console.print(message("output.written", lang), markup=False)
            for path in written:
                console.print(str(path), markup=False)
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
    return 3 if report_failed else 0


if __name__ == "__main__":
    sys.exit(main())
