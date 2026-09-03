"""Markdown, JSON and standalone HTML report generation."""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any


def _hex(value: int | None) -> str:
    return "N/A" if value is None else f"0x{value:X}"


def _md_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _target_confidence(result: dict[str, Any], target: dict[str, Any]) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    findings = {finding["id"]: finding for finding in result.get("findings", [])}
    confidence = [
        findings[finding_id]["confidence"]
        for finding_id in target.get("finding_ids", [])
        if finding_id in findings
    ]
    return max(confidence, key=order.get) if confidence else "unknown"


def markdown_report(result: dict[str, Any]) -> str:
    basic = result["basic"]
    risk = result["risk"]
    lines = [
        "# ReverseHelper Analysis Report",
        "",
        f"> Static triage report for `{_md_escape(basic['file_name'])}`. The sample was not executed.",
        "",
        "## Summary",
        "",
        f"- **Risk:** {risk['level']} ({risk['score']}/{risk['maximum']})",
        f"- **Packing:** {result['packing']['verdict']}",
        f"- **Architecture:** {basic['architecture']}",
        f"- **SHA-256:** `{result['hashes']['sha256']}`",
        f"- **Analyzed (UTC):** {result['analyzed_at_utc']}",
        "",
        "## Basic information",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| File | `{_md_escape(basic['file_name'])}` |",
        f"| Size | {basic['file_size']} bytes |",
        f"| Type | {basic['file_type']} |",
        f"| Machine | {_hex(basic['machine'])} ({basic['architecture']}) |",
        f"| ImageBase | {_hex(basic['image_base'])} |",
        f"| EntryPoint RVA | {_hex(basic['entry_point_rva'])} |",
        f"| EntryPoint VA | {_hex(basic['entry_point_va'])} |",
        f"| EntryPoint file offset | {_hex(basic.get('entry_point_offset'))} |",
        f"| Subsystem | {_md_escape(basic['subsystem'])} |",
        f"| Compile time | {basic['compile_time_utc'] or 'Unavailable'} |",
    ]

    entry = result.get("entry_point_analysis")
    if entry:
        lines += [
            "",
            "## Entry-point review",
            "",
            f"- **Section:** `{_md_escape(entry['section'] or 'outside mapped sections')}`",
            f"- **File offset:** {_hex(entry['file_offset'])}",
            f"- **Bytes:** `{entry['bytes_hex']}`",
            f"- **Recognized pattern:** `{entry['pattern'] or 'none'}`",
        ]
        if entry["control_transfer_target_rva"] is not None:
            lines.append(
                f"- **First transfer target:** RVA {_hex(entry['control_transfer_target_rva'])} / "
                f"VA {_hex(entry['control_transfer_target_va'])}"
            )
        for item in entry["indicators"]:
            lines.append(f"- **{item['type']}:** {_md_escape(item['evidence'])}")

    lines += [
        "",
        "## Sections",
        "",
        "| Name | RVA | Virtual size | Raw offset | Raw size | Perms | Entropy | Flags |",
        "|---|---:|---:|---:|---:|:---:|---:|---|",
    ]
    for section in result["sections"]:
        flags = []
        if section["high_entropy"]:
            flags.append("high entropy")
        if section["rwx"]:
            flags.append("RWX")
        lines.append(
            f"| `{_md_escape(section['name'])}` | {_hex(section['virtual_address'])} | "
            f"{_hex(section['virtual_size'])} | {_hex(section['raw_address'])} | "
            f"{_hex(section['raw_size'])} | {section['permissions']} | {section['entropy']:.3f} | "
            f"{', '.join(flags) or '-'} |"
        )

    lines += ["", "## Executable-section padding", ""]
    caves = result.get("code_caves", [])
    if caves:
        lines += [
            "| Section | File offset | RVA | VA | Size | Fill |",
            "|---|---:|---:|---:|---:|---|",
        ]
        for cave in caves:
            lines.append(
                f"| `{_md_escape(cave['section'])}` | {_hex(cave['file_offset'])} | {_hex(cave['rva'])} | "
                f"{_hex(cave['va'])} | {_hex(cave['size'])} | `{cave['fill_byte']}` |"
            )
        lines += [
            "",
            "These runs are padding candidates, not automatically safe code caves. Check references and section mapping before patching.",
        ]
    else:
        lines.append("No 00/CC run of at least 32 bytes was found in executable sections.")

    lines += ["", "## Imports", ""]
    if result["imports"]:
        for library in result["imports"]:
            names = ", ".join(item["name"] for item in library["functions"][:30])
            suffix = " …" if len(library["functions"]) > 30 else ""
            lines.append(f"- **{_md_escape(library['dll'])}:** {_md_escape(names)}{suffix}")
    else:
        lines.append("No imports were parsed.")

    lines += ["", "## Suspicious APIs", ""]
    if result["suspicious_imports"]:
        lines += ["| DLL | API | Category | Severity |", "|---|---|---|---|"]
        for item in result["suspicious_imports"]:
            lines.append(
                f"| {_md_escape(item['dll'])} | `{_md_escape(item['name'])}` | "
                f"{item['category']} | {item['severity']} |"
            )
    else:
        lines.append("No rule-matched suspicious APIs.")

    lines += ["", "## Interesting strings", ""]
    interesting = result["strings"]["interesting"]
    if interesting:
        lines += [
            "| File offset | RVA | VA | Section | Encoding | Categories | Value |",
            "|---:|---:|---:|---|---|---|---|",
        ]
        for item in interesting[:100]:
            value = item["value"][:160]
            lines.append(
                f"| {_hex(item['offset'])} | {_hex(item.get('rva'))} | {_hex(item.get('va'))} | "
                f"{_md_escape(item.get('section') or 'overlay')} | {item['encoding']} | "
                f"{', '.join(item['categories'])} | "
                f"`{_md_escape(value)}` |"
            )
    else:
        lines.append("No strings matched the built-in triage rules.")

    lines += ["", "## Extracted strings", ""]
    extracted = result["strings"]["items"]
    if extracted:
        lines += [
            "| File offset | RVA | VA | Section | Encoding | Value |",
            "|---:|---:|---:|---|---|---|",
        ]
        for item in extracted[:100]:
            value = item["value"][:160]
            lines.append(
                f"| {_hex(item['offset'])} | {_hex(item.get('rva'))} | {_hex(item.get('va'))} | "
                f"{_md_escape(item.get('section') or 'overlay')} | {item['encoding']} | "
                f"`{_md_escape(value)}` |"
            )
        if len(extracted) > 100:
            lines.append("")
            lines.append(f"Showing 100 of {len(extracted)} extracted strings; JSON contains the retained set.")
    else:
        lines.append("No strings met the configured minimum length.")

    lines += ["", "## Packing indicators", ""]
    if result["packing"]["indicators"]:
        for item in result["packing"]["indicators"]:
            lines.append(f"- **{item['severity'].upper()} — {item['type']}:** {_md_escape(item['evidence'])}")
    else:
        lines.append("No obvious packing indicators were detected.")

    lines += ["", "## Cryptographic constants", ""]
    if result["crypto_constants"]:
        for item in result["crypto_constants"]:
            offsets = ", ".join(_hex(offset) for offset in item["offsets"])
            lines.append(
                f"- **{item['algorithm']} / {item['constant']}** ({item['confidence']} confidence): {offsets}"
            )
    else:
        lines.append("No built-in constant signatures matched.")

    lines += ["", "## Findings", ""]
    findings = result.get("findings", [])
    if findings:
        for finding in findings:
            lines += [
                f"### {_md_escape(finding['title'])}",
                "",
                f"- **Category:** `{finding['category']}`",
                f"- **Confidence / severity:** {finding['confidence'].upper()} / {finding['severity'].upper()}",
                f"- **Location:** RVA {_hex(finding.get('rva'))} / preferred VA {_hex(finding.get('va'))} / "
                f"file {_hex(finding.get('file_offset'))} / `{_md_escape(finding.get('section') or '-')}`",
                f"- **Evidence:** {'; '.join(_md_escape(item) for item in finding['evidence'])}",
                f"- **Reason:** {_md_escape(finding['reason'])}",
                f"- **Recommended action:** {_md_escape(finding['recommended_action'])}",
                "",
            ]
    else:
        lines.append("No instruction-level findings were produced.")

    lines += ["", "## Recommended Reverse Targets", ""]
    targets = result.get("reverse_targets", [])
    if targets:
        lines += [
            "| Priority | Category | Confidence | RVA | Preferred VA | Evidence sources |",
            "|---|---|---|---:|---:|---|",
        ]
        for target in targets:
            sources = ", ".join(target.get("finding_ids", [])) or "-"
            lines.append(
                f"| {target['priority'].upper()} | `{target['category']}` | "
                f"{_target_confidence(result, target).upper()} | {_hex(target['rva'])} | "
                f"{_hex(target.get('va'))} | {_md_escape(sources)} |"
            )
        for target in targets:
            lines += [
                "",
                f"- **{target['priority'].upper()} {_hex(target['rva'])} — {target['category']}**",
                f"  - Reason: {_md_escape(target['reason'])}",
                f"  - Recommended action: {_md_escape(target['recommended_action'])}",
            ]
    else:
        lines.append("No ranked reverse targets were produced.")
    if result.get("debugger_export_notice"):
        lines += ["", f"> {_md_escape(result['debugger_export_notice'])}"]

    lines += ["", "## Suggested Analysis Path", ""]
    analysis_path = result.get("analysis_path", [])
    if analysis_path:
        for item in analysis_path:
            lines += [
                f"### {item['priority'].upper()} — {_md_escape(item['where'])} — {item['category']}",
                "",
                f"- **Why:** {_md_escape(item['why'])}",
                f"- **Static Question:** {_md_escape(item['static_question'])}",
                f"- **Dynamic Question:** {_md_escape(item['dynamic_question'])}",
                f"- **Recommended Action:** {_md_escape(item['recommended_action'])}",
                "",
            ]
    else:
        lines.append("No static-to-dynamic analysis path was generated.")

    lines += ["", "## Unresolved Questions", ""]
    questions = result.get("unresolved_questions", [])
    if questions:
        for item in questions:
            lines += [
                f"- **{_md_escape(item['question'])}**",
                f"  - Why unresolved: {_md_escape(item['why_unresolved'])}",
                f"  - Related RVA: {_hex(item.get('related_rva'))}",
                f"  - Suggested dynamic observation: {_md_escape(item['suggested_dynamic_observation'])}",
            ]
    else:
        lines.append("No unresolved runtime questions were generated.")

    lines += ["", "## Analysis Warnings", ""]
    warnings = result.get("analysis_warnings", [])
    if warnings:
        for warning in warnings:
            lines.append(
                f"- **{_md_escape(warning['module'])} / {_md_escape(warning['error_type'])}:** "
                f"{_md_escape(warning['reason'])}"
            )
    else:
        lines.append("No optional analysis module failures were recorded.")

    lines += [
        "",
        "## Risk explanation",
        "",
    ]
    if risk["reasons"]:
        for reason in risk["reasons"]:
            lines.append(f"- **+{reason['points']} {reason['source']}:** {_md_escape(reason['detail'])}")
    else:
        lines.append("No scoring rules were triggered.")
    lines += [
        "",
        f"> {risk['disclaimer']}",
        "",
        "---",
        "Generated by ReverseHelper. Review all findings manually in Ghidra/x64dbg before drawing conclusions.",
        "",
    ]
    return "\n".join(lines)


def html_report(result: dict[str, Any]) -> str:
    basic = result["basic"]
    risk = result["risk"]
    markdown = markdown_report(result)
    section_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.3f}</td></tr>".format(
            html.escape(section["name"]),
            _hex(section["virtual_address"]),
            _hex(section["raw_size"]),
            html.escape(section["permissions"]),
            section["entropy"],
        )
        for section in result["sections"]
    )
    api_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(item["dll"]),
            html.escape(item["name"]),
            html.escape(item["category"]),
            html.escape(item["severity"]),
        )
        for item in result["suspicious_imports"]
    ) or '<tr><td colspan="4">No rule-matched suspicious APIs.</td></tr>'
    indicators = "".join(
        f"<li><strong>{html.escape(item['severity'].upper())}</strong> — {html.escape(item['evidence'])}</li>"
        for item in result["packing"]["indicators"]
    ) or "<li>No obvious packing indicators.</li>"
    target_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            html.escape(target["priority"].upper()),
            html.escape(target["category"]),
            _hex(target["rva"]),
            html.escape(_target_confidence(result, target).upper()),
        )
        for target in result.get("reverse_targets", [])[:20]
    ) or '<tr><td colspan="4">No ranked reverse targets.</td></tr>'
    warning_items = "".join(
        "<li><strong>{}</strong> / {}: {}</li>".format(
            html.escape(warning["module"]),
            html.escape(warning["error_type"]),
            html.escape(warning["reason"]),
        )
        for warning in result.get("analysis_warnings", [])
    ) or "<li>No optional analysis module failures.</li>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReverseHelper report — {html.escape(basic['file_name'])}</title>
<style>
:root{{--bg:#0b1020;--panel:#121a2e;--line:#26334f;--text:#e6edf7;--muted:#9aabc2;--accent:#68d5ff;--warn:#ffca62}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 Inter,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:auto;padding:42px 24px}}h1{{font-size:34px;margin:0 0 8px}}h2{{margin-top:34px;color:var(--accent)}}
.muted{{color:var(--muted)}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px;margin:24px 0}}
.card{{background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:18px}}.metric{{font-size:28px;font-weight:700}}
table{{width:100%;border-collapse:collapse;background:var(--panel)}}th,td{{padding:10px 12px;border:1px solid var(--line);text-align:left}}
th{{color:var(--accent)}}code{{color:var(--warn)}}details{{margin-top:34px}}pre{{white-space:pre-wrap;background:var(--panel);padding:18px;border-radius:12px;overflow:auto}}
</style></head><body><main>
<h1>ReverseHelper Analysis Report</h1><p class="muted">Static PE triage — the target was read but never executed.</p>
<div class="grid"><div class="card"><div class="muted">Risk</div><div class="metric">{risk['level']}</div><div>{risk['score']}/10</div></div>
<div class="card"><div class="muted">Packing</div><div class="metric">{html.escape(result['packing']['verdict'])}</div></div>
<div class="card"><div class="muted">Architecture</div><div class="metric">{html.escape(basic['architecture'])}</div></div>
<div class="card"><div class="muted">File</div><strong>{html.escape(basic['file_name'])}</strong><div>{basic['file_size']} bytes</div></div></div>
<h2>Identity</h2><div class="card"><code>SHA-256 {result['hashes']['sha256']}</code><br>ImageBase {_hex(basic['image_base'])} · EntryPoint {_hex(basic['entry_point_va'])}</div>
<h2>Sections</h2><table><thead><tr><th>Name</th><th>RVA</th><th>Raw size</th><th>Perms</th><th>Entropy</th></tr></thead><tbody>{section_rows}</tbody></table>
<h2>Suspicious APIs</h2><table><thead><tr><th>DLL</th><th>API</th><th>Category</th><th>Severity</th></tr></thead><tbody>{api_rows}</tbody></table>
<h2>Packing/anomaly indicators</h2><div class="card"><ul>{indicators}</ul></div>
<h2>Recommended Reverse Targets</h2><table><thead><tr><th>Priority</th><th>Category</th><th>RVA</th><th>Confidence</th></tr></thead><tbody>{target_rows}</tbody></table>
<p class="muted">{html.escape(result.get('debugger_export_notice', ''))}</p>
<h2>Analysis Warnings</h2><div class="card"><ul>{warning_items}</ul></div>
<details><summary>Complete Markdown report</summary><pre>{html.escape(markdown)}</pre></details>
</main></body></html>"""


def write_json(result: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return target.resolve()


def write_markdown(result: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(markdown_report(result), encoding="utf-8")
    return target.resolve()


def write_html(result: dict[str, Any], path: str | Path) -> Path:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(html_report(result), encoding="utf-8")
    return target.resolve()


def write_report_bundle(result: dict[str, Any], directory: str | Path) -> list[Path]:
    output = Path(directory)
    stem = Path(result["basic"]["file_name"]).stem + "_report"
    return [
        write_markdown(result, output / f"{stem}.md"),
        write_json(result, output / f"{stem}.json"),
        write_html(result, output / f"{stem}.html"),
    ]
