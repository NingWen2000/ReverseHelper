"""CTF string relevance from text, direct code references and local branch context."""

from __future__ import annotations

import re
from bisect import bisect_left

from capstone import CS_GRP_JUMP


RULES = (
    ("FAILURE", r"\b(?:wrong|incorrect|unsuccessful|fail(?:ed|ure)?|invalid|denied|try\s+again|not\s+correct|not\s+valid)\b"),
    ("SUCCESS", r"\b(?:correct|success(?:ful)?|congratulations|congrats|well\s+done|accepted)\b"),
    ("FLAG", r"\b(?:flag|ctf|crackme)\b"),
    ("PASSWORD", r"\b(?:password|passwd|passphrase)\b"),
    ("INPUT", r"\b(?:input|enter|type\s+your|provide)\b"),
    ("KEY", r"\b(?:key|secret|serial|license)\b"),
    ("ERROR", r"\b(?:error|exception|fatal|abort)\b"),
    ("FORMAT", r"%(?:\d+\$)?[-+#0 .\d*]*(?:hh|ll|[hljztL])?[diuoxXfFeEgGaAcspn]|%\["),
    ("FILE", r"(?:[a-z]:\\|[/\\][\w.-]+[/\\]|\b[\w.-]+\.(?:txt|dat|bin|exe|dll|cfg|ini|json)\b)"),
    ("NETWORK", r"https?://|ftp://|\b(?:socket|connect|recv|send|user-agent|winsock)\b"),
    ("CRYPTO", r"\b(?:aes|rc4|x?tea|xxtea|xor|sha\d*|md5|crc\d*|encrypt|decrypt|base64)\b"),
    ("DEBUG", r"\b(?:debug(?:ger)?|isdebuggerpresent|x64dbg|x32dbg|windbg|assert)\b"),
)
PATTERNS = [(name, re.compile(pattern, re.I)) for name, pattern in RULES]
CTF_CATEGORIES = {"SUCCESS", "FAILURE", "FLAG", "PASSWORD", "INPUT", "KEY"}
RUNTIME_NOISE = re.compile(
    r"mingw runtime failure|virtualquery failed for|pseudo relocation|invalid parameter|"
    r"pure virtual function call|runtime error|glob-\d+\.\d+-mingw",
    re.I,
)


def classify_ctf_string(value):
    categories = [name for name, pattern in PATTERNS if pattern.search(value)]
    # Negated positive wording is failure evidence, not both outcomes.
    if re.search(r"\bnot\s+(?:correct|valid|successful)\b", value, re.I):
        categories = [c for c in categories if c != "SUCCESS"]
        if "FAILURE" not in categories:
            categories.insert(0, "FAILURE")
    return categories or ["GENERIC"]


def analyze_interesting_strings(strings, context, *, limited_static_visibility=False):
    addresses = sorted(context.references)
    results = []
    for item in strings.get("items", []):
        categories = classify_ctf_string(item["value"])
        runtime_noise = bool(RUNTIME_NOISE.search(item["value"]))
        category = categories[0]
        address = item.get("va")
        width = 2 if item["encoding"] == "UTF-16LE" else 1
        xrefs = []
        if address is not None:
            start = bisect_left(addresses, address)
            end = bisect_left(addresses, address + len(item["value"]) * width)
            for referenced in addresses[start:end]:
                if (referenced - address) % width:
                    continue
                for source_rva in context.references[referenced]:
                    fn = context.owner(source_rva)
                    branches = []
                    if fn:
                        for ins, dec in context.local_records(source_rva, before=6, after=6):
                            if dec.group(CS_GRP_JUMP) and dec.mnemonic != "jmp":
                                branches.append(ins.rva)
                    xrefs.append({"rva": source_rva, "address": context.image_base + source_rva,
                                  "function": fn.name if fn else None, "function_rva": fn.rva if fn else None,
                                  "reference_address": referenced, "string_offset": referenced - address,
                                  "nearby_branches": branches, "kind": "direct_operand"})
        xrefs.sort(key=lambda x: (x["rva"], x["reference_address"]))
        functions = sorted({xref["function"] for xref in xrefs if xref["function"]})
        score = 20 if category in CTF_CATEGORIES else 5 if category != "GENERIC" else 0
        reasons = [f"{category.lower()}-related text" if category != "GENERIC" else "No CTF keyword matched"]
        if xrefs:
            score += 20
            reasons.append("Referenced by executable code through a direct operand")
        if functions:
            score += 10
            reasons.append("Reference belongs to a bounded function candidate")
        if any(xref["nearby_branches"] for xref in xrefs):
            score += 10
            reasons.append("Nearby conditional control flow (proximity, not proven dependence)")
        if limited_static_visibility:
            score = min(score, 30)
            reasons.append("Packed/obfuscated surface limits confidence until an unpacked image is available")
        if runtime_noise:
            score = min(score, 10)
            reasons.append("Known compiler/runtime diagnostic pattern; not challenge evidence by itself")
        results.append({
            "id": f"S-{item['offset']:08X}-{item['encoding']}", "address": address, "rva": item.get("rva"),
            "file_offset": item["offset"], "value": item["value"], "encoding": item["encoding"],
            "category": category, "categories": categories, "score": score,
            "priority": "HIGH" if score >= 50 else "MEDIUM" if score >= 30 else "LOW",
            "confidence": "low" if limited_static_visibility or runtime_noise else "medium" if functions else "low",
            "runtime_noise": runtime_noise, "xref_count": len({x["rva"] for x in xrefs}),
            "xref_functions": functions, "xrefs": xrefs, "reasons": reasons,
            "outcome": category if category in {"SUCCESS", "FAILURE"} and not {"SUCCESS", "FAILURE"} <= set(categories) else None,
        })
    return sorted(results, key=lambda item: (-item["score"], item["file_offset"], item["id"]))
