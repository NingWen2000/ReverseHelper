"""Import/export table parsing and suspicious Windows API rules."""

from __future__ import annotations

from typing import Any


SUSPICIOUS_APIS: dict[str, tuple[str, str]] = {
    "virtualalloc": ("memory", "medium"),
    "virtualallocex": ("injection", "high"),
    "virtualprotect": ("memory", "medium"),
    "writeprocessmemory": ("injection", "high"),
    "readprocessmemory": ("process", "medium"),
    "createremotethread": ("injection", "high"),
    "ntcreatethreadex": ("injection", "high"),
    "queueuserapc": ("injection", "high"),
    "openprocess": ("process", "medium"),
    "createtoolhelp32snapshot": ("process", "medium"),
    "loadlibrarya": ("dynamic-loading", "low"),
    "loadlibraryw": ("dynamic-loading", "low"),
    "getprocaddress": ("dynamic-loading", "medium"),
    "winexec": ("execution", "high"),
    "shellexecutea": ("execution", "medium"),
    "shellexecutew": ("execution", "medium"),
    "createprocessa": ("execution", "medium"),
    "createprocessw": ("execution", "medium"),
    "isdebuggerpresent": ("anti-debug", "medium"),
    "checkremotedebuggerpresent": ("anti-debug", "medium"),
    "ntqueryinformationprocess": ("anti-debug", "medium"),
    "outputdebugstringa": ("anti-debug", "low"),
    "outputdebugstringw": ("anti-debug", "low"),
    "setwindowshookexa": ("hooking", "medium"),
    "setwindowshookexw": ("hooking", "medium"),
    "urldownloadtofilea": ("network", "high"),
    "urldownloadtofilew": ("network", "high"),
    "internetopena": ("network", "medium"),
    "internetopenw": ("network", "medium"),
    "internetopenurla": ("network", "high"),
    "internetopenurlw": ("network", "high"),
    "wsastartup": ("network", "low"),
    "connect": ("network", "medium"),
    "recv": ("network", "medium"),
    "send": ("network", "medium"),
    "cryptdecrypt": ("cryptography", "medium"),
    "cryptencrypt": ("cryptography", "medium"),
    "regsetvalueexa": ("persistence", "medium"),
    "regsetvalueexw": ("persistence", "medium"),
}


def _decode(value: bytes | str | None, fallback: str) -> str:
    if value is None:
        return fallback
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def analyze_imports(pe: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    libraries: list[dict[str, Any]] = []
    suspicious: list[dict[str, Any]] = []
    for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
        dll = _decode(entry.dll, "<unknown>")
        functions: list[dict[str, Any]] = []
        for imported in entry.imports:
            name = _decode(imported.name, f"ordinal_{imported.ordinal}")
            rule = SUSPICIOUS_APIS.get(name.lower())
            item = {
                "name": name,
                "ordinal": imported.ordinal,
                "iat_address": int(imported.address),
                "suspicious": rule is not None,
            }
            if rule:
                item.update({"category": rule[0], "severity": rule[1], "dll": dll})
                suspicious.append(dict(item))
            functions.append(item)
        libraries.append({"dll": dll, "functions": functions})
    return libraries, suspicious


def analyze_exports(pe: Any) -> list[dict[str, Any]]:
    exports: list[dict[str, Any]] = []
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if not directory:
        return exports
    for symbol in directory.symbols:
        exports.append(
            {
                "name": _decode(symbol.name, f"ordinal_{symbol.ordinal}"),
                "ordinal": int(symbol.ordinal),
                "address_rva": int(symbol.address),
            }
        )
    return exports
