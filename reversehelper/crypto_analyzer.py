"""Known-constant matching for common cryptographic primitives."""

from __future__ import annotations

from typing import Any


AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76"
    "ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d83115"
    "04c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f84"
    "53d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa8"
    "51a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d1973"
    "60814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479"
    "e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a"
    "703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df"
    "8ca1890dbfe6426841992d0fb054bb16"
)

SIGNATURES: tuple[dict[str, Any], ...] = (
    {"algorithm": "AES", "constant": "S-box", "pattern": AES_SBOX, "confidence": "high"},
    {"algorithm": "AES", "constant": "Rcon", "pattern": bytes.fromhex("01020408102040801b36"), "confidence": "medium"},
    {"algorithm": "TEA", "constant": "delta 0x9E3779B9 (LE)", "pattern": bytes.fromhex("b979379e"), "confidence": "medium"},
    {"algorithm": "TEA", "constant": "delta 0x9E3779B9 (BE)", "pattern": bytes.fromhex("9e3779b9"), "confidence": "medium"},
    {"algorithm": "MD5", "constant": "initialization vector", "pattern": bytes.fromhex("0123456789abcdeffedcba9876543210"), "confidence": "high"},
    {"algorithm": "CRC32", "constant": "polynomial 0xEDB88320 (LE)", "pattern": bytes.fromhex("2083b8ed"), "confidence": "medium"},
    {"algorithm": "CRC32", "constant": "polynomial 0xEDB88320 (BE)", "pattern": bytes.fromhex("edb88320"), "confidence": "medium"},
)


def _find_offsets(data: bytes, pattern: bytes, limit: int = 8) -> list[int]:
    offsets: list[int] = []
    start = 0
    while len(offsets) < limit:
        offset = data.find(pattern, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + 1
    return offsets


def find_crypto_constants(data: bytes) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for signature in SIGNATURES:
        offsets = _find_offsets(data, signature["pattern"])
        if offsets:
            findings.append(
                {
                    "algorithm": signature["algorithm"],
                    "constant": signature["constant"],
                    "confidence": signature["confidence"],
                    "offsets": offsets,
                    "match_count": len(offsets),
                }
            )
    return findings
