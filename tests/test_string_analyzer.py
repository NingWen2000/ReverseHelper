import pytest

from reversehelper.string_analyzer import classify_string, extract_strings


def test_classification_rules():
    assert "url" in classify_string("https://example.test/payload")
    assert "command" in classify_string("powershell.exe -enc AAA")
    assert "credential" in classify_string("password=demo")
    assert classify_string("ordinary harmless sentence") == []


def test_extracts_ascii_and_utf16le_strings():
    data = b"\x00hello world\x00" + "flag{demo}".encode("utf-16le") + b"\x00"
    result = extract_strings(data, minimum=4)
    encodings = {item["encoding"] for item in result["items"]}
    values = {item["value"] for item in result["items"]}
    assert {"ASCII", "UTF-16LE"}.issubset(encodings)
    assert "hello world" in values
    assert "flag{demo}" in values
    assert result["interesting_count"] >= 1


def test_string_limits_are_validated():
    with pytest.raises(ValueError):
        extract_strings(b"hello", minimum=2)
    with pytest.raises(ValueError):
        extract_strings(b"hello", maximum=0)
