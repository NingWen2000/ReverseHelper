from reversehelper.crypto_analyzer import AES_SBOX, find_crypto_constants


def test_detects_crypto_constants_and_offsets():
    data = b"prefix" + AES_SBOX + b"padding" + bytes.fromhex("b979379e")
    findings = find_crypto_constants(data)
    names = {(item["algorithm"], item["constant"]) for item in findings}
    assert ("AES", "S-box") in names
    assert ("TEA", "delta 0x9E3779B9 (LE)") in names
    aes = next(item for item in findings if item["constant"] == "S-box")
    assert aes["offsets"] == [6]


def test_no_false_match_on_empty_data():
    assert find_crypto_constants(b"") == []
