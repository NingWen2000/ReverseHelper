# Find common cryptographic constants and add plate comments.
# @author NingWen2000
# @category ReverseHelper
# @keybinding
# @menupath Tools.ReverseHelper.Find Crypto Constants
# @toolbar

from jarray import array


SIGNATURES = [
    ("TEA delta 0x9E3779B9 (little endian)", [0xB9, 0x79, 0x37, 0x9E]),
    ("TEA delta 0x9E3779B9 (big endian)", [0x9E, 0x37, 0x79, 0xB9]),
    ("MD5 initialization vector", [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]),
    ("CRC32 polynomial 0xEDB88320", [0x20, 0x83, 0xB8, 0xED]),
]


def signed(values):
    return array([value if value < 128 else value - 256 for value in values], "b")


memory = currentProgram.getMemory()
listing = currentProgram.getListing()
hits = 0

for label, values in SIGNATURES:
    pattern = signed(values)
    for block in memory.getBlocks():
        if not block.isInitialized():
            continue
        cursor = block.getStart()
        while cursor is not None and cursor.compareTo(block.getEnd()) <= 0:
            match = memory.findBytes(cursor, block.getEnd(), pattern, None, True, monitor)
            if match is None:
                break
            listing.setComment(match, 3, "ReverseHelper: possible " + label)
            println("[+] %s at %s" % (label, match))
            hits += 1
            cursor = match.add(1)

println("ReverseHelper finished: %d constant match(es)." % hits)
