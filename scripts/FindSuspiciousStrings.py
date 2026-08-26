# Classify defined strings and annotate interesting values.
# @author NingWen2000
# @category ReverseHelper
# @keybinding
# @menupath Tools.ReverseHelper.Find Suspicious Strings
# @toolbar

import re


RULES = [
    ("URL", re.compile(r"https?://", re.I)),
    ("COMMAND", re.compile(r"cmd\.exe|powershell|wscript|cscript", re.I)),
    ("CREDENTIAL", re.compile(r"password|passwd|credential|secret|token", re.I)),
    ("ANTI-DEBUG", re.compile(r"debugger|ollydbg|x32dbg|x64dbg|windbg", re.I)),
    ("CTF", re.compile(r"flag|ctf|crackme|serial|license", re.I)),
]


listing = currentProgram.getListing()
data_iterator = listing.getDefinedData(True)
hits = 0

while data_iterator.hasNext() and not monitor.isCancelled():
    item = data_iterator.next()
    if not item.hasStringValue():
        continue
    value = str(item.getValue())
    labels = [label for label, pattern in RULES if pattern.search(value)]
    if labels:
        comment = "ReverseHelper [%s]: %s" % (", ".join(labels), value[:200])
        listing.setComment(item.getAddress(), 3, comment)
        println("[+] %s at %s" % (", ".join(labels), item.getAddress()))
        hits += 1

println("ReverseHelper finished: %d interesting string(s)." % hits)
