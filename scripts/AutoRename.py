# Rename default-named functions that call selected high-signal imported APIs.
# @author NingWen2000
# @category ReverseHelper
# @keybinding
# @menupath Tools.ReverseHelper.Auto Rename Callers
# @toolbar

from ghidra.program.model.symbol import SourceType


API_NAMES = {
    "WriteProcessMemory": "inject_memory",
    "CreateRemoteThread": "create_remote_thread",
    "VirtualAllocEx": "allocate_remote_memory",
    "IsDebuggerPresent": "anti_debug_check",
    "CheckRemoteDebuggerPresent": "anti_debug_check",
    "GetProcAddress": "resolve_api",
    "LoadLibraryA": "load_library",
    "LoadLibraryW": "load_library",
    "WinExec": "execute_command",
    "CreateProcessA": "create_process",
    "CreateProcessW": "create_process",
}


symbol_table = currentProgram.getSymbolTable()
function_manager = currentProgram.getFunctionManager()
renamed = 0

for api_name, prefix in API_NAMES.items():
    symbols = symbol_table.getSymbols(api_name)
    for symbol in symbols:
        references = getReferencesTo(symbol.getAddress())
        for reference in references:
            function = function_manager.getFunctionContaining(reference.getFromAddress())
            if function is None or not function.getName().startswith("FUN_"):
                continue
            candidate = "rh_%s_%s" % (prefix, function.getEntryPoint().toString().replace(":", "_"))
            try:
                function.setName(candidate, SourceType.USER_DEFINED)
                function.setComment("ReverseHelper: caller of imported API %s" % api_name)
                println("[+] %s -> %s" % (function.getEntryPoint(), candidate))
                renamed += 1
            except Exception as error:
                printerr("[-] Could not rename %s: %s" % (function.getEntryPoint(), error))

println("ReverseHelper finished: %d function(s) renamed." % renamed)
