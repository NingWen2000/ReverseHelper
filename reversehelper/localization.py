"""Offline presentation resources. Never passed to an analyzer or serializer."""

from enum import Enum
import re


class Language(str, Enum):
    EN = "en"
    ZH_CN = "zh-CN"


# Stable keys belong to the presentation layer; values in analysis JSON are untouched.
MESSAGES = {
    "summary.unknown_function": ("function unknown", "函数未知"),
    "summary.reasons": ("  Reasons: ", "  原因："),
    "summary.evidence_prefix": ("  Evidence: ", "  证据："),
    "summary.context_only": ("context only", "仅作上下文"),
    "summary.candidate": ("candidate", "候选"),
    "summary.title": ("ReverseHelper {0} Analysis", "ReverseHelper — {0} 模式分析"),
    "summary.challenge": ("Challenge Summary", "题目摘要"),
    "summary.target": ("Target: {0}", "目标文件：{0}"),
    "summary.binary": ("Binary: {0}", "二进制类型：{0}"),
    "summary.packing": ("Packing: {0}", "加壳情况：{0}"),
    "summary.visibility": ("Static visibility: {0}", "静态可见性：{0}"),
    "summary.start_here": ("START HERE", "建议从这里开始"),
    "summary.start_with_these": ("START WITH THESE", "建议优先查看这些位置"),
    "summary.reason": ("Reason: {0}", "原因：{0}"),
    "summary.next": ("Next: {0}", "建议下一步：{0}"),
    "summary.input": ("Input Flow", "输入来源与数据流"),
    "summary.slice": ("Static Slice", "静态数据流切片"),
    "summary.likely_path": ("Likely Static Path", "很可能的静态路径"),
    "summary.partial": ("Partial Input Flow", "部分输入数据流"),
    "summary.possible_path": ("Possible Static Path", "可能的静态路径"),
    "summary.flow_break": ("FLOW BREAK", "静态追踪中断点"),
    "summary.validation": ("Likely Validation", "很可能的验证逻辑"),
    "summary.suggestions": ("Semantic Suggestions", "语义建议"),
    "summary.control_flow": ("Control Flow", "控制流"),
    "summary.algorithms": ("Algorithms", "算法候选"),
    "summary.strings": ("Interesting Strings", "值得关注的字符串"),
    "summary.candidates": ("Validation Candidates", "验证逻辑候选"),
    "summary.targets": ("Top Reverse Targets", "优先逆向目标"),
    "summary.static_path": ("Suggested Static Path", "建议的静态分析路径"),
    "summary.warnings": ("Analysis Warnings", "分析警告"),
    "summary.coverage": ("Coverage", "分析覆盖范围"),
    "summary.unpack": ("Post-Unpack Guidance", "脱壳后的建议"),
    "summary.no_input": ("No supported input destination was recovered.", "未恢复出受支持的输入目标位置。"),
    "summary.no_slice": ("No input-to-validation slice was established within the Quick budgets.", "在当前分析预算内未建立输入到验证逻辑的静态数据流切片。"),
    "summary.no_semantic": ("No high-confidence semantic suggestion.", "暂无高置信度的语义建议。"),
    "summary.no_control": ("No high or strong on-slice control-flow structure.", "暂无高置信度或切片上证据充分的控制流结构。"),
    "summary.no_algorithm": ("No high or strong on-slice algorithm candidate.", "暂无高置信度或切片上证据充分的算法候选。"),
    "summary.no_strings": ("No classified strings available; check warnings and scan coverage.", "暂无已分类字符串；请检查警告和扫描覆盖范围。"),
    "summary.no_targets": ("No ranked targets available.", "暂无可排序的逆向目标。"),
    "summary.ambiguous_start": ("No single target has enough confidence and separation for a definitive START HERE.", "当前没有置信度和分数差距足够明确的单一首选目标。"),
    "summary.deep_hint": ("Run again with --deep when broader static coverage is worth the extra time.", "如需扩大静态分析覆盖范围，可使用 --deep 重新分析。"),
    "summary.warning": ("Warning: {0}", "警告：{0}"),
    "summary.truncated": ("Truncated: ", "分析因预算限制被截断："),
    "summary.confidence": ("{0}  |  {1}/100  |  Confidence: {2}", "{0}  |  {1}/100  |  置信度：{2}"),
    "summary.start_candidate": ("{0}. {1}  |  {2}/100  |  Confidence: {3}", "{0}. {1}  |  {2}/100  |  置信度：{3}"),
    "summary.indented_reason": ("   Reason: {0}", "   原因：{0}"),
    "summary.dispatcher": ("  Dispatcher: RVA 0x{0:X}", "  分发器：RVA 0x{0:X}"),
    "summary.suggested": ("  Suggested: {0}", "  建议：{0}"),
    "summary.evidence": ("Evidence: {0}", "证据：{0}"),
    "summary.next_unresolved": ("Next unresolved target: FUN_{0:X} via call RVA 0x{1:X}", "下一个未解析目标：FUN_{0:X}，调用位置 RVA 0x{1:X}"),
    "summary.string_count": ("Showing {0} of {1} classified strings; JSON retains all available records.", "显示 {1} 个已分类字符串中的 {0} 个；JSON 保留全部可用记录。"),
    "summary.validation_count": ("Showing {0} of {1} validation candidates; JSON retains all available records.", "显示 {1} 个验证逻辑候选中的 {0} 个；JSON 保留全部可用记录。"),
    "summary.no_validation": ("No actionable validation candidate; {0} comparison observations remain in JSON for review.", "暂无可操作的验证逻辑候选；JSON 中保留了 {0} 个比较观察记录供复查。"),
    "error.analysis": ("Analysis failed:", "错误：分析失败。"),
    "error.missing": ("Input file does not exist", "错误：目标文件不存在。"),
    "error.read": ("Could not read input file", "错误：无法读取目标文件。"),
    "error.format": ("Invalid or unsupported PE file", "错误：无效的 PE 文件或不支持的格式。"),
    "error.language": ("Unsupported language: {0}. Available languages: en, zh-CN", "不支持的语言：{0}。可用语言：en, zh-CN"),
    "error.report": ("Could not write report", "错误：无法写入报告"),
    "error.ghidra": ("Could not export Ghidra annotations", "错误：无法导出 Ghidra 注释"),
    "warning.console": ("Warning: console summary failed; analysis results remain available for file export.", "警告：终端摘要显示失败；仍可导出分析结果。"),
    "warning.module": ("{0}: {1}", "警告：模块 {0} 的分析结果可能不完整。诊断：{1}"),
    "output.written": ("Reports written:", "已写入报告："),
    "help.language": ("UI language (default: en)", "界面语言（默认：en）"),
}

ENUM_LABELS = {
    "FULLY_VISIBLE": "完全可见", "PARTIALLY_VISIBLE": "部分可见",
    "PACKED_OR_TRANSFORMED": "已加壳或运行时变换", "NORMAL": "完全可见",
    "LIMITED": "已加壳或运行时变换", "UNKNOWN": "未知",
    "HIGH": "高", "MEDIUM": "中", "LOW": "低", "CONFIRMED": "已确认",
    "LIKELY": "很可能", "POSSIBLE": "可能", "COMPLETE": "完成",
    "TRUNCATED": "已截断", "SKIPPED": "已跳过", "UNAVAILABLE": "不可用", "ERROR": "错误",
    "CRYPTO": "加密/密码变换", "ENCODING": "编码", "CHECKSUM": "校验和", "TRANSFORM": "数据变换",
    "SWITCH": "switch 分支", "JUMP_TABLE": "跳转表", "STATE_MACHINE": "状态机",
    "DISPATCHER": "分发器", "INDIRECT_JUMP": "间接跳转", "FLATTENING_LIKE": "类控制流平坦化结构",
    "INPUT": "输入", "TRANSFORMED_INPUT": "已变换输入", "KEY": "密钥", "POSSIBLE_KEY": "可能的密钥",
    "TARGET": "目标数据", "LOOKUP_TABLE": "查找表", "STATE": "状态变量", "VALIDATION_RESULT": "验证结果",
    "VALIDATION": "验证逻辑", "SUSPICIOUS_FUNCTION": "可疑函数", "COMPARE": "比较",
    "KEY_TABLE": "密钥/数据表", "ANTI_DEBUG": "反调试", "PACKING": "加壳",
    "SUCCESS": "成功提示", "FAILURE": "失败提示", "FILE": "文件", "GENERIC": "普通字符串",
    "ON_SLICE": "位于切片上", "OFF_SLICE": "位于切片之外", "CONFIRMED_SLICE": "已确认切片",
    "LIKELY_SLICE": "很可能的切片", "PARTIAL_SLICE": "部分切片",
    "INPUT_FLOW_TO_VALIDATION": "输入到验证逻辑的数据流", "INPUT_SOURCE": "输入来源",
    "COMPARE_TARGET": "比较目标", "COMPARE_LENGTH": "比较长度", "SUCCESS_BRANCH": "成功分支", "FAILURE_BRANCH": "失败分支",
    "INPUT_TRANSFORM": "输入变换", "VALIDATION_FUNCTION": "验证逻辑函数", "VALIDATION_SINK": "验证逻辑汇聚点",
}


def message(key, lang=Language.EN, *args):
    return MESSAGES[key][Language(lang) == Language.ZH_CN].format(*args)


def display_enum(value, lang=Language.EN):
    if Language(lang) == Language.EN or not isinstance(value, str):
        return value
    return ENUM_LABELS.get(value.upper().replace(" ", "_"), value)


# Translate only explicitly identified analyzer-authored prose, never sample strings,
# file paths, symbols, arbitrary JSON fields or rendered documents.
PROSE = {
    "Known constant bytes or a direct reference; algorithm use and buffer role are unproven.": "发现已知常量字节或直接引用；尚未证实算法用途和缓冲区角色。",
    "Sensitive API is called here; purpose is unproven.": "此处调用敏感 API；尚未证实其用途。",
    "Structural packing indicators justify reviewing the entry point; packing is not proven.": "结构性加壳迹象提示应检查入口点；尚未证实已加壳。",
    "String count or byte scan budget reached; unscanned strings remain unknown.": "字符串数量或字节扫描预算已耗尽；未扫描的字符串仍未知。",
    "Some executable bytes were skipped, undecodable or outside Quick budgets; absence of findings is not absence of logic.": "部分可执行字节被跳过、无法解码或超出 Quick 预算；未发现结果不代表逻辑不存在。",
    "A PE CODE section lacking the EXECUTE bit was decoded because it is .text or contains the entry point; section permissions remain suspicious.": "某个缺少 EXECUTE 位的 PE CODE 节区因名为 .text 或包含入口点而被解码；节区权限仍可疑。",
    "A reliable CRT-to-user-main argc/argv relationship was not recovered; no argv source was guessed.": "未恢复出可靠的 CRT 到用户 main 的 argc/argv 关系；未猜测 argv 来源。",
    "Algorithm analysis truncated; unexamined functions or instructions remain unknown.": "算法分析因预算限制被截断；未检查的函数或指令仍未知。",
    "Control-flow analysis truncated; unexamined functions, blocks or targets remain unknown.": "控制流分析因预算限制被截断；未检查的函数、基本块或目标仍未知。",
    "Inspect the selector range check, then label each case target before reading case bodies.": "先检查选择器的范围判断，再标注每个 case 目标，最后阅读分支代码。",
    "Trace the operand definition and classify it as a table, callback, or unknown target.": "追踪操作数的定义，判断它是表、回调还是未知目标。",
    "Inspect the call operand origins as a possible function table; keep each target unresolved unless uniquely proven.": "将调用操作数的来源作为可能的函数表检查；只有获得唯一证据后才确定目标。",
    "Review both successors manually; this is only an opaque-like pattern and does not prove either edge unreachable.": "手动检查两个后继分支；这只是类似不透明谓词的模式，不能证明任一分支不可达。",
    "Track state assignments first, then group case blocks by the state values that reach the dispatcher.": "先追踪状态赋值，再按到达分发器的状态值对 case 块分组。",
    "Treat this as flattening-like, not proven flattening; map state writes and dispatcher cases without rewriting the CFG.": "将其视为类控制流平坦化结构，尚不能认定已平坦化；记录状态写入和分发器分支，不重写 CFG。",
    "Comparator result controls a local conditional branch": "比较结果控制局部条件分支",
    "References CTF-related text in executable code": "可执行代码引用了 CTF 相关文本",
    "Byte comparison loop has a back edge and iterator progress": "字节比较循环包含回边和迭代推进",
    "Same function also checks a string length; same buffer unproven": "同一函数还检查字符串长度；尚未证实使用同一缓冲区",
    "Source-reachable callee return reaches the validation outcome branch": "输入来源可达的被调函数返回值到达验证结果分支",
    "Input and comparison share a function but bounded flow does not connect them": "输入与比较位于同一函数，但有界数据流尚未将二者连接",
    "Strong packing indicators make the entry stub the first static review target": "明显加壳证据使入口桩成为首选静态检查目标",
    "PE structure comparison context reduces CTF relevance": "PE 结构比较上下文降低了与 CTF 题目逻辑的相关性",
    "PE structure context reduces CTF relevance": "PE 结构上下文降低了与 CTF 题目逻辑的相关性",
    "Comparison lacks enough independent context to be an actionable validation candidate": "比较缺少足够的独立上下文，尚不能作为可操作的验证逻辑候选",
    "Compiler/CRT symbol context reduces challenge-validation relevance": "编译器/CRT 符号上下文降低了与题目验证逻辑的相关性",
    "Forwarding thunk is not a validation body": "转发 thunk 并非验证逻辑主体",
    "Packed surface caps pre-unpack code claims": "加壳表层限制了脱壳前代码结论的评分上限",
    "argument linkage unknown": "参数关联未知",
    "bounded flow analysis ended before a validation sink": "有界数据流分析在到达验证逻辑汇聚点之前结束",
    "Interprocedural edge budget reached": "跨过程边预算已耗尽，分析被截断",
    "Interprocedural function budget reached": "跨过程函数预算已耗尽，分析被截断",
    "Global interprocedural edge budget reached": "全局跨过程边预算已耗尽，分析被截断",
    "BUDGET_LIMIT: Interprocedural fixed-point iteration budget reached": "跨过程不动点迭代预算已耗尽，分析被截断",
    "BUDGET_LIMIT: function summary edge budget reached": "函数摘要边预算已耗尽，分析被截断",
    "Inspect the entry stub and identify the transition to the original entry point (OEP).": "检查入口桩，识别向原始入口点（OEP）的转移。",
    "Record the unpacked image layout and rebuild or verify imports after the OEP transition.": "记录脱壳后的映像布局，并在转移到 OEP 后重建或验证导入表。",
    "Dump the unpacked image in an isolated debugger, then run ReverseHelper again on that dump.": "在隔离的调试环境中转储脱壳后的映像，再对转储运行 ReverseHelper。",
    "indirect call target is ambiguous": "间接调用目标存在歧义",
    "propagation stops at the proven call argument": "数据传播在已证实的调用参数处停止",
    "source-reachable value is proven through the last transform/store, but alias recovery into the following call is unresolved": "已证实输入来源可达的值经过最后一次变换或存储，但尚未解析到后续调用的别名关系",
    "No strong packing evidence": "未发现明显加壳证据",
    "Packing analysis unavailable": "加壳分析不可用",
    "Packed / obfuscated binary detected; static visibility is limited": "检测到加壳或混淆；静态可见性受限",
    "Contains a comparator call or comparison loop": "包含比较函数调用或比较循环",
    "Contains an input-related API call": "包含输入相关 API 调用",
    "user input linkage remains unproven": "尚未证实与用户输入的关联",
    "Separate comparison successors reference success/failure text": "比较后的不同后继分支引用成功/失败文本",
    "References both success- and failure-related strings": "同时引用成功和失败相关字符串",
    "inspect the comparison arguments, cited strings and both branch successors": "检查比较参数、引用的字符串以及两个后继分支",
    "inspect both comparison operands and check whether the result controls user validation": "检查两个比较操作数，并确认结果是否控制用户输入的验证逻辑",
    "inspect the input API arguments and destination buffer references": "检查输入 API 参数和目标缓冲区引用",
    "inspect the byte transformations and their callers": "检查字节变换及其调用方",
    "inspect the cited constants and surrounding operations before naming an algorithm": "先检查引用的常量和周围操作，再判断算法",
    "inspect code references and establish the constant data's role": "检查代码引用并确定常量数据的角色",
    "inspect the API arguments and surrounding conditions": "检查 API 参数及周围条件",
    "inspect the entry code and cited section anomalies": "检查入口代码和所列节区异常",
    "inspect the cited string references and local callers": "检查所列字符串引用和局部调用方",
    "This is the first source-reachable function with a non-trivial transform on the static path.": "这是静态路径上首个输入来源可达且包含非平凡变换的函数。",
    "Input flow is proven up to this function and becomes unresolved at the reported flow break.": "输入数据流已追踪到该函数，并在报告的静态追踪中断点处无法继续解析。",
    "Scores rank review priority, not probability. Static flow is bounded and path-insensitive; only unique simple indirect targets are propagated, and POSSIBLE segments are not asserted as facts.": "分数用于排列检查优先级，不代表概率。静态数据流分析受预算限制且不区分路径；仅传播唯一的简单间接目标，可能的数据流片段不作为事实。",
    "Scores rank review priority, not probability. Pre-unpack strings, validation and ranking have reduced reliability; re-run on an unpacked dump.": "分数用于排列检查优先级，不代表概率。在完成脱壳或获取展开后的代码之前，不要完全信任当前的字符串、验证逻辑、排序和静态切片结果；请对脱壳后的转储重新分析。",
    "Static tracking lost here": "静态追踪在此中断",
    "Validation candidate. Review operands and both branch outcomes.": "验证逻辑候选。请检查操作数以及两个分支的结果。",
    "Input-reachable transform": "输入来源可达的变换",
    "This transform lies on a bounded static input path.": "此变换位于有界静态输入路径上。",
    "Semantic suggestion": "语义建议",
    "Review before applying; no rename is automatic.": "应用前请先复查；不会自动重命名。",
}


PROSE_PATTERNS = [
    (re.compile(r"Not started after the ([\d.]+)s analysis deadline; result is unavailable\."), "超过 {0} 秒分析期限，模块未启动；结果不可用。"),
    (re.compile(r"Module took ([\d.]+)s, above the ([\d.]+)s soft budget; bounded output was retained\."), "模块耗时 {0} 秒，超过 {1} 秒软预算；已保留有界输出。"),
    (re.compile(r"A function membership walk reached (\d+) instructions; remaining membership is unknown\."), "函数归属遍历已达到 {0} 条指令；剩余归属未知。"),
    (re.compile(r"Semantic suggestions truncated; lower-ranked suggestions remain outside the (Quick|Deep) output limits\."), "语义建议因预算限制被截断；较低排名的建议超出 {0} 输出上限。"),
    (re.compile(r"Inspect (.+) and follow the next source-reachable use\."), "检查 {0}，继续追踪下一处输入来源可达的使用。"),
    (re.compile(r"(?P<confidence>Confirmed|Likely|Possible) user-input flow reaches this validation site"), "{0}的用户输入数据流到达此验证逻辑位置"),
    (re.compile(r"(?P<confidence>Confirmed|Likely|Possible) bounded input-to-validation slice reaches this site"), "{0}的有界输入到验证逻辑切片到达此位置"),
    (re.compile(r"(.+) transform lies on an input-to-validation slice"), "{0} 变换位于输入到验证逻辑的切片上"),
    (re.compile(r"Retained symbol identifies (.+) as a program-level entry controller"), "保留的符号表明 {0} 是程序级入口控制函数"),
    (re.compile(r"Directly calls comparison candidate RVA (0x[0-9A-Fa-f]+)"), "直接调用比较候选 RVA {0}"),
    (re.compile(r"Bounded by evidence independence and function attribution \(cap (\d+)\)"), "受证据独立性及函数归属限制（上限 {0}）"),
    (re.compile(r"(?P<confidence>High|Medium) (.+) candidate is (?P<relation>.+)"), "{0}置信度的 {1} 候选：{2}"),
    (re.compile(r"Possible (.+)"), "可能存在 {0} 变换"),
    (re.compile(r"FLOW BREAK @ RVA (0x[0-9A-Fa-f]+)"), "静态追踪中断点 @ RVA {0}"),
    (re.compile(r"(\d+) source-reachable edges recovered"), "已恢复 {0} 条输入来源可达的边"),
    (re.compile(r"last proven edge is (.+) at RVA (0x[0-9A-Fa-f]+)"), "最后证实的边为 {0}，位于 RVA {1}"),
    (re.compile(r"Input-source budget retained (\d+) of (\d+) sources"), "输入来源预算仅保留 {1} 个来源中的 {0} 个"),
    (re.compile(r"BUDGET_LIMIT: Call-depth budget stopped propagation into RVA (0x[0-9A-Fa-f]+)"), "调用深度预算阻止了向 RVA {0} 的传播，分析被截断"),
    (re.compile(r"Direct call target RVA (0x[0-9A-Fa-f]+) has no bounded function model"), "直接调用目标 RVA {0} 没有有界函数模型"),
]


def prose(value, lang=Language.EN):
    if Language(lang) == Language.EN or not isinstance(value, str):
        return value
    if value in PROSE:
        return PROSE[value]
    for pattern, template in PROSE_PATTERNS:
        match = pattern.fullmatch(value)
        if match:
            enum_groups = set(pattern.groupindex.values())
            return template.format(*(display_enum(part, lang) if index in enum_groups else part
                                     for index, part in enumerate(match.groups(), 1)))
    if "; " in value:
        return "；".join(prose(part, lang) for part in value.split("; "))
    match = re.fullmatch(r"Open (.+) in Ghidra/IDA", value)
    if match:
        return "在 Ghidra/IDA 中打开 " + match[1]
    if value.endswith(".") and value[:-1] in PROSE:
        return PROSE[value[:-1]] + "。"
    match = re.fullmatch(r"Comparison reaches branch RVA (0x[0-9A-Fa-f]+)", value)
    if match:
        return "比较结果到达分支 RVA " + match[1]
    if value.startswith("Independent evidence families: "):
        return "独立证据类别：" + value.split(": ", 1)[1]
    match = re.fullmatch(r"No supported critical-function candidate yet. Inspect entry RVA (0x[0-9A-Fa-f]+) and retained string references in Ghidra/IDA.", value)
    if match:
        return "暂无受支持的关键函数候选。请在 Ghidra/IDA 中检查入口 RVA " + match[1] + " 和保留的字符串引用。"
    return value
