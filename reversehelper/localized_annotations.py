"""Localize annotation prose on an export copy; preserve every machine field."""

from copy import deepcopy

from .localization import Language, display_enum, message, prose


def annotation_export(result, lang=Language.EN):
    if Language(lang) == Language.EN:
        return result
    exported = deepcopy(result)
    summary = result.get("challenge_summary", {})
    for item in exported.get("annotations", []):
        category = item["category"]
        title = display_enum(prose(item["title"], lang), lang)
        original = item["comment"]
        if original.startswith("Static path: "):
            comment = "静态路径：" + display_enum(prose(original.partition(": ")[2], lang), lang)
        elif category == "RH:START":
            title = message("summary.start_here", lang)
            start = summary.get("start_here") or {}
            comment = "原因：" + prose(start.get("reason", ""), lang) + "\n建议下一步：" + prose(start.get("action", ""), lang)
        elif category == "RH:INPUT":
            comment = "输入来源候选：" + title
        elif category == "RH:VALIDATION":
            comment = "验证逻辑候选。请检查操作数以及两个分支的结果。"
        elif category == "RH:SLICE":
            comment = "此变换位于有界静态输入路径上。"
        elif category == "RH:FLOW_BREAK":
            reason = original.partition("Reason: ")[2].partition("\n")[0]
            comment = "静态追踪在此中断。\n原因：" + prose(reason, lang) + "\n建议：手动检查未解析的控制转移、函数返回值及调用方对它的使用。"
        elif category == "RH:ALGORITHM":
            comment = "算法候选：" + title + "。请手动检查常量、位宽和数据对象。"
        elif category.startswith("RH:SUGGEST_"):
            proposed = original.partition("Suggested semantic: ")[2].partition("\n")[0]
            comment = "建议语义：" + proposed + "\n应用前请先复查；不会自动重命名。"
        else:
            action = original.partition("Suggested: ")[2]
            comment = "控制流候选：" + title + ("\n建议：" + prose(action, lang) if action else "")
        item["title"] = title
        item["comment"] = "[ReverseHelper]\n" + title + "\n置信度：" + display_enum(item["confidence"], lang) + "\n" + comment
        if item.get("evidence"):
            item["comment"] += "\n证据：\n" + "\n".join("- " + prose(str(value), lang) for value in item["evidence"][:8])
    return exported
