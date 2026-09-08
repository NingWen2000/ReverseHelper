"""Development-only Windows portable language matrix; never executes target PEs."""

import argparse
import json
import os
from pathlib import Path
import shutil
import statistics
import subprocess
import sys
import timeit

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "tests")]
from p0_support import write_pe
from reversehelper.challenge_summary import summary_lines


def facts(value):
    if isinstance(value, dict):
        return {key: facts(item) for key, item in value.items()
                if key not in {"analyzed_at_utc", "module_timings_ms"} and not key.endswith("elapsed_ms")}
    if isinstance(value, list):
        return [facts(item) for item in value]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("executable", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "build/localization-validation")
    args = parser.parse_args()
    directory = args.output.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    folder = directory / "用户 测试" / "Desktop" / "题目"
    folder.mkdir(parents=True, exist_ok=True)
    executable = folder / "ReverseHelper.exe"
    shutil.copy2(args.executable.resolve(), executable)
    environment = {**os.environ, "PYTHONIOENCODING": "utf-8", "COLUMNS": "120"}
    matrix = []
    for x64 in (False, True):
        target = write_pe(folder / ("逆向64.exe" if x64 else "逆向32.exe"), api="memcmp", x64=x64)
        for mode in ("quick", "deep"):
            analyses = []
            for language in ("en", "zh-CN"):
                output = folder / (target.stem + "-" + mode + "-" + language)
                output.mkdir(exist_ok=True)
                command = [str(target), "--" + mode, "--lang", language, "--report", str(output),
                           "--json", str(output / "plain.json"), "--ghidra", str(output / "annotations.json")]
                run = subprocess.run([str(executable), *command], cwd=ROOT, capture_output=True, env=environment, timeout=120)
                assert run.returncode == 0, run.stderr.decode("utf-8", errors="replace")
                # Frozen Python may ignore PYTHONIOENCODING; English preserves its
                # existing OEM stream encoding, Chinese explicitly emits UTF-8 pipes.
                try:
                    text = run.stdout.decode("utf-8")
                except UnicodeDecodeError:
                    assert language == "en"
                    text = run.stdout.decode("gbk")
                assert ("题目摘要" if language == "zh-CN" else "Challenge Summary") in text
                assert "逆向" in text and "UnicodeEncodeError" not in run.stderr.decode("utf-8")
                (output / "console.txt").write_text(text, encoding="utf-8")
                payload = json.loads((output / "plain.json").read_text(encoding="utf-8"))
                annotations = json.loads((output / "annotations.json").read_text(encoding="utf-8"))
                for before, after in zip(payload["annotations"], annotations["annotations"], strict=True):
                    assert {key: value for key, value in before.items() if key not in {"title", "comment"}} == {key: value for key, value in after.items() if key not in {"title", "comment"}}
                if language == "zh-CN":
                    assert any("建议从这里开始" in item["comment"] for item in annotations["annotations"])
                report = (output / (target.stem + "_report.md")).read_text(encoding="utf-8")
                assert ("题目摘要" if language == "zh-CN" else "Challenge Summary") in report
                analyses.append(facts(payload))
                source = subprocess.run([sys.executable, "-m", "reversehelper", str(target), "--" + mode,
                                         "--lang", language, "--quiet", "--json", str(output / "source.json")],
                                        cwd=ROOT, capture_output=True, env=environment, timeout=120)
                assert source.returncode == 0
                assert facts(json.loads((output / "source.json").read_text(encoding="utf-8"))) == facts(payload)
                matrix.append({"architecture": "x64" if x64 else "x86", "mode": mode, "language": language,
                               "portable_source_equal": True, "reports": True, "ghidra": True, "json": True})
            assert analyses[0] == analyses[1]

    shells = []
    for shell in ("cmd.exe", "pwsh.exe", "powershell.exe"):
        resolved = shutil.which(shell)
        if not resolved:
            shells.append({"shell": shell, "status": "unavailable"})
            continue
        if shell == "cmd.exe":
            command = [resolved, "/d", "/c", "ReverseHelper.exe --lang zh-CN --help"]
        else:
            command = [resolved, "-NoProfile", "-NonInteractive", "-Command", "& '" + str(executable).replace("'", "''") + "' --lang zh-CN --help"]
        run = subprocess.run(command, cwd=executable.parent, capture_output=True, env=environment, timeout=120)
        # Shells may transcode their own redirected output to the Windows OEM encoding.
        encodings = [encoding for encoding in ("utf-8", "gbk") if "界面语言" in run.stdout.decode(encoding, errors="replace")]
        shells.append({"shell": shell, "exit_code": run.returncode, "readable_encodings": encodings,
                       "status": "passed" if run.returncode == 0 and encodings else "failed"})
        (directory / (shell + ".stdout.bin")).write_bytes(run.stdout)

    fixture = json.loads((ROOT / "tests/golden/localization/rich-input.json").read_text(encoding="utf-8"))
    timing = {}
    for language in ("en", "zh-CN"):
        samples = timeit.repeat(lambda: summary_lines(fixture, lang=language), repeat=7, number=300)
        timing[language] = round(statistics.median(samples) * 1000 / 300, 4)
    summary = {"matrix": matrix, "shells": shells, "render_median_ms": timing,
               "measurement": "7 batches of 300 rich-summary renders per language; median per-render time",
               "boundaries": ["Current Windows host only; no independent clean machine", "No interactive Windows Terminal visual check", "Ghidra importer planning tested, real Ghidra UI not exercised"]}
    (directory / "validation.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, ensure_ascii=True))
    return 1 if any(item["status"] == "failed" for item in shells) else 0


if __name__ == "__main__":
    raise SystemExit(main())
