from pathlib import Path

import pytest

from reversehelper import cli


def test_help_describes_target_and_examples(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--help"])

    assert exc_info.value.code == 0
    output = capsys.readouterr().out
    assert "Static Windows PE triage" in output
    assert "target" in output
    assert "reversehelper sample.exe" in output
    assert "--quick" in output
    assert "--only anomaly" in output


def test_version_is_v0_0_2(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["--version"])

    assert exc_info.value.code == 0
    assert capsys.readouterr().out.strip() == "ReverseHelper 0.0.2"


def test_missing_target_shows_usage_without_traceback(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main([])

    assert exc_info.value.code == 2
    error = capsys.readouterr().err
    assert "the following arguments are required: target" in error
    assert "Traceback" not in error


def test_default_command_runs_complete_analyzer_for_path_with_spaces(tmp_path, monkeypatch):
    target = tmp_path / "path with spaces" / "sample.exe"
    target.parent.mkdir()
    target.write_bytes(b"MZ")
    calls = []

    class RecordingAnalyzer:
        def __init__(self, minimum_string_length, maximum_strings):
            calls.append((minimum_string_length, maximum_strings))

        def analyze(self, path):
            calls.append(path)
            return {"complete": True}

    monkeypatch.setattr(cli, "ReverseHelperAnalyzer", RecordingAnalyzer)
    monkeypatch.setattr(cli, "print_analysis", lambda result: calls.append(result))

    assert cli.main([str(target)]) == 0
    assert calls == [(4, 2000), Path(target), {"complete": True}]


@pytest.mark.parametrize(
    ("arguments", "expected_call", "expected_print"),
    [
        (["--quick"], ("quick",), ("quick",)),
        (["--only", "anomaly"], ("module", "anomaly"), ("module", "anomaly")),
        (["--only", "strings"], ("module", "strings"), ("module", "strings")),
        (["--only", "imports"], ("module", "imports"), ("module", "imports")),
    ],
)
def test_analysis_mode_dispatch(tmp_path, monkeypatch, arguments, expected_call, expected_print):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")
    calls = []

    class RecordingAnalyzer:
        def __init__(self, minimum_string_length, maximum_strings):
            pass

        def analyze_quick(self, path):
            calls.append(("quick",))
            return {"mode": "quick"}

        def analyze_module(self, path, module):
            calls.append(("module", module))
            return {"mode": module}

    monkeypatch.setattr(cli, "ReverseHelperAnalyzer", RecordingAnalyzer)
    monkeypatch.setattr(cli, "print_quick_analysis", lambda result: calls.append(("quick",)))
    monkeypatch.setattr(
        cli,
        "print_module_analysis",
        lambda result, module: calls.append(("module", module)),
    )

    assert cli.main([str(target), *arguments]) == 0
    assert calls == [expected_call, expected_print]


def test_quick_and_only_are_mutually_exclusive(capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["sample.exe", "--quick", "--only", "strings"])

    assert exc_info.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


@pytest.mark.parametrize("mode", [["--quick"], ["--only", "imports"]])
def test_partial_modes_reject_full_report_options(mode, capsys):
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["sample.exe", *mode, "--report"])

    assert exc_info.value.code == 2
    assert "report options require the default full analysis mode" in capsys.readouterr().err


@pytest.mark.parametrize(
    ("target_factory", "expected_error"),
    [
        (lambda tmp_path: tmp_path / "nonexistent.exe", "Input file does not exist"),
        (lambda tmp_path: tmp_path, "Input path is a directory"),
    ],
)
def test_invalid_input_path_is_a_clean_cli_error(tmp_path, target_factory, expected_error, capsys):
    assert cli.main([str(target_factory(tmp_path))]) == 2

    error = capsys.readouterr().err
    assert expected_error in error
    assert "Traceback" not in error


def test_non_pe_file_is_a_clean_cli_error(tmp_path, capsys):
    target = tmp_path / "plain.txt"
    target.write_text("not a PE", encoding="utf-8")

    assert cli.main([str(target)]) == 2

    error = capsys.readouterr().err
    assert "Input is not a PE file: missing MZ signature" in error
    assert "Traceback" not in error


def test_unreadable_file_is_a_clean_cli_error(tmp_path, monkeypatch, capsys):
    target = tmp_path / "sample.exe"
    target.write_bytes(b"MZ")
    original_read_bytes = Path.read_bytes

    def fail_for_target(path):
        if path == target.resolve():
            raise PermissionError(13, "Permission denied", str(path))
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", fail_for_target)

    assert cli.main([str(target)]) == 2

    error = capsys.readouterr().err
    assert "Could not read input file" in error
    assert "Traceback" not in error
