import os, sys; sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import io
import json
import subprocess

import pytest

from loganalyzer.cli import main

PROJECT_ROOT = os.path.join(os.path.dirname(__file__), "..")
TUNED_FLAGS = [
    "--suspicious-threshold", "3", "--suspicious-window", "30",
    "--burst-min-requests", "4", "--burst-window", "60",
]


@pytest.fixture
def log_file(tmp_path, sample_lines):
    path = tmp_path / "access.log"
    path.write_bytes(("\n".join(sample_lines) + "\n").encode("utf-8"))
    return str(path)


def run_json(capsys, argv):
    assert main(argv) == 0
    return json.loads(capsys.readouterr().out)


def test_json_output_respects_the_threshold_options(capsys, log_file):
    data = run_json(capsys, [log_file, "--json", "--top", "2", *TUNED_FLAGS])
    assert data["lines"]["malformed"] == 2
    assert len(data["top_paths"]) == 2
    assert [entry["ip"] for entry in data["ips"]["suspicious"]] == ["198.51.100.7"]
    assert len(data["error_bursts"]) == 1


def test_default_thresholds_are_too_high_for_the_small_sample(capsys, log_file):
    data = run_json(capsys, [log_file, "--json"])
    assert data["ips"]["suspicious"] == []  # needs 10 404s in 60 s by default
    assert data["error_bursts"] == []  # needs 10 requests in the window by default


def test_text_output_is_the_default(capsys, log_file):
    assert main([log_file, *TUNED_FLAGS]) == 0
    out = capsys.readouterr().out
    assert out.startswith("Access log report")
    assert "SUSPICIOUS (many_404)" in out


def test_time_unit_option_reaches_the_parser(capsys, tmp_path, make_line):
    path = tmp_path / "timed.log"
    path.write_text(make_line("192.0.2.1", "10:00:00", "GET / HTTP/1.1", 200, 1, 250) + "\n")
    data = run_json(capsys, [str(path), "--json", "--time-unit", "ms"])
    assert data["response_time_ms"]["p50"] == 250.0


def test_missing_file_gives_exit_code_2_and_a_message(capsys, tmp_path):
    missing = str(tmp_path / "nope.log")
    assert main([missing]) == 2
    captured = capsys.readouterr()
    assert "cannot read" in captured.err and "nope.log" in captured.err
    assert captured.out == ""


def test_directory_instead_of_file_is_reported_not_raised(capsys, tmp_path):
    assert main([str(tmp_path)]) == 2
    assert "cannot read" in capsys.readouterr().err


@pytest.mark.parametrize(
    "flags",
    [["--top", "0"], ["--burst-threshold", "1.5"], ["--suspicious-threshold", "0"], ["--time-unit", "h"]],
)
def test_invalid_options_exit_with_usage_error(capsys, log_file, flags):
    with pytest.raises(SystemExit) as exit_info:
        main([log_file, *flags])
    assert exit_info.value.code == 2
    assert capsys.readouterr().err != ""


def test_standard_input_is_read_when_the_path_is_a_dash(capsys, monkeypatch, sample_lines):
    payload = ("\n".join(sample_lines) + "\n").encode("utf-8")
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(io.BytesIO(payload), encoding="utf-8"))
    data = run_json(capsys, ["-", "--json"])
    assert data["lines"] == {"read": 17, "parsed": 15, "malformed": 2}


def test_undecodable_bytes_in_a_line_do_not_abort_the_run(capsys, tmp_path):
    raw = (
        b'192.0.2.1 - - [05/Mar/2024:10:00:00 +0000] "GET /ok HTTP/1.1" 200 5 "-" "bad\xff\xfeagent"\n'
        b'192.0.2.1 - - [05/Mar/2024:10:00:01 +0000] "GET /ok HTTP/1.1" 200 5 "-" "fine"\n'
    )
    path = tmp_path / "binary.log"
    path.write_bytes(raw)
    data = run_json(capsys, [str(path), "--json"])
    assert data["lines"] == {"read": 2, "parsed": 2, "malformed": 0}


def test_module_entry_point_runs_end_to_end(log_file):
    completed = subprocess.run(
        [sys.executable, "-m", "loganalyzer", log_file, "--json"],
        cwd=PROJECT_ROOT, capture_output=True, text=True, timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout)["lines"]["parsed"] == 15
