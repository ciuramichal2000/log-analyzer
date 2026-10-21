import os, sys; sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import json
import re
from datetime import datetime, timezone

import pytest

from loganalyzer import AnalyzerConfig, LogAnalyzer, analyze, format_text, to_json

UTC = timezone.utc


def test_line_counts_and_malformed_samples_keep_physical_line_numbers(sample_lines, config):
    result = analyze(sample_lines, config)
    assert result.lines_read == 17  # 18 physical lines minus the blank one
    assert result.parsed == 15
    assert result.malformed == 2
    first, second = result.malformed_samples
    assert first.line_number == 7  # numbering counts the blank line 8 as well
    assert first.text == "this is not a log line"
    assert second.line_number == 11
    assert "month" in second.reason
    assert second.text.startswith("192.0.2.4")


def test_top_paths_are_sorted_by_count_then_name_and_ignore_query_strings(sample_lines, config):
    result = analyze(sample_lines, config)
    # /api/items x5; /api/login x3 and /index.html x3 (one with ?utm=x) tie, so alphabetical.
    assert result.top_paths == (("/api/items", 5), ("/api/login", 3), ("/index.html", 3))


def test_status_classes_are_bucketed_per_utc_minute(sample_lines, config):
    result = analyze(sample_lines, config)
    assert result.status_per_minute == {
        "2024-03-05T10:00Z": {"2xx": 3, "4xx": 5},  # lines 1-3 ok; 4-6 are 404, 9-10 are 401
        "2024-03-05T10:02Z": {"4xx": 1},  # line 12
        "2024-03-05T10:05Z": {"2xx": 2, "5xx": 3},  # lines 13-17
        "2024-03-05T10:07Z": {"3xx": 1},  # line 18: 12:07 at +0200 is 10:07 UTC
    }


def test_requests_per_ip_and_the_suspicious_flag(sample_lines, config):
    result = analyze(sample_lines, config)
    assert result.distinct_ips == 5
    # 192.0.2.1 has 5 requests; three IPs tie on 3 and are ordered by address text.
    assert [(stat.ip, stat.requests) for stat in result.top_ips] == [
        ("192.0.2.1", 5),
        ("192.0.2.2", 3),
        ("198.51.100.7", 3),
    ]
    assert [stat.ip for stat in result.suspicious_ips] == ["198.51.100.7"]
    assert result.suspicious_ips[0].reasons == ("many_404",)
    assert result.top_ips[2].suspicious  # same IP shows its flag in the top table
    assert not result.top_ips[0].suspicious


def test_slow_401s_do_not_make_an_ip_suspicious(sample_lines, config):
    result = analyze(sample_lines, config)
    # 203.0.113.9 has three 401s at +40 s, +50 s and +150 s: 110 s apart end to end.
    assert "203.0.113.9" not in [stat.ip for stat in result.suspicious_ips]


def test_response_time_percentiles_use_only_lines_that_have_a_time(sample_lines, config):
    result = analyze(sample_lines, config)
    timing = result.response_time
    # Nine samples (seconds): 0.005 x3, 0.010, 0.020, 0.030, 0.100 x3.
    # Nearest rank: p50 -> ceil(4.5) = 5th = 0.020; p95 and p99 -> 9th = 0.100.
    assert timing.samples == 9
    assert timing.p50_ms == 20.0
    assert timing.p95_ms == 100.0
    assert timing.p99_ms == 100.0
    assert timing.max_ms == 100.0


def test_error_burst_is_found_and_closed_by_later_traffic(sample_lines, config):
    result = analyze(sample_lines, config)
    (burst,) = result.error_bursts
    # At 10:05:30 the 60 s window holds lines 13-16: 3 of 4 failed (0.75 > 0.5).
    assert burst.start == datetime(2024, 3, 5, 10, 5, 30, tzinfo=UTC)
    # At 10:05:40 it is 3 of 5 = 0.6 (still a burst); line 18 empties the window.
    assert burst.end == datetime(2024, 3, 5, 10, 5, 40, tzinfo=UTC)
    assert burst.peak_rate == pytest.approx(0.75)
    assert (burst.peak_errors, burst.peak_requests) == (3, 4)


def test_period_and_total_bytes(sample_lines, config):
    result = analyze(sample_lines, config)
    assert result.first_seen == datetime(2024, 3, 5, 10, 0, 0, tzinfo=UTC)
    assert result.last_seen == datetime(2024, 3, 5, 10, 7, 15, tzinfo=UTC)
    # 100+200+300 + 10*3 + 50*3 + 1000 + 20*3 + 1000; line 18 has "-" and adds nothing.
    assert result.total_bytes_sent == 2840


def test_period_uses_the_earliest_and_latest_timestamps_not_the_first_and_last_lines(make_line):
    # Arrival order is 10:00:05, 10:00:00, 10:00:09, 10:00:03: neither end of the file holds an extreme.
    clocks = ["10:00:05", "10:00:00", "10:00:09", "10:00:03"]
    lines = [make_line("192.0.2.1", clock, "GET / HTTP/1.1", 200) for clock in clocks]
    result = analyze(lines)
    assert result.first_seen == datetime(2024, 3, 5, 10, 0, 0, tzinfo=UTC)
    assert result.last_seen == datetime(2024, 3, 5, 10, 0, 9, tzinfo=UTC)


def test_lines_count_as_soon_as_they_are_fed_and_results_can_be_read_mid_stream(sample_lines, config):
    analyzer = LogAnalyzer(config)
    parsed_after_each_line = []
    for text in sample_lines[:16]:
        analyzer.feed_line(text)
        parsed_after_each_line.append(analyzer.result().parsed)
    # Lines 7 (bad), 8 (blank) and 11 (bad) do not advance the count.
    assert parsed_after_each_line == [1, 2, 3, 4, 5, 6, 6, 6, 7, 8, 8, 9, 10, 11, 12, 13]

    (burst,) = analyzer.result().error_bursts  # burst still open at line 16
    assert burst.end == datetime(2024, 3, 5, 10, 5, 30, tzinfo=UTC)
    analyzer.feed_line(sample_lines[16])
    (burst,) = analyzer.result().error_bursts  # the same burst, extended, not a second one
    assert burst.end == datetime(2024, 3, 5, 10, 5, 40, tzinfo=UTC)


def test_a_one_shot_generator_gives_the_same_result_as_a_list(sample_lines, config):
    assert analyze(iter(sample_lines), config) == analyze(sample_lines, config)


def test_malformed_samples_are_capped_and_long_lines_are_truncated(config):
    garbage = ["x" * 500] + [f"garbage {n}" for n in range(1, 8)]
    result = analyze(garbage, config)
    assert result.malformed == 8
    assert [sample.line_number for sample in result.malformed_samples] == [1, 2, 3, 4, 5]
    assert len(result.malformed_samples[0].text) == 200


def test_empty_and_blank_input_produce_an_empty_report(config):
    result = analyze(["", "   ", "\n"], config)
    assert (result.lines_read, result.parsed, result.malformed) == (0, 0, 0)
    assert result.first_seen is None and result.last_seen is None
    assert result.top_paths == () and result.error_bursts == ()
    assert result.response_time.samples == 0
    assert result.response_time.p95_ms is None
    text = format_text(result)
    assert "no response times in this log" in text
    assert "(none)" in text


def test_time_unit_setting_changes_how_the_trailing_field_is_read(make_line):
    lines = [make_line("192.0.2.1", "10:00:00", "GET / HTTP/1.1", 200, 1, response_time=250)]
    in_ms = analyze(lines, AnalyzerConfig(time_unit="ms"))
    in_s = analyze(lines, AnalyzerConfig(time_unit="s"))
    assert in_ms.response_time.p50_ms == 250.0
    assert in_s.response_time.p50_ms == 250000.0


@pytest.mark.parametrize(
    "bad_settings",
    [
        {"top_n": 0},
        {"time_unit": "minutes"},
        {"suspicious_threshold": 0},
        {"suspicious_window_seconds": 0},
        {"burst_threshold": 1.0},
        {"burst_window_seconds": -1},
        {"burst_min_requests": 0},
    ],
)
def test_invalid_settings_are_rejected_before_any_line_is_read(bad_settings):
    with pytest.raises(ValueError):
        LogAnalyzer(AnalyzerConfig(**bad_settings))


# --- reports ------------------------------------------------------------------


def test_json_report_has_the_expected_values(sample_lines, config):
    data = json.loads(to_json(analyze(sample_lines, config)))
    assert data["lines"] == {"read": 17, "parsed": 15, "malformed": 2}
    assert data["period"]["first"] == "2024-03-05T10:00:00+00:00"
    assert data["period"]["last"] == "2024-03-05T12:07:15+02:00"  # offset kept as logged
    assert data["top_paths"][0] == {"path": "/api/items", "requests": 5}
    assert data["status_per_minute"]["2024-03-05T10:07Z"] == {"3xx": 1}
    assert data["ips"]["distinct"] == 5
    assert data["ips"]["suspicious"] == [
        {"ip": "198.51.100.7", "requests": 3, "suspicious": True, "reasons": ["many_404"]}
    ]
    assert data["response_time_ms"] == {
        "samples": 9, "p50": 20.0, "p95": 100.0, "p99": 100.0, "max": 100.0,
    }
    assert data["error_bursts"] == [
        {
            "start": "2024-03-05T10:05:30+00:00",
            "end": "2024-03-05T10:05:40+00:00",
            "peak_error_rate": 0.75,
            "peak_errors": 3,
            "peak_requests": 4,
        }
    ]
    assert data["malformed_samples"][1]["line"] == 11


def test_json_report_for_an_empty_log_uses_nulls(config):
    data = json.loads(to_json(analyze([], config)))
    assert data["period"] == {"first": None, "last": None}
    assert data["response_time_ms"]["p50"] is None
    assert data["error_bursts"] == []


def test_text_report_shows_every_section(sample_lines, config):
    text = format_text(analyze(sample_lines, config))
    lines = text.splitlines()

    assert "Lines read: 17  parsed: 15  malformed: 2" in lines
    assert "  line 7: line does not match the access-log format" in lines
    assert "    'this is not a log line'" in lines
    assert re.search(r"^\s+5\s+/api/items$", text, re.MULTILINE)

    minute_row = next(line for line in lines if line.strip().startswith("2024-03-05T10:05Z"))
    assert minute_row.split() == ["2024-03-05T10:05Z", "2", "0", "0", "3"]  # 2xx 3xx 4xx 5xx

    flagged = [line for line in lines if "SUSPICIOUS" in line]
    assert flagged and all("198.51.100.7" in line and "many_404" in line for line in flagged)
    assert "Suspicious IPs: 1" in lines

    assert "  p50: 20.000 ms  p95: 100.000 ms  p99: 100.000 ms" in lines
    burst_line = next(line for line in lines if "peak" in line)
    assert "75.0% 5xx (3 of 4 requests in window)" in burst_line
