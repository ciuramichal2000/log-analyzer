import os, sys; sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timedelta, timezone

import pytest

from loganalyzer import LogParseError, parse_line

COMBINED = (
    '192.0.2.10 - alice [05/Mar/2024:10:15:30 +0000] "GET /shop/item?id=7&ref=mail HTTP/1.1" '
    '200 5120 "https://example.test/start" "Mozilla/5.0 (X11; Linux)" 0.125'
)


def test_combined_line_with_response_time_is_parsed_field_by_field():
    entry = parse_line(COMBINED)
    assert entry.ip == "192.0.2.10"
    assert entry.timestamp == datetime(2024, 3, 5, 10, 15, 30, tzinfo=timezone.utc)
    assert entry.method == "GET"
    assert entry.path == "/shop/item"  # query string is dropped so variants merge
    assert entry.status == 200
    assert entry.bytes_sent == 5120
    assert entry.response_time == pytest.approx(0.125)


def test_line_without_trailing_time_has_no_response_time():
    line = COMBINED.rsplit(" ", 1)[0]
    assert parse_line(line).response_time is None


def test_common_format_without_referer_and_agent_is_accepted():
    line = '198.51.100.4 - - [05/Mar/2024:10:15:30 +0000] "HEAD /health HTTP/1.0" 204 -'
    entry = parse_line(line)
    assert (entry.method, entry.path, entry.status) == ("HEAD", "/health", 204)
    assert entry.bytes_sent is None  # "-" means nothing was sent


def test_timezone_offset_is_applied_to_the_instant():
    east = parse_line('192.0.2.1 - - [05/Mar/2024:12:00:00 +0530] "GET / HTTP/1.1" 200 1')
    west = parse_line('192.0.2.1 - - [05/Mar/2024:12:00:00 -0700] "GET / HTTP/1.1" 200 1')
    assert east.timestamp.utcoffset() == timedelta(hours=5, minutes=30)
    # 12:00 at +05:30 is 06:30 UTC; 12:00 at -07:00 is 19:00 UTC.
    assert east.timestamp == datetime(2024, 3, 5, 6, 30, tzinfo=timezone.utc)
    assert west.timestamp == datetime(2024, 3, 5, 19, 0, tzinfo=timezone.utc)


@pytest.mark.parametrize(
    ("unit", "raw", "expected_seconds"),
    [("s", "1.5", 1.5), ("ms", "250", 0.25), ("us", "1500000", 1.5)],
)
def test_time_unit_converts_trailing_field_to_seconds(unit, raw, expected_seconds):
    line = (
        '192.0.2.1 - - [05/Mar/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 1 "-" "curl/8" ' + raw
    )
    assert parse_line(line, time_unit=unit).response_time == pytest.approx(expected_seconds)


def test_escaped_quote_inside_user_agent_does_not_break_the_line():
    line = (
        '192.0.2.1 - - [05/Mar/2024:10:00:00 +0000] "GET /a HTTP/1.1" 200 10 '
        r'"-" "Odd \"agent\" name" 0.5'
    )
    entry = parse_line(line)
    assert entry.path == "/a"
    assert entry.response_time == pytest.approx(0.5)


def test_request_without_method_keeps_raw_text_as_path():
    line = '203.0.113.5 - - [05/Mar/2024:10:00:00 +0000] "-" 408 0 "-" "-"'
    entry = parse_line(line)
    assert entry.method == ""
    assert entry.path == "-"
    assert entry.status == 408


def test_trailing_newline_and_carriage_return_are_ignored():
    assert parse_line(COMBINED + "\r\n").status == 200


@pytest.mark.parametrize(
    "line",
    [
        "",
        "this is not a log line",
        '192.0.2.1 - - [05/Mar/2024:10:00:00 +0000] "GET / HTTP/1.1" 20 5',  # 2-digit status
        '192.0.2.1 - - [05/Mar/2024:10:00:00 +0000] "GET / HTTP/1.1" 999 5',  # status out of range
        '192.0.2.1 - - [05/Mar/2024:10:00:00 +0000] "GET / HTTP/1.1" 099 5',
        '192.0.2.1 - - [05/Foo/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 5',  # unknown month
        '192.0.2.1 - - [31/Feb/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 5',  # impossible date
        '192.0.2.1 - - [05/Mar/2024:25:00:00 +0000] "GET / HTTP/1.1" 200 5',  # hour 25
        '192.0.2.1 - - [05/Mar/2024:10:00:00 +9900] "GET / HTTP/1.1" 200 5',  # offset > 24h
        '192.0.2.1 - - [05/Mar/2024:10:00:00 +0000] "GET / HTTP/1.1" 200',  # no size
        '192.0.2.1 - - [05/Mar/2024:10:00:00 +0000] "GET / HTTP/1.1" 200 5 "-" "ua" fast',  # non-numeric time
        '192.0.2.1 - - [05/Mar/2024:10:00:00 +0000] "GET / HTTP/1.1 200 5',  # unterminated request
    ],
)
def test_malformed_lines_raise_log_parse_error(line):
    with pytest.raises(LogParseError):
        parse_line(line)


def test_unknown_time_unit_is_a_caller_error_not_a_parse_error():
    with pytest.raises(ValueError, match="unknown time unit") as info:
        parse_line(COMBINED, time_unit="minutes")
    assert not isinstance(info.value, LogParseError)
