import os, sys; sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from loganalyzer import AnalyzerConfig


def build_line(ip, clock, request, status, size=100, response_time=None, zone="+0000"):
    """One invented combined-format line on 2024-03-05, optionally with a response time."""
    tail = "" if response_time is None else f" {response_time}"
    return (
        f'{ip} - - [05/Mar/2024:{clock} {zone}] "{request}" {status} {size} '
        f'"-" "test-agent"{tail}'
    )


@pytest.fixture
def make_line():
    return build_line


@pytest.fixture
def config():
    """Small thresholds so the invented log below can trigger every detector."""
    return AnalyzerConfig(
        top_n=3,
        suspicious_threshold=3,
        suspicious_window_seconds=30,
        burst_threshold=0.5,
        burst_window_seconds=60,
        burst_min_requests=4,
    )


@pytest.fixture
def sample_lines():
    """18 physical lines: 15 valid, 2 malformed (7 and 11), 1 blank (8).

    Facts the tests rely on, worked out by hand from this list:
      * 404 x3 from 198.51.100.7 within 9 s -> suspicious; the three 401s from
        203.0.113.9 span 110 s -> not suspicious at a 30 s window.
      * lines 14-16 are 5xx; at line 16 the window holds 4 requests, 3 failed.
      * line 18 is 12:07:15 at +0200, i.e. 10:07:15 UTC.
    """
    return [
        build_line("192.0.2.1", "10:00:00", "GET /index.html HTTP/1.1", 200, 100, "0.010"),  # 1
        build_line("192.0.2.1", "10:00:05", "GET /index.html HTTP/1.1", 200, 200, "0.020"),  # 2
        build_line("192.0.2.2", "10:00:10", "GET /about HTTP/1.1", 200, 300, "0.030"),  # 3
        build_line("198.51.100.7", "10:00:20", "GET /wp-login.php HTTP/1.1", 404, 10, "0.005"),  # 4
        build_line("198.51.100.7", "10:00:25", "GET /admin HTTP/1.1", 404, 10, "0.005"),  # 5
        build_line("198.51.100.7", "10:00:29", "GET /.env HTTP/1.1", 404, 10, "0.005"),  # 6
        "this is not a log line",  # 7 malformed
        "",  # 8 blank
        build_line("203.0.113.9", "10:00:40", "POST /api/login HTTP/1.1", 401, 50, "0.100"),  # 9
        build_line("203.0.113.9", "10:00:50", "POST /api/login HTTP/1.1", 401, 50, "0.100"),  # 10
        '192.0.2.4 - - [05/Foo/2024:10:01:00 +0000] "GET /x HTTP/1.1" 200 5 "-" "test-agent"',  # 11 malformed
        build_line("203.0.113.9", "10:02:30", "POST /api/login HTTP/1.1", 401, 50, "0.100"),  # 12
        build_line("192.0.2.1", "10:05:00", "GET /api/items HTTP/1.1", 200, 1000),  # 13
        build_line("192.0.2.1", "10:05:10", "GET /api/items HTTP/1.1", 500, 20),  # 14
        build_line("192.0.2.2", "10:05:20", "GET /api/items HTTP/1.1", 502, 20),  # 15
        build_line("192.0.2.2", "10:05:30", "GET /api/items HTTP/1.1", 503, 20),  # 16
        build_line("192.0.2.1", "10:05:40", "GET /api/items HTTP/1.1", 200, 1000),  # 17
        build_line("192.0.2.3", "12:07:15", "GET /index.html?utm=x HTTP/1.1", 301, "-", zone="+0200"),  # 18
    ]
