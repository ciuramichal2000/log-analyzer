"""Parse one line of an Apache/nginx access log into a LogEntry.

The parser is strict about structure and never guesses: a line either yields a
complete LogEntry or raises LogParseError with the reason. That lets the caller
count and report bad lines instead of silently skewing the statistics.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Multiplier that converts the trailing response-time field to seconds.
# nginx $request_time is seconds, Apache %D is microseconds, %{ms}T is milliseconds.
TIME_UNITS: dict[str, float] = {"s": 1.0, "ms": 0.001, "us": 0.000001}

_MONTHS = {
    name: number
    for number, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}

# Quoted fields allow backslash-escaped characters (Apache writes \" inside
# them). The two alternatives never overlap, so matching stays linear-time.
_LINE_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?:[^"\\]|\\.)*" "(?:[^"\\]|\\.)*"(?: (?P<rt>\d+(?:\.\d+)?))?)?$'
)

_TIME_RE = re.compile(
    r"^(\d{2})/([A-Za-z]{3})/(\d{4}):(\d{2}):(\d{2}):(\d{2}) ([+-])(\d{2})(\d{2})$"
)


class LogParseError(ValueError):
    """Raised when a line is not a valid access-log record."""


@dataclass(frozen=True, slots=True)
class LogEntry:
    """The fields of one request that the analyzer needs."""

    ip: str
    timestamp: datetime  # timezone-aware, in the offset written in the log
    method: str  # empty when the request line could not be split
    path: str  # request target without the query string
    status: int
    bytes_sent: int | None
    response_time: float | None  # seconds, None when the log has no such field


def _parse_timestamp(text: str) -> datetime:
    """Parse '10/Oct/2000:13:55:36 -0700' without depending on the locale.

    strptime's %b follows the process locale, which would make the same log
    parse differently on different machines.
    """
    match = _TIME_RE.match(text)
    if match is None:
        raise LogParseError(f"bad timestamp {text!r}")
    day, month_name, year, hour, minute, second, sign, tz_hours, tz_minutes = match.groups()
    month = _MONTHS.get(month_name.title())
    if month is None:
        raise LogParseError(f"bad month {month_name!r} in timestamp {text!r}")
    offset = timedelta(hours=int(tz_hours), minutes=int(tz_minutes))
    if sign == "-":
        offset = -offset
    try:
        return datetime(
            int(year), month, int(day), int(hour), int(minute), int(second),
            tzinfo=timezone(offset),
        )
    except ValueError as error:
        raise LogParseError(f"impossible timestamp {text!r}: {error}") from error


def parse_line(line: str, time_unit: str = "s") -> LogEntry:
    """Parse a single access-log line.

    Accepts the combined format, the common format (no referer/user agent) and
    either of them followed by one numeric response-time field.

    Raises:
        ValueError: ``time_unit`` is not one of TIME_UNITS (a caller mistake).
        LogParseError: the line is not a valid record.
    """
    if time_unit not in TIME_UNITS:
        raise ValueError(f"unknown time unit {time_unit!r}; expected one of {sorted(TIME_UNITS)}")
    match = _LINE_RE.match(line.rstrip())
    if match is None:
        raise LogParseError("line does not match the access-log format")

    status = int(match["status"])
    if not 100 <= status <= 599:
        raise LogParseError(f"status {status} is outside 100-599")

    request_parts = match["request"].split(" ")
    if len(request_parts) >= 2:
        method, target = request_parts[0], request_parts[1]
    else:
        # Probes and timed-out connections log things like "-" or raw bytes.
        method, target = "", match["request"]

    size = None if match["size"] == "-" else int(match["size"])
    response_time = (
        None if match["rt"] is None else float(match["rt"]) * TIME_UNITS[time_unit]
    )
    return LogEntry(
        ip=match["ip"],
        timestamp=_parse_timestamp(match["time"]),
        method=method,
        path=target.split("?", 1)[0],
        status=status,
        bytes_sent=size,
        response_time=response_time,
    )
