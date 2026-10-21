"""Single-pass log analysis: feed lines in, get an AnalysisResult out."""

import heapq
from array import array
from collections import Counter, defaultdict
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .detectors import Burst, ErrorBurstDetector, ScanDetector, percentile
from .parser import TIME_UNITS, LogParseError, parse_line

MAX_MALFORMED_SAMPLES = 5
MAX_SAMPLE_CHARS = 200

_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class AnalyzerConfig:
    """Tunable limits. Defaults suit a small public web server."""

    top_n: int = 10
    time_unit: str = "s"
    suspicious_threshold: int = 10
    suspicious_window_seconds: float = 60.0
    burst_threshold: float = 0.5
    burst_window_seconds: float = 60.0
    burst_min_requests: int = 10

    def __post_init__(self) -> None:
        if self.top_n < 1:
            raise ValueError(f"top_n must be at least 1, got {self.top_n}")
        if self.time_unit not in TIME_UNITS:
            raise ValueError(f"unknown time unit {self.time_unit!r}; expected one of {sorted(TIME_UNITS)}")
        # The detector arguments are validated by the detectors themselves.


@dataclass(frozen=True)
class MalformedLine:
    """A line that could not be parsed, kept so the report can show why."""

    line_number: int
    reason: str
    text: str


@dataclass(frozen=True)
class IpStat:
    """Request count for one client and the reasons it was flagged, if any."""

    ip: str
    requests: int
    reasons: tuple[str, ...]

    @property
    def suspicious(self) -> bool:
        return bool(self.reasons)


@dataclass(frozen=True)
class ResponseTimeStats:
    """Latency percentiles in milliseconds; None when no line carried a time."""

    samples: int
    p50_ms: float | None
    p95_ms: float | None
    p99_ms: float | None
    max_ms: float | None


@dataclass(frozen=True)
class AnalysisResult:
    """Everything the report needs, independent of how it is rendered."""

    lines_read: int
    parsed: int
    malformed: int
    malformed_samples: tuple[MalformedLine, ...]
    first_seen: datetime | None
    last_seen: datetime | None
    total_bytes_sent: int
    top_paths: tuple[tuple[str, int], ...]
    status_per_minute: dict[str, dict[str, int]]
    distinct_ips: int
    top_ips: tuple[IpStat, ...]
    suspicious_ips: tuple[IpStat, ...]
    response_time: ResponseTimeStats
    error_bursts: tuple[Burst, ...]

    def to_dict(self) -> dict:
        """JSON-ready structure (datetimes become ISO-8601 strings)."""

        def ip_dict(stat: IpStat) -> dict:
            return {
                "ip": stat.ip,
                "requests": stat.requests,
                "suspicious": stat.suspicious,
                "reasons": list(stat.reasons),
            }

        return {
            "lines": {
                "read": self.lines_read,
                "parsed": self.parsed,
                "malformed": self.malformed,
            },
            "malformed_samples": [
                {"line": sample.line_number, "reason": sample.reason, "text": sample.text}
                for sample in self.malformed_samples
            ],
            "period": {
                "first": self.first_seen.isoformat() if self.first_seen else None,
                "last": self.last_seen.isoformat() if self.last_seen else None,
            },
            "total_bytes_sent": self.total_bytes_sent,
            "top_paths": [{"path": path, "requests": count} for path, count in self.top_paths],
            "status_per_minute": self.status_per_minute,
            "ips": {
                "distinct": self.distinct_ips,
                "top": [ip_dict(stat) for stat in self.top_ips],
                "suspicious": [ip_dict(stat) for stat in self.suspicious_ips],
            },
            "response_time_ms": {
                "samples": self.response_time.samples,
                "p50": self.response_time.p50_ms,
                "p95": self.response_time.p95_ms,
                "p99": self.response_time.p99_ms,
                "max": self.response_time.max_ms,
            },
            "error_bursts": [
                {
                    "start": burst.start.isoformat(),
                    "end": burst.end.isoformat(),
                    "peak_error_rate": round(burst.peak_rate, 4),
                    "peak_errors": burst.peak_errors,
                    "peak_requests": burst.peak_requests,
                }
                for burst in self.error_bursts
            ],
        }


def _count_desc_then_key(item: tuple[str, int]) -> tuple[int, str]:
    """Sort key: highest count first, ties broken alphabetically for stable output."""
    return (-item[1], item[0])


def _minute_label(minute_index: int) -> str:
    """UTC label for a minute counted from the Unix epoch, e.g. 2024-03-05T10:15Z."""
    moment = _EPOCH + timedelta(minutes=minute_index)
    return moment.strftime("%Y-%m-%dT%H:%MZ")


class LogAnalyzer:
    """Consumes access-log lines one at a time and accumulates statistics.

    The log lines themselves are never stored. Memory grows with the number of
    distinct paths, IPs and minutes, with the requests inside the error-burst
    window, and by eight bytes per response-time sample.
    """

    def __init__(self, config: AnalyzerConfig | None = None) -> None:
        self._config = config or AnalyzerConfig()
        self._scan = ScanDetector(
            self._config.suspicious_threshold, self._config.suspicious_window_seconds
        )
        self._bursts = ErrorBurstDetector(
            self._config.burst_threshold,
            self._config.burst_window_seconds,
            self._config.burst_min_requests,
        )
        self._line_number = 0
        self._lines_read = 0
        self._parsed = 0
        self._malformed = 0
        self._malformed_samples: list[MalformedLine] = []
        self._first_seen: datetime | None = None
        self._last_seen: datetime | None = None
        self._total_bytes = 0
        self._paths: Counter[str] = Counter()
        self._ips: Counter[str] = Counter()
        self._minutes: defaultdict[int, Counter[int]] = defaultdict(Counter)
        self._response_times = array("d")  # seconds

    def feed_line(self, line: str) -> None:
        """Process one raw line. Blank lines are skipped; bad lines are counted."""
        self._line_number += 1
        if not line.strip():
            return
        self._lines_read += 1
        try:
            entry = parse_line(line, self._config.time_unit)
        except LogParseError as error:
            self._malformed += 1
            if len(self._malformed_samples) < MAX_MALFORMED_SAMPLES:
                self._malformed_samples.append(
                    MalformedLine(self._line_number, str(error), line.rstrip()[:MAX_SAMPLE_CHARS])
                )
            return

        self._parsed += 1
        epoch = entry.timestamp.timestamp()
        if self._first_seen is None or entry.timestamp < self._first_seen:
            self._first_seen = entry.timestamp
        if self._last_seen is None or entry.timestamp > self._last_seen:
            self._last_seen = entry.timestamp
        if entry.bytes_sent is not None:
            self._total_bytes += entry.bytes_sent
        self._paths[entry.path] += 1
        self._ips[entry.ip] += 1
        self._minutes[int(epoch // 60)][entry.status // 100] += 1
        if entry.response_time is not None:
            self._response_times.append(entry.response_time)
        self._scan.observe(entry.ip, entry.status, epoch)
        self._bursts.observe(entry.timestamp, entry.status)

    def result(self) -> AnalysisResult:
        """Snapshot of the statistics so far; safe to call repeatedly."""
        top_n = self._config.top_n
        top_paths = heapq.nsmallest(top_n, self._paths.items(), key=_count_desc_then_key)
        top_ips = tuple(
            IpStat(ip, count, self._scan.reasons_for(ip))
            for ip, count in heapq.nsmallest(top_n, self._ips.items(), key=_count_desc_then_key)
        )
        suspicious = sorted(
            (IpStat(ip, self._ips[ip], self._scan.reasons_for(ip)) for ip in self._scan.flagged_ips),
            key=lambda stat: (-stat.requests, stat.ip),
        )
        status_per_minute = {
            _minute_label(minute): {f"{cls}xx": count for cls, count in sorted(classes.items())}
            for minute, classes in sorted(self._minutes.items())
        }
        return AnalysisResult(
            lines_read=self._lines_read,
            parsed=self._parsed,
            malformed=self._malformed,
            malformed_samples=tuple(self._malformed_samples),
            first_seen=self._first_seen,
            last_seen=self._last_seen,
            total_bytes_sent=self._total_bytes,
            top_paths=tuple(top_paths),
            status_per_minute=status_per_minute,
            distinct_ips=len(self._ips),
            top_ips=top_ips,
            suspicious_ips=tuple(suspicious),
            response_time=self._response_time_stats(),
            error_bursts=tuple(self._bursts.bursts()),
        )

    def _response_time_stats(self) -> ResponseTimeStats:
        if not self._response_times:
            return ResponseTimeStats(0, None, None, None, None)
        ordered = sorted(self._response_times)

        def to_ms(seconds: float) -> float:
            return round(seconds * 1000, 3)

        return ResponseTimeStats(
            samples=len(ordered),
            p50_ms=to_ms(percentile(ordered, 50)),
            p95_ms=to_ms(percentile(ordered, 95)),
            p99_ms=to_ms(percentile(ordered, 99)),
            max_ms=to_ms(ordered[-1]),
        )


def analyze(lines: Iterable[str], config: AnalyzerConfig | None = None) -> AnalysisResult:
    """Analyse an iterable of lines (a file object, a generator, a list)."""
    analyzer = LogAnalyzer(config)
    for line in lines:
        analyzer.feed_line(line)
    return analyzer.result()
