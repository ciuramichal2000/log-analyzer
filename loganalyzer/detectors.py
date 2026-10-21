"""Streaming detectors and statistics used by the analyzer.

Each detector keeps bounded state, so a large log can be processed line by line
without holding the requests in memory.
"""

from collections import deque
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta


def percentile(sorted_values: Sequence[float], pct: int) -> float:
    """Nearest-rank percentile of an ascending sequence.

    Nearest-rank always returns a value that was really observed (no
    interpolation between two requests), which is what people expect from
    "p95 latency". The rank is computed with integers to avoid float rounding
    pushing it one position off.
    """
    if not sorted_values:
        raise ValueError("cannot take a percentile of no values")
    if not isinstance(pct, int) or not 0 < pct <= 100:
        raise ValueError(f"percentile must be an integer in 1..100, got {pct!r}")
    rank = (pct * len(sorted_values) + 99) // 100  # ceil(pct * n / 100)
    return sorted_values[rank - 1]


class ScanDetector:
    """Flags IPs that collect many 404 or 401 responses in a short window.

    Many 404s usually mean path scanning; many 401s mean credential guessing.
    They are counted separately because the two behaviours are different and
    mixing them would flag a client that merely hit a few of each.

    Only the last ``threshold`` timestamps per (ip, status) are stored, so
    memory per client is bounded. A client is flagged when those timestamps
    span at most ``window_seconds`` (inclusive). Using max-min instead of
    last-first keeps slightly out-of-order log lines from producing a negative
    span. Input is assumed to be roughly chronological.
    """

    WATCHED_STATUSES = {404: "many_404", 401: "many_401"}

    def __init__(self, threshold: int, window_seconds: float) -> None:
        if threshold < 1:
            raise ValueError(f"threshold must be at least 1, got {threshold}")
        if window_seconds <= 0:
            raise ValueError(f"window_seconds must be positive, got {window_seconds}")
        self._threshold = threshold
        self._window = window_seconds
        self._recent: dict[tuple[str, int], deque[float]] = {}
        self._reasons: dict[str, set[str]] = {}

    def observe(self, ip: str, status: int, epoch_seconds: float) -> None:
        """Record one response; statuses other than 401/404 are ignored."""
        reason = self.WATCHED_STATUSES.get(status)
        if reason is None:
            return
        recent = self._recent.setdefault((ip, status), deque(maxlen=self._threshold))
        recent.append(epoch_seconds)
        if len(recent) == self._threshold and max(recent) - min(recent) <= self._window:
            self._reasons.setdefault(ip, set()).add(reason)

    def reasons_for(self, ip: str) -> tuple[str, ...]:
        """Sorted reasons the IP was flagged for; empty when it is not."""
        return tuple(sorted(self._reasons.get(ip, ())))

    @property
    def flagged_ips(self) -> list[str]:
        """Every flagged IP, in no particular order."""
        return list(self._reasons)


@dataclass
class Burst:
    """A period during which the 5xx share of recent requests stayed too high."""

    start: datetime
    end: datetime
    peak_rate: float
    peak_errors: int
    peak_requests: int


class ErrorBurstDetector:
    """Finds periods where 5xx responses exceed ``threshold`` of a sliding window.

    The window holds the requests of the last ``window_seconds`` seconds
    (exclusive of the oldest edge). ``min_requests`` stops a single failed
    request in a quiet minute from counting as a 100% error burst. A burst
    starts at the first request where the rate is strictly above the threshold
    and ends at the last request where it still was.
    """

    def __init__(self, threshold: float, window_seconds: float, min_requests: int) -> None:
        if not 0 <= threshold < 1:
            raise ValueError(f"threshold must be in [0, 1), got {threshold}")
        if window_seconds <= 0:
            raise ValueError(f"window_seconds must be positive, got {window_seconds}")
        if min_requests < 1:
            raise ValueError(f"min_requests must be at least 1, got {min_requests}")
        self._threshold = threshold
        self._window = timedelta(seconds=window_seconds)
        self._min_requests = min_requests
        self._events: deque[tuple[datetime, bool]] = deque()
        self._error_count = 0
        self._latest: datetime | None = None
        self._open: Burst | None = None
        self._closed: list[Burst] = []

    def observe(self, timestamp: datetime, status: int) -> None:
        """Add one request to the window and update the burst state."""
        if self._latest is None or timestamp > self._latest:
            self._latest = timestamp
        cutoff = self._latest - self._window
        while self._events and self._events[0][0] <= cutoff:
            _, was_error = self._events.popleft()
            self._error_count -= int(was_error)

        is_error = 500 <= status <= 599
        self._events.append((timestamp, is_error))
        self._error_count += int(is_error)

        total = len(self._events)
        rate = self._error_count / total
        if total >= self._min_requests and rate > self._threshold:
            if self._open is None:
                self._open = Burst(timestamp, timestamp, rate, self._error_count, total)
            else:
                self._open.end = timestamp
                if rate > self._open.peak_rate:
                    self._open.peak_rate = rate
                    self._open.peak_errors = self._error_count
                    self._open.peak_requests = total
        elif self._open is not None:
            self._closed.append(self._open)
            self._open = None

    def bursts(self) -> list[Burst]:
        """Finished bursts plus a snapshot of the one still in progress.

        The snapshot is a copy, so asking for results mid-stream does not cut
        a burst in two.
        """
        found = list(self._closed)
        if self._open is not None:
            found.append(replace(self._open))
        return found
