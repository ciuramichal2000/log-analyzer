"""Render an AnalysisResult as plain text or JSON."""

import json

from .analyzer import AnalysisResult, IpStat


def to_json(result: AnalysisResult) -> str:
    """Pretty-printed JSON with a stable key order."""
    return json.dumps(result.to_dict(), indent=2)


def _ip_line(stat: IpStat, width: int) -> str:
    flag = f"  SUSPICIOUS ({', '.join(stat.reasons)})" if stat.suspicious else ""
    return f"  {stat.ip:<{width}}  {stat.requests:>8}{flag}"


def _ms(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.3f} ms"


def format_text(result: AnalysisResult) -> str:
    """Human-readable report; every section is present even when empty."""
    out: list[str] = ["Access log report", "=================", ""]
    out.append(
        f"Lines read: {result.lines_read}  parsed: {result.parsed}  malformed: {result.malformed}"
    )
    if result.first_seen and result.last_seen:
        out.append(f"Period: {result.first_seen.isoformat()} to {result.last_seen.isoformat()}")
    out.append(f"Bytes sent: {result.total_bytes_sent}")

    if result.malformed_samples:
        out += ["", f"Malformed lines (first {len(result.malformed_samples)} of {result.malformed})"]
        for sample in result.malformed_samples:
            out.append(f"  line {sample.line_number}: {sample.reason}")
            out.append(f"    {sample.text[:100]!r}")

    out += ["", "Top paths", "  requests  path"]
    out += [f"  {count:>8}  {path}" for path, count in result.top_paths] or ["  (none)"]

    out += ["", "Status classes per minute (UTC)"]
    classes = sorted({cls for counts in result.status_per_minute.values() for cls in counts})
    if classes:
        out.append("  " + f"{'minute':<18}" + "".join(f"{cls:>8}" for cls in classes))
        for minute, counts in result.status_per_minute.items():
            out.append(
                "  " + f"{minute:<18}" + "".join(f"{counts.get(cls, 0):>8}" for cls in classes)
            )
    else:
        out.append("  (none)")

    out += ["", f"Requests per IP (top {len(result.top_ips)} of {result.distinct_ips} distinct)"]
    if result.top_ips:
        width = max(len(stat.ip) for stat in result.top_ips)
        out += [_ip_line(stat, width) for stat in result.top_ips]
    else:
        out.append("  (none)")

    out += ["", f"Suspicious IPs: {len(result.suspicious_ips)}"]
    if result.suspicious_ips:
        width = max(len(stat.ip) for stat in result.suspicious_ips)
        out += [_ip_line(stat, width) for stat in result.suspicious_ips]

    timing = result.response_time
    out += ["", "Response time"]
    if timing.samples:
        out.append(f"  samples: {timing.samples}")
        out.append(f"  p50: {_ms(timing.p50_ms)}  p95: {_ms(timing.p95_ms)}  p99: {_ms(timing.p99_ms)}")
        out.append(f"  max: {_ms(timing.max_ms)}")
    else:
        out.append("  no response times in this log")

    out += ["", f"Error bursts (5xx): {len(result.error_bursts)}"]
    for burst in result.error_bursts:
        out.append(
            f"  {burst.start.isoformat()} to {burst.end.isoformat()}: peak "
            f"{burst.peak_rate:.1%} 5xx ({burst.peak_errors} of {burst.peak_requests} requests in window)"
        )
    return "\n".join(out) + "\n"
