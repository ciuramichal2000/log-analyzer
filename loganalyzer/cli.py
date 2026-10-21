"""Command-line interface: ``python -m loganalyzer access.log``."""

import argparse
import sys
from collections.abc import Iterator, Sequence
from typing import IO

from .analyzer import AnalyzerConfig, LogAnalyzer, analyze
from .parser import TIME_UNITS
from .report import format_text, to_json


def build_parser() -> argparse.ArgumentParser:
    defaults = AnalyzerConfig()
    parser = argparse.ArgumentParser(
        prog="loganalyzer",
        description="Analyse an nginx/Apache access log (combined or common format).",
    )
    parser.add_argument("logfile", help="path to the log file, or - to read standard input")
    parser.add_argument("--json", action="store_true", help="print JSON instead of the text report")
    parser.add_argument("--top", type=int, default=defaults.top_n, metavar="N",
                        help="rows in the top-paths and top-IPs tables (default: %(default)s)")
    parser.add_argument("--time-unit", choices=sorted(TIME_UNITS), default=defaults.time_unit,
                        help="unit of the optional trailing response-time field (default: %(default)s)")
    parser.add_argument("--suspicious-threshold", type=int, default=defaults.suspicious_threshold,
                        metavar="N", help="404s (or 401s) from one IP that make it suspicious "
                        "(default: %(default)s)")
    parser.add_argument("--suspicious-window", type=float, default=defaults.suspicious_window_seconds,
                        metavar="SECONDS", help="window for the suspicious check (default: %(default)s)")
    parser.add_argument("--burst-threshold", type=float, default=defaults.burst_threshold,
                        metavar="RATE", help="5xx share in the window above which an error burst "
                        "starts, 0 to <1 (default: %(default)s)")
    parser.add_argument("--burst-window", type=float, default=defaults.burst_window_seconds,
                        metavar="SECONDS", help="sliding window for error bursts (default: %(default)s)")
    parser.add_argument("--burst-min-requests", type=int, default=defaults.burst_min_requests,
                        metavar="N", help="requests the window needs before a burst can be "
                        "declared (default: %(default)s)")
    return parser


def _decoded_lines(binary: IO[bytes]) -> Iterator[str]:
    """Yield lines decoded as UTF-8, replacing undecodable bytes.

    Real logs contain raw bytes in user agents and request lines; decoding
    strictly would abort the whole run on the first one.
    """
    for raw in binary:
        yield raw.decode("utf-8", errors="replace")


def _write_stdout(text: str) -> None:
    """Print without crashing on characters the console encoding cannot show."""
    encoding = sys.stdout.encoding or "utf-8"
    sys.stdout.write(text.encode(encoding, errors="backslashreplace").decode(encoding))


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI; returns the process exit code (0 ok, 2 bad usage or unreadable input)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = AnalyzerConfig(
            top_n=args.top,
            time_unit=args.time_unit,
            suspicious_threshold=args.suspicious_threshold,
            suspicious_window_seconds=args.suspicious_window,
            burst_threshold=args.burst_threshold,
            burst_window_seconds=args.burst_window,
            burst_min_requests=args.burst_min_requests,
        )
        LogAnalyzer(config)  # surfaces detector settings errors before reading any input
    except ValueError as error:
        parser.error(str(error))

    try:
        if args.logfile == "-":
            result = analyze(_decoded_lines(sys.stdin.buffer), config)
        else:
            with open(args.logfile, "rb") as handle:
                result = analyze(_decoded_lines(handle), config)
    except OSError as error:
        print(f"loganalyzer: cannot read {args.logfile}: {error.strerror or error}", file=sys.stderr)
        return 2

    _write_stdout(to_json(result) + "\n" if args.json else format_text(result))
    return 0
