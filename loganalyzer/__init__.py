"""Streaming analysis of nginx/Apache access logs."""

from .analyzer import AnalysisResult, AnalyzerConfig, LogAnalyzer, analyze
from .detectors import Burst, ErrorBurstDetector, ScanDetector, percentile
from .parser import LogEntry, LogParseError, parse_line
from .report import format_text, to_json

__all__ = [
    "AnalysisResult",
    "AnalyzerConfig",
    "Burst",
    "ErrorBurstDetector",
    "LogAnalyzer",
    "LogEntry",
    "LogParseError",
    "ScanDetector",
    "analyze",
    "format_text",
    "parse_line",
    "percentile",
    "to_json",
]
