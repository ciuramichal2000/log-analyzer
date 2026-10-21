# loganalyzer

A command-line tool and Python library that reads nginx/Apache access logs one line at a time and reports the busiest paths, status codes per minute, request counts per IP with a simple "suspicious client" flag, response-time percentiles and bursts of 5xx errors. Lines it cannot parse are counted and shown as samples instead of stopping the run. The output is a text report or JSON. It uses only the Python standard library.

## Interesting engineering

- Streaming design: each line is parsed, folded into counters and dropped, so the log is never held in memory. What is kept grows with the number of distinct paths, IPs and minutes, the requests inside the error-burst window, and 8 bytes per response-time sample.
- The suspicious check keeps only the last N timestamps per IP and status, and measures their spread with max-min so slightly out-of-order lines cannot fake a burst. 404s and 401s are counted separately (path scanning vs. password guessing).
- Error bursts use a sliding time window with a minimum request count, so one failed request in a quiet minute is not reported as a 100% error rate. A burst's start, end and peak rate are tracked, and asking for results mid-stream does not split an open burst.
- Percentiles use the nearest-rank method with integer arithmetic, so p95 is always a value that was actually observed and float rounding cannot shift the rank.
- Timestamps are parsed without `strptime`, so month names do not depend on the machine's locale; all per-minute buckets are normalised to UTC.

## Usage

```
python -m loganalyzer access.log
python -m loganalyzer access.log --json --top 5
python -m loganalyzer access.log --suspicious-threshold 20 --suspicious-window 120
python -m loganalyzer access.log --burst-threshold 0.3 --burst-window 300 --burst-min-requests 50
zcat access.log.gz | python -m loganalyzer - --time-unit us
```

Library use:

```python
from loganalyzer import AnalyzerConfig, analyze, format_text

with open("access.log", "rb") as handle:
    lines = (raw.decode("utf-8", errors="replace") for raw in handle)
    result = analyze(lines, AnalyzerConfig(top_n=5))
print(format_text(result))
```

Exit code 0 means the report was produced, 2 means bad options or an unreadable file.

### Log format

Combined format (`ip - user [time] "request" status size "referer" "agent"`) or common format (without referer and agent). Optionally one numeric response-time field can follow, for example nginx `$request_time` (seconds) appended to the format. Use `--time-unit ms` or `--time-unit us` if the field is in milliseconds or microseconds (Apache `%D`).

### Defaults

| Setting | Default |
| --- | --- |
| IP flagged as suspicious | 10 responses with status 404 (or 10 with 401) within 60 seconds |
| Error burst | 5xx share above 50% of the last 60 seconds, with at least 10 requests in that window |
| Table size (`--top`) | 10 |

## Limitations

- Only a single trailing numeric field is read as the response time; other custom fields after the user agent make the line count as malformed.
- Percentiles are exact, so every response-time sample is kept in memory. Counters for distinct paths and IPs also grow with the data, so a log full of unique scanner URLs will use more memory.
- The windows assume a roughly chronological log. Heavily shuffled input can miss a burst.
- Only status codes 401 and 404 are watched for the suspicious flag, and the flag is a heuristic, not proof of an attack.
- Query strings are dropped before counting paths. Lines are read as UTF-8 with undecodable bytes replaced; compressed files must be decompressed first.

## Running the tests

```
python -m pytest -q
```

The tests use only invented log lines, fixed timestamps and no network or sleeping.

Built with AI coding assistance.
