import os, sys; sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from datetime import datetime, timedelta, timezone

import pytest

from loganalyzer import ErrorBurstDetector, ScanDetector, percentile

T0 = datetime(2024, 3, 5, 10, 0, 0, tzinfo=timezone.utc)


def at(seconds: float) -> datetime:
    return T0 + timedelta(seconds=seconds)


# --- percentile -------------------------------------------------------------


def test_percentile_nearest_rank_on_one_to_hundred():
    values = list(range(1, 101))
    # With 100 values the p-th percentile is the p-th smallest value.
    assert percentile(values, 50) == 50
    assert percentile(values, 95) == 95
    assert percentile(values, 99) == 99
    assert percentile(values, 100) == 100


def test_percentile_rounds_the_rank_up_for_small_samples():
    values = list(range(1, 11))  # n = 10
    assert percentile(values, 50) == 5  # ceil(5.0) = 5th value
    assert percentile(values, 95) == 10  # ceil(9.5) = 10th value
    assert percentile(values, 99) == 10  # ceil(9.9) = 10th value
    assert percentile(values, 10) == 1  # ceil(1.0) = 1st value


def test_percentile_of_one_value_is_that_value():
    assert percentile([0.42], 1) == 0.42
    assert percentile([0.42], 99) == 0.42


def test_percentile_returns_an_observed_value_not_an_interpolation():
    assert percentile([10, 20], 50) == 10  # rank ceil(1.0) = 1
    assert percentile([10, 20], 51) == 20  # rank ceil(1.02) = 2


@pytest.mark.parametrize("pct", [0, -5, 101, 50.5])
def test_percentile_rejects_bad_percent(pct):
    with pytest.raises(ValueError, match="percentile must be"):
        percentile([1, 2, 3], pct)


def test_percentile_rejects_empty_input():
    with pytest.raises(ValueError, match="no values"):
        percentile([], 50)


# --- ScanDetector -----------------------------------------------------------


def test_ip_with_threshold_404s_inside_the_window_is_flagged():
    scan = ScanDetector(threshold=3, window_seconds=60)
    for second in (0, 20, 40):
        scan.observe("192.0.2.9", 404, second)
    assert scan.reasons_for("192.0.2.9") == ("many_404",)
    assert scan.flagged_ips == ["192.0.2.9"]


def test_one_404_fewer_than_threshold_is_not_flagged():
    scan = ScanDetector(threshold=3, window_seconds=60)
    scan.observe("192.0.2.9", 404, 0)
    scan.observe("192.0.2.9", 404, 10)
    assert scan.reasons_for("192.0.2.9") == ()
    assert scan.flagged_ips == []


def test_404s_spread_over_more_than_the_window_are_not_flagged():
    scan = ScanDetector(threshold=3, window_seconds=60)
    for second in (0, 40, 80):  # 80 s apart end to end
        scan.observe("192.0.2.9", 404, second)
    assert scan.reasons_for("192.0.2.9") == ()


def test_window_slides_and_the_boundary_is_inclusive():
    scan = ScanDetector(threshold=3, window_seconds=60)
    for second in (0, 40, 80):
        scan.observe("192.0.2.9", 404, second)
    assert scan.reasons_for("192.0.2.9") == ()
    # The last three are now 40, 80, 100: exactly 60 s end to end.
    scan.observe("192.0.2.9", 404, 100)
    assert scan.reasons_for("192.0.2.9") == ("many_404",)


def test_401s_get_their_own_reason():
    scan = ScanDetector(threshold=2, window_seconds=30)
    scan.observe("203.0.113.1", 401, 5)
    scan.observe("203.0.113.1", 401, 9)
    assert scan.reasons_for("203.0.113.1") == ("many_401",)


def test_401s_and_404s_are_not_added_together():
    scan = ScanDetector(threshold=3, window_seconds=60)
    for second, status in ((0, 404), (1, 401), (2, 404), (3, 401)):
        scan.observe("192.0.2.9", status, second)
    assert scan.reasons_for("192.0.2.9") == ()


def test_other_statuses_never_flag_an_ip():
    scan = ScanDetector(threshold=2, window_seconds=60)
    for second in range(20):
        scan.observe("192.0.2.9", 500 if second % 2 else 200, second)
    assert scan.flagged_ips == []


def test_each_ip_is_counted_separately():
    scan = ScanDetector(threshold=3, window_seconds=60)
    for second, ip in enumerate(("192.0.2.1", "192.0.2.2") * 2):
        scan.observe(ip, 404, second)  # two 404s each, never three for one IP
    assert scan.flagged_ips == []
    scan.observe("192.0.2.1", 404, 5)
    assert scan.flagged_ips == ["192.0.2.1"]


def test_slightly_out_of_order_lines_do_not_fake_a_burst():
    scan = ScanDetector(threshold=3, window_seconds=60)
    for second in (100, 0, 10):  # spread is 100 s even though last-first is negative
        scan.observe("192.0.2.9", 404, second)
    assert scan.reasons_for("192.0.2.9") == ()
    scan.observe("192.0.2.9", 404, 20)  # last three arrivals: 0, 10, 20
    assert scan.reasons_for("192.0.2.9") == ("many_404",)


@pytest.mark.parametrize(("threshold", "window"), [(0, 60), (-1, 60), (3, 0), (3, -1)])
def test_scan_detector_rejects_bad_settings(threshold, window):
    with pytest.raises(ValueError):
        ScanDetector(threshold=threshold, window_seconds=window)


# --- ErrorBurstDetector -----------------------------------------------------


def feed(detector: ErrorBurstDetector, events):
    for second, status in events:
        detector.observe(at(second), status)


def test_burst_starts_above_threshold_and_ends_when_the_window_empties():
    detector = ErrorBurstDetector(threshold=0.5, window_seconds=60, min_requests=4)
    feed(detector, [(0, 200), (10, 200), (20, 500), (30, 500)])
    assert detector.bursts() == []  # 2 of 4 is exactly 0.5, not above it
    feed(detector, [(40, 500), (50, 500)])
    feed(detector, [(120, 200)])  # everything before 60 s has left the window

    (burst,) = detector.bursts()
    assert burst.start == at(40)  # 3 of 5 = 0.6 is the first rate above 0.5
    assert burst.end == at(50)
    assert burst.peak_errors == 4
    assert burst.peak_requests == 6
    assert burst.peak_rate == pytest.approx(4 / 6)


def test_rate_equal_to_threshold_is_not_a_burst():
    detector = ErrorBurstDetector(threshold=0.5, window_seconds=60, min_requests=4)
    feed(detector, [(0, 200), (1, 200), (2, 500), (3, 500)])
    assert detector.bursts() == []


def test_min_requests_stops_a_single_failure_from_being_a_burst():
    detector = ErrorBurstDetector(threshold=0.5, window_seconds=60, min_requests=5)
    feed(detector, [(0, 500), (1, 500), (2, 500), (3, 500)])  # 100% errors, only 4 requests
    assert detector.bursts() == []
    feed(detector, [(4, 500)])
    assert len(detector.bursts()) == 1


def test_errors_older_than_the_window_stop_counting():
    detector = ErrorBurstDetector(threshold=0.5, window_seconds=60, min_requests=4)
    feed(detector, [(0, 500), (1, 500), (2, 500), (3, 500)])
    feed(detector, [(100, 200), (101, 200), (102, 200), (103, 200)])
    (burst,) = detector.bursts()
    assert (burst.start, burst.end) == (at(3), at(3))  # first moment with 4 requests in the window


def test_a_request_exactly_one_window_old_has_left_the_window():
    detector = ErrorBurstDetector(threshold=0.5, window_seconds=60, min_requests=2)
    feed(detector, [(0, 500), (59, 500)])  # 59 s apart: both inside the window
    assert len(detector.bursts()) == 1

    detector = ErrorBurstDetector(threshold=0.5, window_seconds=60, min_requests=2)
    feed(detector, [(0, 500), (60, 500)])  # exactly 60 s apart: the first one is gone
    assert detector.bursts() == []
    feed(detector, [(61, 500)])  # 60 and 61 are two failures in the window
    assert len(detector.bursts()) == 1


def test_a_quiet_gap_separates_two_bursts():
    detector = ErrorBurstDetector(threshold=0.5, window_seconds=30, min_requests=2)
    # Burst 1: from the 2nd request (2 of 2 failed) to the 3rd (2 of 3, still above 0.5).
    feed(detector, [(0, 500), (5, 503), (10, 200)])
    # After 490 quiet seconds the window is empty again. 1 of 2 is exactly 0.5 (no burst);
    # the third request makes it 2 of 3.
    feed(detector, [(500, 200), (505, 502), (506, 504)])
    first, second = detector.bursts()
    assert (first.start, first.end) == (at(5), at(10))
    assert (second.start, second.end) == (at(506), at(506))


def test_only_5xx_counts_as_error():
    detector = ErrorBurstDetector(threshold=0.1, window_seconds=60, min_requests=2)
    feed(detector, [(0, 404), (1, 499), (2, 401), (3, 302), (4, 429), (5, 400)])
    assert detector.bursts() == []
    feed(detector, [(6, 599)])  # 599 is still 5xx
    assert len(detector.bursts()) == 1


def test_asking_for_bursts_mid_stream_does_not_split_an_open_burst():
    detector = ErrorBurstDetector(threshold=0.5, window_seconds=60, min_requests=2)
    feed(detector, [(0, 500), (1, 500)])
    assert [burst.end for burst in detector.bursts()] == [at(1)]
    feed(detector, [(2, 500)])
    (burst,) = detector.bursts()
    assert (burst.start, burst.end) == (at(1), at(2))


def test_a_burst_snapshot_taken_earlier_does_not_change_when_the_burst_grows():
    detector = ErrorBurstDetector(threshold=0.5, window_seconds=60, min_requests=2)
    feed(detector, [(0, 500), (1, 500)])
    (snapshot,) = detector.bursts()
    feed(detector, [(2, 500), (3, 500)])
    # The detector's own burst now ends at 3 s, but the copy handed out earlier is frozen at 1 s.
    assert snapshot.end == at(1)
    (latest,) = detector.bursts()
    assert (latest.start, latest.end) == (at(1), at(3))


@pytest.mark.parametrize(
    ("threshold", "window", "min_requests"),
    [(-0.1, 60, 1), (1.0, 60, 1), (0.5, 0, 1), (0.5, -3, 1), (0.5, 60, 0)],
)
def test_burst_detector_rejects_bad_settings(threshold, window, min_requests):
    with pytest.raises(ValueError):
        ErrorBurstDetector(threshold=threshold, window_seconds=window, min_requests=min_requests)
