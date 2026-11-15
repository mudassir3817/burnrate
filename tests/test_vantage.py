from __future__ import annotations

import sqlite3

import pytest

from burnrate.models import ErrorKind, ProbeResult, SliKind
from burnrate.report import full_report
from burnrate.storage import SCHEMA_VERSION, Storage
from burnrate.vantage import is_suspect_cycle, mark_suspect

from .conftest import NOW


def probe(target: str, ok: bool, kind: ErrorKind, ts: float = NOW, latency: float = 50.0) -> ProbeResult:
    return ProbeResult(
        target=target,
        ts=ts,
        ok=ok,
        status=None if not ok else 200,
        latency_ms=latency,
        error_kind=kind,
    )


def all_timing_out(n: int = 6) -> list[ProbeResult]:
    return [probe(f"svc{i}", False, ErrorKind.TIMEOUT) for i in range(n)]


# ----------------------------------------------------------------- heuristic


def test_a_whole_cycle_of_transport_failures_is_suspect():
    """Six unrelated hosts do not fail inside the same minute. The prober does."""
    assert is_suspect_cycle(all_timing_out()) is True


def test_mixed_transport_failures_still_count():
    cycle = [
        probe("a", False, ErrorKind.TIMEOUT),
        probe("b", False, ErrorKind.DNS),
        probe("c", False, ErrorKind.CONNECT),
    ]
    assert is_suspect_cycle(cycle) is True


def test_one_server_answering_clears_the_whole_cycle():
    """A 500 proves the request left the machine and came back."""
    cycle = all_timing_out(5) + [probe("svc5", False, ErrorKind.HTTP_5XX)]
    assert is_suspect_cycle(cycle) is False


def test_one_success_clears_the_cycle():
    cycle = all_timing_out(5) + [probe("svc5", True, ErrorKind.NONE)]
    assert is_suspect_cycle(cycle) is False


def test_a_cycle_of_server_errors_is_not_suspect():
    """Real outages look like this, and must still burn budget."""
    cycle = [probe(f"svc{i}", False, ErrorKind.HTTP_5XX) for i in range(6)]
    assert is_suspect_cycle(cycle) is False


def test_too_few_targets_to_draw_a_conclusion():
    """With one target, 'all of them failed' is just 'it failed'."""
    assert is_suspect_cycle(all_timing_out(1)) is False
    assert is_suspect_cycle(all_timing_out(2)) is False
    assert is_suspect_cycle(all_timing_out(3)) is True


def test_min_targets_is_configurable():
    assert is_suspect_cycle(all_timing_out(2), min_targets=2) is True


def test_an_empty_cycle_is_not_suspect():
    assert is_suspect_cycle([]) is False


def test_marking_preserves_order_and_every_other_field():
    cycle = all_timing_out(3)
    marked = mark_suspect(cycle)
    assert [m.target for m in marked] == [c.target for c in cycle]
    assert all(m.suspect for m in marked)
    assert all(m.error_kind is c.error_kind and m.ts == c.ts for m, c in zip(marked, cycle))


def test_marking_a_healthy_cycle_changes_nothing():
    cycle = [probe(f"svc{i}", True, ErrorKind.NONE) for i in range(4)]
    assert mark_suspect(cycle) == cycle


# ------------------------------------------------------------------- storage


def test_suspect_probes_do_not_count_against_availability(storage: Storage):
    for i in range(10):
        storage.record_probe(
            ProbeResult(
                target="svc", ts=NOW - i, ok=False, latency_ms=10000.0,
                error_kind=ErrorKind.TIMEOUT, suspect=True,
            )
        )
    stat = storage.window_stat("svc", SliKind.AVAILABILITY, 3600, NOW, 1000.0)
    assert (stat.valid, stat.bad) == (0, 0)


def test_suspect_probes_do_not_count_against_latency_either(storage: Storage):
    storage.record_probe(
        ProbeResult(target="svc", ts=NOW, ok=False, latency_ms=10000.0,
                    error_kind=ErrorKind.TIMEOUT, suspect=True)
    )
    storage.record_probe(
        ProbeResult(target="svc", ts=NOW, ok=True, status=200, latency_ms=100.0)
    )
    stat = storage.window_stat("svc", SliKind.LATENCY, 3600, NOW, 1000.0)
    assert (stat.valid, stat.good) == (1, 1)


def test_suspect_probes_are_kept_not_deleted(storage: Storage):
    """Excluded from the arithmetic, still there for diagnosis."""
    storage.record_probe(
        ProbeResult(target="svc", ts=NOW, ok=False, latency_ms=10000.0,
                    error_kind=ErrorKind.TIMEOUT, suspect=True)
    )
    kept = storage.probes_between("svc", NOW - 10, NOW + 10)
    assert len(kept) == 1
    assert kept[0].suspect is True
    assert kept[0].error_kind is ErrorKind.TIMEOUT
    assert storage.suspect_count(NOW - 10, NOW + 10) == 1


def test_suspect_latency_is_excluded_from_percentiles(storage: Storage):
    storage.record_probe(
        ProbeResult(target="svc", ts=NOW, ok=True, status=200, latency_ms=9999.0, suspect=True)
    )
    storage.record_probe(
        ProbeResult(target="svc", ts=NOW, ok=True, status=200, latency_ms=120.0)
    )
    assert storage.latency_samples("svc", NOW - 10, NOW + 10) == [120.0]


def test_the_report_says_what_it_set_aside(config, storage: Storage):
    for i in range(6):
        storage.record_probe(
            ProbeResult(target="svc", ts=NOW - i, ok=False, latency_ms=10000.0,
                        error_kind=ErrorKind.TIMEOUT, suspect=True)
        )
    text = full_report(config, storage, NOW)
    assert "set aside" in text
    assert "6 of those probes" in text


# ----------------------------------------------------------------- migration

_V1_SCHEMA = """
CREATE TABLE schema_version (version INTEGER NOT NULL);
CREATE TABLE probes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    target     TEXT    NOT NULL,
    ts         REAL    NOT NULL,
    ok         INTEGER NOT NULL,
    status     INTEGER,
    latency_ms REAL,
    error_kind TEXT    NOT NULL DEFAULT 'none'
);
CREATE TABLE alerts (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    target         TEXT    NOT NULL,
    kind           TEXT    NOT NULL,
    severity       TEXT    NOT NULL,
    rule_label     TEXT    NOT NULL,
    opened_ts      REAL    NOT NULL,
    closed_ts      REAL,
    peak_long_burn REAL    NOT NULL,
    peak_short_burn REAL   NOT NULL
);
INSERT INTO schema_version (version) VALUES (1);
INSERT INTO probes (target, ts, ok, status, latency_ms, error_kind)
VALUES ('svc', :ts, 1, 200, 120.0, 'none');
"""


def test_an_old_database_is_migrated_rather_than_rejected(tmp_path):
    """The monitor's history lives in a CI cache; refusing to open it loses it."""
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(_V1_SCHEMA.replace(":ts", str(NOW)))
    conn.commit()
    conn.close()

    with Storage(path) as storage:
        assert storage.probe_count() == 1, "the existing history must survive"
        stat = storage.window_stat("svc", SliKind.AVAILABILITY, 3600, NOW, 1000.0)
        assert (stat.valid, stat.good) == (1, 1)
        storage.record_probe(ProbeResult(target="svc", ts=NOW, ok=True, status=200, latency_ms=90.0))
        assert storage.probe_count() == 2

    conn = sqlite3.connect(path)
    assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == SCHEMA_VERSION
    conn.close()


def test_migrated_rows_default_to_not_suspect(tmp_path):
    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.executescript(_V1_SCHEMA.replace(":ts", str(NOW)))
    conn.commit()
    conn.close()

    with Storage(path) as storage:
        assert storage.suspect_count(NOW - 10, NOW + 10) == 0


def test_a_database_from_the_future_is_refused(tmp_path):
    """Downgrading the code must not quietly reinterpret a newer file."""
    path = tmp_path / "future.db"
    conn = sqlite3.connect(path)
    conn.executescript(_V1_SCHEMA.replace(":ts", str(NOW)))
    conn.execute("UPDATE schema_version SET version = ?", (SCHEMA_VERSION + 5,))
    conn.commit()
    conn.close()

    with pytest.raises(RuntimeError, match="newer than this build"):
        Storage(path)
