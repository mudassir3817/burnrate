"""Deciding when a probe cycle is evidence about the prober, not the services.

On 14 November one visit recorded six timeouts out of six targets, eight
hours after the same six had all answered. The targets sit on four unrelated
providers. Either all of them failed inside the same minute and recovered
together, or the one thing they share — the machine doing the probing and the
path out of it — was broken.

The second explanation is the ordinary one, and a monitor that cannot tell
the difference spends its entire error budget accusing healthy services.

What follows is a heuristic, and it is written down as one. It does not
delete anything: a suspect probe keeps its row, its error and its timestamp,
and is excluded from the SLI denominators because it is not a measurement of
the service. The report says how many were set aside, so the judgement stays
visible instead of quietly improving the numbers.
"""

from __future__ import annotations

from dataclasses import replace

from .models import ErrorKind, ProbeResult

# Failures that happen before any server speaks. These are the ones a broken
# local network produces. An HTTP status is the opposite kind of evidence: a
# 500 proves the request arrived, was routed, and came back.
TRANSPORT_FAILURES = frozenset(
    {ErrorKind.DNS, ErrorKind.CONNECT, ErrorKind.TIMEOUT, ErrorKind.TLS}
)

# Below this many targets, "all of them failed" is not a coincidence worth
# remarking on. With one target it is simply "it failed", and suppressing that
# would make the monitor useless exactly when it matters.
DEFAULT_MIN_TARGETS = 3


def is_suspect_cycle(results: list[ProbeResult], min_targets: int = DEFAULT_MIN_TARGETS) -> bool:
    """True when a whole cycle failed in the way a broken prober fails.

    Every result must be a transport-level failure. One target answering, even
    with a 500, is proof the path out was working, so nothing is suspect.
    """
    if len(results) < min_targets:
        return False
    return all(not r.ok and r.error_kind in TRANSPORT_FAILURES for r in results)


def mark_suspect(
    results: list[ProbeResult], min_targets: int = DEFAULT_MIN_TARGETS
) -> list[ProbeResult]:
    """Return the cycle's results, flagged if the cycle incriminates itself.

    Order is preserved and the results are otherwise untouched.
    """
    if not is_suspect_cycle(results, min_targets):
        return list(results)
    return [replace(r, suspect=True) for r in results]
