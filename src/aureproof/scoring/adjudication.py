# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""The adjudication queue, final decisions, agreement and post-adjudication counts.

Pure (issue #51; scoring.md §7; specs/adjudication). Every ``unresolved:*``
finding is queued; nothing is dropped. For each finding, the latest record per
adjudicator and role counts. A ``resolution`` record settles the finding.
Otherwise the independent adjudicators must agree, and if they don't, the
finding stays undecided. A ``label_change`` is decided but stays unresolved
under the current dataset revision: it needs a re-score under the new one. The
original matcher verdict is never changed.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from fractions import Fraction
from typing import Literal

from aureproof.contracts.adjudication import UNRESOLVED, Adjudication, Decision, Role
from aureproof.contracts.specs import utc_instant
from aureproof.scoring.episode import EpisodeScore

MIN_DOUBLE_COVERAGE = Fraction(1, 5)  # plan §5.7: two adjudicators on at least 20%
Key = tuple[str, int]  # (episode_id, finding_index)
Status = Literal["decided", "label_change", "disagreement", "pending"]


@dataclass(frozen=True)
class QueueItem:
    episode_id: str
    finding_index: int
    verdict: str


@dataclass(frozen=True)
class Resolution:
    item: QueueItem
    status: Status
    decision: Decision | None
    adjudicators: tuple[str, ...]


@dataclass(frozen=True)
class Agreement:
    queued: int
    double_adjudicated: int
    agreed: int
    kappa: float | None
    undefined_reason: str | None
    coverage_ok: bool  # at least MIN_DOUBLE_COVERAGE of queued findings have two adjudicators


def queue(episodes: Iterable[tuple[str, EpisodeScore]]) -> list[QueueItem]:
    """Every unresolved finding, in episode and finding order."""
    return [
        QueueItem(episode_id, v.finding_index, v.verdict.value)
        for episode_id, score in episodes
        for v in score.verdicts or ()
        if v.verdict.value in UNRESOLVED
    ]


def check(records: Sequence[Adjudication], items: Sequence[QueueItem], seal: str) -> list[str]:
    """Problems that make records unusable for this bundle; empty means usable."""
    by_key = {(i.episode_id, i.finding_index): i for i in items}
    problems = []
    for n, r in enumerate(records):
        key = (r.finding.episode_id, r.finding.finding_index)
        if r.bundle_seal != seal:
            problems.append(f"record {n}: made for another bundle ({r.bundle_seal})")
        elif key not in by_key:
            problems.append(f"record {n}: {key} is not an unresolved finding of this bundle")
        elif by_key[key].verdict != r.original_verdict:
            problems.append(f"record {n}: {key} is {by_key[key].verdict}, not {r.original_verdict}")
    return problems


def _latest(records: Iterable[Adjudication]) -> dict[tuple[str, Role], Adjudication]:
    latest: dict[tuple[str, Role], Adjudication] = {}
    for r in sorted(records, key=lambda r: utc_instant(r.timestamp)):
        latest[(r.adjudicator, r.role)] = r  # a later record supersedes; none is erased
    return latest


def resolve(items: Sequence[QueueItem], records: Sequence[Adjudication]) -> list[Resolution]:
    grouped: dict[Key, list[Adjudication]] = {}
    for r in records:
        grouped.setdefault((r.finding.episode_id, r.finding.finding_index), []).append(r)
    out = []
    for item in items:
        latest = _latest(grouped.get((item.episode_id, item.finding_index), []))
        names = tuple(sorted({a for a, _ in latest}))
        settled = [r for (_, role), r in latest.items() if role is Role.RESOLUTION]
        votes = {r.decision for (_, role), r in latest.items() if role is not Role.RESOLUTION}
        decision: Decision | None
        if settled:
            decision = max(settled, key=lambda r: utc_instant(r.timestamp)).decision
        elif len(votes) == 1:
            decision = next(iter(votes))
        else:
            decision = None
        if decision is None:
            status: Status = "disagreement" if votes else "pending"
        elif decision is Decision.LABEL_CHANGE:
            status = "label_change"
        else:
            status = "decided"
        out.append(Resolution(item, status, decision, names))
    return out


def agreement(items: Sequence[QueueItem], records: Sequence[Adjudication]) -> Agreement:
    """Cohen's kappa between the primary and the second adjudicator, where both exist."""
    pairs: list[tuple[Decision, Decision]] = []
    for item in items:
        mine = [
            r
            for r in records
            if (r.finding.episode_id, r.finding.finding_index)
            == (item.episode_id, item.finding_index)
        ]
        latest = _latest(mine)
        first = [r for (_, role), r in latest.items() if role is Role.PRIMARY]
        second = [r for (_, role), r in latest.items() if role is Role.SECOND]
        if first and second:
            pairs.append((first[0].decision, second[0].decision))
    n = len(pairs)
    coverage_ok = bool(items) and Fraction(n, len(items)) >= MIN_DOUBLE_COVERAGE
    agreed = sum(a == b for a, b in pairs)
    if n == 0:
        return Agreement(len(items), 0, 0, None, "no finding has two adjudicators", coverage_ok)
    observed = Fraction(agreed, n)
    left, right = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    expected = sum(Fraction(left[c] * right[c], n * n) for c in Decision)
    if expected == 1:
        reason = "every decision is in one category, so chance agreement is 1"
        return Agreement(len(items), n, agreed, None, reason, coverage_ok)
    kappa = float((observed - expected) / (1 - expected))
    return Agreement(len(items), n, agreed, kappa, None, coverage_ok)


def adjusted(
    score: EpisodeScore, episode_id: str, resolutions: Sequence[Resolution]
) -> tuple[int, int, int, int]:
    """(confirmed, refuted, unresolved, submitted) for one episode after adjudication."""
    verdicts = [v.verdict.value for v in score.verdicts or ()]
    decided = {
        r.item.finding_index: r.decision
        for r in resolutions
        if r.item.episode_id == episode_id and r.status == "decided"
    }
    confirmed = verdicts.count("confirmed") + sum(d is Decision.CONFIRMED for d in decided.values())
    refuted = verdicts.count("refuted") + sum(d is Decision.REFUTED for d in decided.values())
    unresolved = sum(v in UNRESOLVED for v in verdicts) - len(decided)
    return confirmed, refuted, unresolved, len(verdicts)


def post_adjudication(
    episodes: Iterable[tuple[str, EpisodeScore]], resolutions: Sequence[Resolution]
) -> dict[str, tuple[int, int]]:
    """Adjudicated precision, strict yield and unresolved fraction, as (numerator, denominator)."""
    c = r = u = n = 0
    for episode_id, score in episodes:
        if not score.graded:
            continue
        dc, dr, du, dn = adjusted(score, episode_id, resolutions)
        c, r, u, n = c + dc, r + dr, u + du, n + dn
    return {
        "adjudicated_precision": (c, c + r),
        "strict_confirmed_yield": (c, n),
        "unresolved_fraction": (u, c + r + u),
    }
