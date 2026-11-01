# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Paired comparison of two live run bundles under a Decision Protocol (issues #50, #53).

Pure: files in, a decision out. Each bundle must belong to the protocol, or the
comparison fails closed with every problem listed: the sealed protocol is the
same document, the sealed system is configuration A (or B), every cohort task
has the THR the protocol names by digest, that THR's controls ran under the
scoring identity that graded the run (the seal's ``scoring_profile``, which every
re-scored episode must carry), every task and variant has exactly the protocol's
repetitions and nothing else, every planned episode names this protocol and
system, and the bundle re-scores byte for byte. Only then are the
re-scored episodes grouped by cluster, one ``ClusterRow`` each, and passed to
the exact three-way gate (``stats.decide``). Quality (strict confirmed yield)
and operational completion are reported separately.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Literal

from pydantic import ValidationError

from aureproof.bundle.canonical import digest_ref
from aureproof.bundle.models import SEAL
from aureproof.bundle.run import (
    EPISODES,
    JOURNAL_EPISODE_PLANNED,
    PROTOCOL,
    SYSTEM,
    rescore,
    thr_path,
)
from aureproof.contracts import SystemSpec
from aureproof.contracts.adjudication import Adjudication
from aureproof.contracts.decision import ClusterRow, Decision, DecisionProtocol
from aureproof.contracts.strict_json import JsonInputError, loads_strict
from aureproof.contracts.thr import TaskHealthRecord, thr_digest
from aureproof.scoring import compute_metrics
from aureproof.scoring.adjudication import adjusted, check, queue, resolve
from aureproof.scoring.episode import EpisodeScore
from aureproof.stats.decide import decide

Side = Literal["A", "B"]
VARIANTS = ("vulnerable", "repaired")


class GateError(ValueError):
    """The evidence does not belong to the protocol; no decision is made."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


@dataclass(frozen=True)
class SideSummary:
    side: Side
    system_identity: str
    episodes: int
    dispositions: dict[str, int]
    metrics: dict[str, str]  # "numerator/denominator", exact


@dataclass(frozen=True)
class Comparison:
    protocol: DecisionProtocol
    decision: Decision
    a: SideSummary
    b: SideSummary
    cluster_tasks: dict[str, list[str]] = field(default_factory=dict)


def _load(files: Mapping[str, bytes], path: str) -> object:
    return loads_strict(files[path], i_json=True)


def _scoring_profile(files: Mapping[str, bytes]) -> str | None:
    """The scoring identity the seal says graded the run, or None when unreadable."""
    try:
        profile = loads_strict(files[SEAL], i_json=True)["predicate"]["versions"]
        profile = profile["scoring_profile"]
    except (KeyError, TypeError, JsonInputError):
        return None
    return profile if isinstance(profile, str) else None


def _check(
    side: Side, protocol: DecisionProtocol, files: Mapping[str, bytes]
) -> tuple[list[str], dict[str, str], list[tuple[str, str, EpisodeScore]]]:
    """Problems, the task-to-cluster map, and (task_id, score) pairs for one bundle."""
    problems: list[str] = []
    expected_system = getattr(protocol.configurations, side)
    try:
        sealed = DecisionProtocol.model_validate(_load(files, PROTOCOL))
        if sealed.identity != protocol.identity:
            problems.append(f"{side}: sealed protocol {sealed.identity} is not this protocol")
    except (KeyError, JsonInputError, ValidationError) as exc:
        problems.append(f"{side}: no readable {PROTOCOL}: {type(exc).__name__}")
    try:
        system = SystemSpec.model_validate(_load(files, SYSTEM))
        if system.identity != expected_system:
            problems.append(f"{side}: system {system.identity} is not configuration {side}")
    except (KeyError, JsonInputError, ValidationError) as exc:
        problems.append(f"{side}: no readable {SYSTEM}: {type(exc).__name__}")

    profile = _scoring_profile(files)
    if profile is None:
        problems.append(f"{side}: the seal names no readable scoring profile")

    clusters: dict[str, str] = {}
    for cohort_task in protocol.cohort:
        found = None
        for path in files:
            if path.startswith("tasks/") and path.endswith("/thr.json"):
                try:
                    record = TaskHealthRecord.model_validate(_load(files, path))
                except (JsonInputError, ValidationError):
                    continue
                if record.task.task_identity == cohort_task.task_identity:
                    found = record
        if found is None:
            problems.append(f"{side}: no THR for cohort task {cohort_task.task_identity}")
        elif thr_digest(found) != cohort_task.thr_digest:
            problems.append(f"{side}: {found.task.task_id}: THR digest differs from the protocol")
        elif thr_path(found.task.task_id) not in files:
            problems.append(
                f"{side}: {found.task.task_id}: THR is not at {thr_path(found.task.task_id)}"
            )
        else:
            # The THR vouches for the grader its controls ran under, not for any grader.
            if profile is not None and found.scoring_identity != profile:
                problems.append(
                    f"{side}: {found.task.task_id}: THR controls ran under scoring identity "
                    f"{found.scoring_identity}, but the run was scored under {profile}"
                )
            clusters[found.task.task_id] = cohort_task.cluster_id

    try:
        episodes = _load(files, EPISODES)
        assert isinstance(episodes, list)
        counts = Counter((str(e["task_id"]), str(e["variant"])) for e in episodes)
    except (KeyError, JsonInputError, AssertionError, TypeError) as exc:
        problems.append(f"{side}: no readable {EPISODES}: {type(exc).__name__}")
        counts = Counter()
    for task_id in clusters:
        for variant in VARIANTS:
            n = counts.pop((task_id, variant), 0)
            if n != protocol.repetitions:
                problems.append(
                    f"{side}: {task_id}/{variant} has {n} episodes, protocol says "
                    f"{protocol.repetitions}"
                )
    for (task_id, variant), n in sorted(counts.items()):
        problems.append(f"{side}: {n} episode(s) of {task_id}/{variant} outside the cohort")

    for line in files.get("journal.jsonl", b"").splitlines():
        event = loads_strict(line, i_json=True)["event"]
        if event.get("kind") != JOURNAL_EPISODE_PLANNED:
            continue
        planned = event["payload"]["episode"]
        if planned.get("protocol") != protocol.identity or planned.get("system") != expected_system:
            problems.append(f"{side}: episode {event['episode_id']} was planned for another run")

    try:
        completeness = str(loads_strict(files[SEAL], i_json=True)["predicate"]["completeness"])
    except (KeyError, TypeError, JsonInputError):
        completeness = "unreadable"
    if completeness != "complete":
        problems.append(f"{side}: sealed as {completeness}; the gate needs complete evidence")
    redo = rescore(files)
    if redo.status != "reproduced":
        problems.append(f"{side}: offline re-score {redo.status}: {'; '.join(redo.problems)}")
    graded_by = sorted({score.scoring_identity for _, score in redo.scored} - {profile})
    if profile is not None and graded_by:
        problems.append(
            f"{side}: the seal names scoring profile {profile}, but episodes were scored "
            f"under {', '.join(graded_by)}"
        )
    pairs = [(ep.task_id, ep.episode_id, score) for ep, score in redo.scored]
    return problems, clusters, pairs


def _summary(side: Side, identity: str, pairs: list[tuple[str, str, EpisodeScore]]) -> SideSummary:
    scores = [s for _, _, s in pairs]
    metrics = compute_metrics(scores)
    return SideSummary(
        side=side,
        system_identity=identity,
        episodes=len(scores),
        dispositions=dict(sorted(Counter(s.disposition.value for s in scores).items())),
        metrics={k: f"{m.numerator}/{m.denominator}" for k, m in sorted(metrics.items())},
    )


def _adjudicated(
    side: Side,
    files: Mapping[str, bytes],
    pairs: list[tuple[str, str, EpisodeScore]],
    records: Sequence[Adjudication],
) -> tuple[list[str], dict[str, tuple[int, int, int]]]:
    """Problems with the records, and per task (confirmed, unresolved, submitted)."""
    episodes = [(eid, s) for _, eid, s in pairs]
    items = queue(episodes)
    seal = digest_ref(files[SEAL]) if SEAL in files else ""
    problems = [f"{side}: {p}" for p in check(records, items, seal)]
    resolutions = resolve(items, records) if not problems else []
    totals: dict[str, tuple[int, int, int]] = {}
    for task_id, eid, score in pairs:
        if not score.graded:
            continue
        c, _, u, n = adjusted(score, eid, resolutions)
        tc, tu, tn = totals.get(task_id, (0, 0, 0))
        totals[task_id] = (tc + c, tu + u, tn + n)
    return problems, totals


def compare(
    protocol: DecisionProtocol,
    files_a: Mapping[str, bytes],
    files_b: Mapping[str, bytes],
    *,
    adjudications_a: Sequence[Adjudication] = (),
    adjudications_b: Sequence[Adjudication] = (),
) -> Comparison:
    """The protocol's decision for two bundles, or ``GateError`` listing every mismatch.

    Adjudication records must name the bundle's seal and its unresolved findings.
    A decided finding counts under its adjudicated verdict; any finding still
    unresolved keeps a decisive result provisional (specs/decision §5).
    """
    problems_a, clusters_a, pairs_a = _check("A", protocol, files_a)
    problems_b, clusters_b, pairs_b = _check("B", protocol, files_b)
    problems = problems_a + problems_b
    adj_a, totals_a = _adjudicated("A", files_a, pairs_a, adjudications_a)
    adj_b, totals_b = _adjudicated("B", files_b, pairs_b, adjudications_b)
    problems += adj_a + adj_b
    if not problems and clusters_a != clusters_b:
        problems.append("A and B map the cohort to different task IDs")
    if problems:
        raise GateError(problems)

    rows = []
    cluster_tasks: dict[str, list[str]] = {}
    for task_id, cluster in clusters_a.items():
        cluster_tasks.setdefault(cluster, []).append(task_id)
    for cluster, tasks in sorted(cluster_tasks.items()):
        a = [sum(totals_a.get(t, (0, 0, 0))[i] for t in tasks) for i in range(3)]
        b = [sum(totals_b.get(t, (0, 0, 0))[i] for t in tasks) for i in range(3)]
        rows.append(
            ClusterRow(
                cluster_id=cluster,
                a_confirmed=a[0],
                a_submitted=a[2],
                b_confirmed=b[0],
                b_submitted=b[2],
                a_unresolved=a[1],
                b_unresolved=b[1],
                difference=None,
            )
        )
    return Comparison(
        protocol=protocol,
        decision=decide(protocol, rows),
        a=_summary("A", protocol.configurations.A, pairs_a),
        b=_summary("B", protocol.configurations.B, pairs_b),
        cluster_tasks={c: sorted(t) for c, t in sorted(cluster_tasks.items())},
    )
