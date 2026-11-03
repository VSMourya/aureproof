# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Adjudication: queue, final decisions, agreement, post-adjudication counts (issue #51)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from aureproof.contracts import EpisodeSignals, LabelSet, RunnerOutcome
from aureproof.contracts.adjudication import Adjudication
from aureproof.scoring import score_episode
from aureproof.scoring.adjudication import (
    QueueItem,
    adjusted,
    agreement,
    check,
    post_adjudication,
    queue,
    resolve,
)

ROOT = Path(__file__).resolve().parents[2]
G1 = json.loads((ROOT / "conformance/scoring/v0.1/golden.json").read_text())["label_sets"]["g1"]
LABELS = LabelSet.model_validate(G1)
OK = EpisodeSignals(evidence_complete=True, runner_outcome=RunnerOutcome.OK)
SEAL = "sha256:" + "5" * 64
HIT = {
    "cwe": 89,
    "locations": [{"file": "app/orders.py", "symbol": "find_orders"}],
    "description": "x",
}
WRONG_CLASS = {**HIT, "cwe": 79}  # right place, unaccepted CWE: unresolved:class_mismatch
ELSEWHERE = {
    "cwe": 89,
    "locations": [{"file": "app/orders.py", "start_line": 100, "end_line": 101}],
    "description": "x",
}  # outside every anchor and the reviewed scope: unresolved:out_of_scope


def _score(findings: list[dict[str, Any]]) -> Any:
    view = G1["agent_view"]["vulnerable"]
    return score_episode(
        json.dumps(findings).encode(), OK, LABELS, variant="vulnerable", agent_view=view
    )


def record(
    index: int, decision: str, who: str = "ana", role: str = "primary", **kw: Any
) -> Adjudication:
    fields: dict[str, Any] = {
        "bundle_seal": SEAL,
        "finding": {"episode_id": "e1", "finding_index": index},
        "original_verdict": "unresolved:class_mismatch"
        if index == 1
        else "unresolved:out_of_scope",
        "adjudicator": who,
        "role": role,
        "decision": decision,
        "rationale": "read the code",
        "timestamp": "2026-10-28T12:00:00Z",
        "dataset_revision_before": "0.1.0",
        "dataset_revision_after": "0.1.0",
    }
    fields.update(kw)
    return Adjudication.model_validate(fields)


@pytest.fixture
def episodes() -> list[tuple[str, Any]]:
    return [("e1", _score([HIT, WRONG_CLASS, ELSEWHERE]))]


def test_every_unresolved_finding_is_queued(episodes: list[tuple[str, Any]]) -> None:
    assert [v.verdict.value for v in episodes[0][1].verdicts] == [
        "confirmed",
        "unresolved:class_mismatch",
        "unresolved:out_of_scope",
    ]
    assert queue(episodes) == [
        QueueItem("e1", 1, "unresolved:class_mismatch"),
        QueueItem("e1", 2, "unresolved:out_of_scope"),
    ]


def test_a_label_change_needs_a_new_revision_and_only_it_has_one() -> None:
    with pytest.raises(ValidationError):
        record(1, "label_change")
    with pytest.raises(ValidationError):
        record(1, "confirmed", dataset_revision_after="0.2.0")
    assert (
        record(1, "label_change", dataset_revision_after="0.2.0").decision.value == "label_change"
    )


def test_records_for_another_bundle_or_finding_are_refused(episodes: list[tuple[str, Any]]) -> None:
    items = queue(episodes)
    assert check([record(1, "confirmed")], items, SEAL) == []
    assert "another bundle" in check([record(1, "confirmed")], items, "sha256:" + "6" * 64)[0]
    assert "not an unresolved finding" in check([record(0, "confirmed")], items, SEAL)[0]
    wrong = record(1, "confirmed", original_verdict="unresolved:out_of_scope")
    assert "is unresolved:class_mismatch" in check([wrong], items, SEAL)[0]


def test_decisions_disagreements_resolutions_and_label_changes(
    episodes: list[tuple[str, Any]],
) -> None:
    items = queue(episodes)
    agreeing = [record(1, "confirmed"), record(1, "confirmed", who="ben", role="second")]
    split = [record(2, "refuted"), record(2, "confirmed", who="ben", role="second")]
    [one, two] = resolve(items, agreeing + split)
    assert (one.status, one.decision.value if one.decision else None) == ("decided", "confirmed")
    assert (two.status, two.decision) == ("disagreement", None)
    settled = [*split, record(2, "refuted", who="cy", role="resolution")]
    assert resolve(items, settled)[1].status == "decided"
    relabel = [record(2, "label_change", dataset_revision_after="0.2.0")]
    assert resolve(items, relabel)[1].status == "label_change"
    assert resolve(items, [])[0].status == "pending"


def test_a_later_record_supersedes_without_erasing(episodes: list[tuple[str, Any]]) -> None:
    items = queue(episodes)
    first = record(1, "refuted", timestamp="2026-10-28T12:00:00Z")
    again = record(1, "confirmed", timestamp="2026-10-28T13:00:00Z")
    assert resolve(items, [again, first])[0].decision.value == "confirmed"  # type: ignore[union-attr]


def test_the_latest_record_is_the_latest_instant(episodes: list[tuple[str, Any]]) -> None:
    items = queue(episodes)
    # Half a second later: as strings, ".5Z" sorts before "Z" and the old record would win.
    first = record(1, "refuted", timestamp="2026-10-28T12:00:00Z")
    again = record(1, "confirmed", timestamp="2026-10-28T12:00:00.5Z")
    assert resolve(items, [again, first])[0].decision.value == "confirmed"  # type: ignore[union-attr]
    split = [record(2, "refuted"), record(2, "confirmed", who="ben", role="second")]
    early = record(2, "refuted", who="cy", role="resolution", timestamp="2026-10-28T13:00:00.1Z")
    late = record(2, "confirmed", who="dee", role="resolution", timestamp="2026-10-28T13:00:00.15Z")
    assert resolve(items, [*split, late, early])[1].decision.value == "confirmed"  # type: ignore[union-attr]


def test_post_adjudication_counts_keep_label_changes_and_pending_unresolved(
    episodes: list[tuple[str, Any]],
) -> None:
    items = queue(episodes)
    resolutions = resolve(
        items,
        [record(1, "confirmed"), record(2, "label_change", dataset_revision_after="0.2.0")],
    )
    assert adjusted(episodes[0][1], "e1", resolutions) == (2, 0, 1, 3)
    assert post_adjudication(episodes, resolutions) == {
        "adjudicated_precision": (2, 2),
        "strict_confirmed_yield": (2, 3),
        "unresolved_fraction": (1, 3),
    }
    assert post_adjudication(episodes, resolve(items, []))["strict_confirmed_yield"] == (1, 3)


def test_cohens_kappa_and_double_coverage(episodes: list[tuple[str, Any]]) -> None:
    items = queue(episodes)
    none = agreement(items, [record(1, "confirmed")])
    assert (none.kappa, none.coverage_ok) == (None, False)
    assert none.undefined_reason == "no finding has two adjudicators"
    same = agreement(
        items, [record(1, "confirmed"), record(1, "confirmed", who="b", role="second")]
    )
    assert same.kappa is None and "chance agreement is 1" in (same.undefined_reason or "")
    assert same.coverage_ok  # 1 of 2 queued findings >= 20%
    mixed = agreement(
        items,
        [
            record(1, "confirmed"),
            record(1, "confirmed", who="b", role="second"),
            record(2, "refuted"),
            record(2, "confirmed", who="b", role="second"),
        ],
    )
    # observed 1/2; chance: left {c:1, r:1}, right {c:2} -> (1*2)/4 = 1/2; kappa = 0
    assert mixed.agreed == 1 and mixed.kappa == 0.0
