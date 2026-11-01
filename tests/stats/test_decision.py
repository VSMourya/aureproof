# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Decision Protocol and the exact three-way gate (issue #14)."""

from __future__ import annotations

import itertools
import json
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from aureproof.contracts.decision import ClusterRow, DecisionProtocol
from aureproof.contracts.decision_schema import SCHEMA_DIR, export_schemas
from aureproof.stats import decide, min_clusters, sign_flip, wilson

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "conformance/decision/v0.1/vectors.json").read_text("utf-8"))


def _frac(s: str | None) -> Fraction | None:
    return None if s is None else Fraction(s)


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["id"])
def test_hand_checked_vector(case: dict[str, Any]) -> None:
    protocol = DecisionProtocol.model_validate(case["protocol"])
    decision = decide(protocol, [ClusterRow.model_validate(r) for r in case["rows"]])
    exp = case["expected"]
    assert decision.outcome == exp["outcome"]
    assert decision.provisional_outcome == exp["provisional_outcome"]
    assert decision.clusters == exp["clusters"]
    assert _frac(decision.mean_difference) == _frac(exp["mean_difference"])
    assert _frac(decision.p_value_two_sided) == _frac(exp["p_value_two_sided"])
    for bound in ("lower", "upper"):
        got = getattr(decision.ci, bound)
        want = _frac(exp[bound])
        assert (got is None) == (want is None)
        if want is not None:
            assert got == pytest.approx(float(want), abs=0, rel=1e-15)
    assert decision.protocol == protocol.identity
    assert decision.min_clusters_for_decision == 6


def test_vectors_cover_pass_fail_inconclusive_tie_zero_and_adjudication() -> None:
    outcomes = {c["expected"]["outcome"] for c in VECTORS["cases"]}
    assert outcomes == {"pass", "fail", "inconclusive"}
    titles = " ".join(c["title"] for c in VECTORS["cases"]).lower()
    for word in (
        "zero difference",
        "exactly at -margin",
        "five clusters",
        "unadjudicated",
        "vacuous",
    ):
        assert word in titles


def test_fewer_than_six_clusters_cannot_be_decisive_at_the_default_alpha() -> None:
    assert min_clusters(0.025) == 6
    for k in range(1, 6):
        assert sign_flip([Fraction(1)] * k, 0.025).lower is None
    assert sign_flip([Fraction(1)] * 6, 0.025).lower == 1


@pytest.mark.parametrize("name", sorted(VECTORS["invalid_protocols"]))
def test_invalid_protocols(name: str) -> None:
    with pytest.raises(ValidationError):
        DecisionProtocol.model_validate(VECTORS["invalid_protocols"][name]["instance"])


@pytest.mark.parametrize("w", VECTORS["wilson"], ids=lambda w: f"{w['successes']}/{w['trials']}")
def test_wilson_against_published_values(w: dict[str, Any]) -> None:
    got = wilson(w["successes"], w["trials"], w["alpha"])
    if w["lower"] is None:
        assert got is None
    else:
        assert got is not None
        assert got[0] == pytest.approx(w["lower"], abs=1e-5)
        assert got[1] == pytest.approx(w["upper"], abs=1e-5)


def _p_upper(d: list[Fraction], delta0: Fraction) -> Fraction:
    """The definition: P(sum of sign-flipped (d - delta0) >= observed), by enumeration."""
    shifted = [x - delta0 for x in d]
    observed = sum(shifted, Fraction(0))
    hits = sum(
        sum((s * x for s, x in zip(signs, shifted, strict=True)), Fraction(0)) >= observed
        for signs in itertools.product((1, -1), repeat=len(d))
    )
    return Fraction(hits, 2 ** len(d))


@settings(max_examples=60, deadline=None)
@given(st.lists(st.fractions(min_value=-1, max_value=1, max_denominator=6), min_size=6, max_size=8))
def test_closed_form_interval_matches_the_test_definition(d: list[Fraction]) -> None:
    """The lower bound is the smallest candidate delta0 the exact one-sided test does not reject."""
    alpha = 0.025
    result = sign_flip(d, alpha)
    candidates = sorted(
        {
            Fraction(sum(s, Fraction(0)), len(s))
            for n in range(1, len(d) + 1)
            for s in itertools.combinations(d, n)
        }
    )
    not_rejected = [c for c in candidates if _p_upper(d, c) > alpha]
    assert result.lower == min(not_rejected)
    # Mirror image for the upper bound.
    mirrored = [-x for x in d]
    not_rejected_up = [c for c in sorted({-c for c in candidates}) if _p_upper(mirrored, c) > alpha]
    assert result.upper == -min(not_rejected_up)


def test_committed_decision_schemas_match_the_models() -> None:
    on_disk = {
        p.name.removesuffix(".schema.json"): json.loads(p.read_text("utf-8"))
        for p in (ROOT / SCHEMA_DIR).glob("*.schema.json")
    }
    assert on_disk == export_schemas()


def test_protocol_identity_changes_with_any_term() -> None:
    base = VECTORS["cases"][0]["protocol"]
    ids = {DecisionProtocol.model_validate(base).identity}
    for change in ({"margin": 0.1}, {"repetitions": 5}, {"name": "other"}):
        ids.add(DecisionProtocol.model_validate({**base, **change}).identity)
    assert len(ids) == 4


def test_the_margin_is_the_decimal_the_protocol_wrote() -> None:
    """A CI lower bound of exactly -margin is not a pass (L > -margin is strict).

    Read as a binary float, 0.05 is a little more than 1/20, and every cluster at
    -1/20 used to pass.
    """
    cohort = [
        {
            "task_identity": "sha256:" + format(i, "064x"),
            "thr_digest": "sha256:" + "a" * 64,
            "cluster_id": f"c{i}",
        }
        for i in range(8)
    ]
    protocol = DecisionProtocol.model_validate(
        {
            "protocol_version": "0.1",
            "name": "margin-boundary",
            "cohort": cohort,
            "configurations": {"A": "sha256:" + "1" * 64, "B": "sha256:" + "2" * 64},
            "repetitions": 1,
            "margin": 0.05,
        }
    )
    rows = [
        ClusterRow(
            cluster_id=f"c{i}",
            a_confirmed=20,
            a_submitted=20,
            b_confirmed=19,
            b_submitted=20,
            difference=None,
        )
        for i in range(8)
    ]
    decision = decide(protocol, rows)
    assert decision.mean_difference == "-1/20"
    assert decision.outcome == "inconclusive", decision.reason
    assert "-1/20" in decision.reason and "72057594037927936" not in decision.reason


def _protocol(k: int, margin: float) -> DecisionProtocol:
    return DecisionProtocol.model_validate(
        {
            "protocol_version": "0.1",
            "name": "vacuity",
            "cohort": [
                {
                    "task_identity": "sha256:" + format(i, "064x"),
                    "thr_digest": "sha256:" + "a" * 64,
                    "cluster_id": f"c{i}",
                }
                for i in range(k)
            ],
            "configurations": {"A": "sha256:" + "1" * 64, "B": "sha256:" + "2" * 64},
            "repetitions": 1,
            "margin": margin,
        }
    )


def _counts(most_confirmed: int) -> st.SearchStrategy[tuple[int, int]]:
    """(confirmed, submitted) with confirmed <= submitted <= 6."""
    return st.tuples(st.integers(0, most_confirmed), st.integers(0, 6)).map(
        lambda t: (min(t), max(t))
    )


@settings(max_examples=200, deadline=None)
@given(
    # A weak baseline (at most one confirmed finding per cluster) makes certain passes common.
    st.lists(st.tuples(_counts(1), _counts(6)), min_size=6, max_size=8),
    st.sampled_from([0.0, 0.05, 0.25]),
)
def test_a_pass_is_never_certain_before_b_is_seen(
    clusters: list[tuple[tuple[int, int], tuple[int, int]]], margin: float
) -> None:
    """A pass stands only if B with yield 0 in every cluster would not also have passed.

    Every subset mean, and so the interval's lower bound, rises with each cluster
    difference, so B = 0 everywhere is the worst case for B on the same clusters.
    """
    protocol = _protocol(len(clusters), margin)
    rows = [
        ClusterRow(
            cluster_id=f"c{i}",
            a_confirmed=ac,
            a_submitted=an,
            b_confirmed=bc,
            b_submitted=bn,
            difference=None,
        )
        for i, ((ac, an), (bc, bn)) in enumerate(clusters)
    ]
    worst = [r.model_copy(update={"b_confirmed": 0}) for r in rows]
    decision, worst_case = decide(protocol, rows), decide(protocol, worst)
    certain = worst_case.provisional_outcome == "pass"
    if decision.provisional_outcome == "pass":
        assert decision.outcome == ("inconclusive" if certain else "pass"), decision.reason
    if certain:
        assert decision.outcome != "pass"
        assert decision.provisional_outcome == "pass"
        assert "could have failed" in decision.reason


def test_a_silent_cohort_never_passes_the_gate() -> None:
    """Both configurations submitting nothing anywhere, as a broken runner would."""
    rows = [
        ClusterRow(
            cluster_id=f"c{i}",
            a_confirmed=0,
            a_submitted=0,
            b_confirmed=0,
            b_submitted=0,
            difference=None,
        )
        for i in range(12)
    ]
    decision = decide(_protocol(12, 0.05), rows)
    assert decision.outcome == "inconclusive"
    assert decision.provisional_outcome == "pass"
