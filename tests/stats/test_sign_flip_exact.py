# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""The integer sign-flip equals the original Fraction enumeration exactly, and the
cluster limit is refused when the protocol is written, not after the run."""

from __future__ import annotations

import json
import math
from collections.abc import Sequence
from fractions import Fraction
from itertools import combinations
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from aureproof.contracts.decision import ClusterRow, DecisionProtocol
from aureproof.stats import MAX_CLUSTERS, SignFlipResult, decide, sign_flip
from aureproof.stats.permutation import p_two_sided

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "conformance/decision/v0.1/vectors.json").read_text("utf-8"))
ALPHAS = (0.001, 0.025, 0.05, 0.1, 0.25, 0.4)


# --- The original implementation (main 8c99d4f), kept verbatim as the oracle ---------


def _reference_subset_means(d: Sequence[Fraction]) -> list[Fraction]:
    means: list[Fraction] = []
    for size in range(1, len(d) + 1):
        for subset in combinations(d, size):
            means.append(Fraction(sum(subset, Fraction(0)), size))
    return sorted(means)


def _reference_p_two_sided(d: Sequence[Fraction]) -> Fraction:
    observed = abs(sum(d, Fraction(0)))
    k = len(d)
    hits = 0
    for mask in range(2**k):
        total: Fraction = sum(((-x if mask >> i & 1 else x) for i, x in enumerate(d)), Fraction(0))
        hits += abs(total) >= observed
    return Fraction(hits, 2**k)


def reference_sign_flip(d: Sequence[Fraction], alpha: float) -> SignFlipResult:
    k = len(d)
    mean = Fraction(sum(d, Fraction(0)), k)
    r = math.floor(alpha * 2**k)
    means = _reference_subset_means(d)
    lower = means[r - 1] if r >= 1 else None
    upper = means[len(means) - r] if r >= 1 else None
    return SignFlipResult(k, mean, _reference_p_two_sided(d), lower, upper)


# --- Equality with the oracle -------------------------------------------------------

differences = st.lists(
    st.fractions(min_value=-1, max_value=1, max_denominator=12), min_size=1, max_size=10
)


@settings(max_examples=300, deadline=None)
@given(differences, st.sampled_from(ALPHAS))
def test_integer_enumeration_equals_the_fraction_enumeration(
    d: list[Fraction], alpha: float
) -> None:
    assert sign_flip(d, alpha) == reference_sign_flip(d, alpha)
    assert p_two_sided(d) == _reference_p_two_sided(d)


@pytest.mark.parametrize("alpha", ALPHAS)
def test_equal_on_fourteen_clusters_with_unlike_denominators(alpha: float) -> None:
    d = [Fraction(i % 3, 3) - Fraction(1, 3) + Fraction(1, 7 + i) for i in range(14)]
    assert sign_flip(d, alpha) == reference_sign_flip(d, alpha)


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["id"])
def test_equal_on_the_conformance_vectors(case: dict[str, Any]) -> None:
    rows = [ClusterRow.model_validate(r) for r in case["rows"]]
    protocol = DecisionProtocol.model_validate(case["protocol"])
    d = [Fraction(r.difference) for r in decide(protocol, rows).cluster_table if r.difference]
    if d:
        assert sign_flip(d, 0.025) == reference_sign_flip(d, 0.025)


def test_ties_zeros_and_integers() -> None:
    for d in ([Fraction(0)] * 7, [Fraction(1)] * 6, [Fraction(-1), Fraction(1)] * 4):
        for alpha in ALPHAS:
            assert sign_flip(d, alpha) == reference_sign_flip(d, alpha)


def test_the_limit_itself_runs_exactly() -> None:
    """k = MAX_CLUSTERS, all +1: only the all-plus and all-minus flips reach |sum| = k."""
    result = sign_flip([Fraction(1)] * MAX_CLUSTERS, 0.025)
    assert result.p_two_sided == Fraction(2, 2**MAX_CLUSTERS)
    assert result.lower == result.upper == result.mean == 1


def test_sign_flip_still_refuses_more_than_the_limit() -> None:
    with pytest.raises(ValueError, match=str(MAX_CLUSTERS)):
        sign_flip([Fraction(1)] * (MAX_CLUSTERS + 1), 0.025)
    with pytest.raises(ValueError):
        sign_flip([], 0.025)


# --- The limit is a protocol validity rule ------------------------------------------


def _protocol(clusters: int, tasks_per_cluster: int = 1) -> dict[str, Any]:
    cohort = [
        {
            "task_identity": "sha256:" + format(c * 100 + t, "064x"),
            "thr_digest": "sha256:" + "e" * 64,
            "cluster_id": f"c{c}",
        }
        for c in range(clusters)
        for t in range(tasks_per_cluster)
    ]
    return {
        "protocol_version": "0.1",
        "name": "limit",
        "cohort": cohort,
        "configurations": {"A": "sha256:" + "1" * 64, "B": "sha256:" + "2" * 64},
        "repetitions": 1,
        "margin": 0.05,
    }


def test_a_protocol_beyond_the_limit_is_invalid() -> None:
    with pytest.raises(ValidationError, match="at most 20 clusters"):
        DecisionProtocol.model_validate(_protocol(MAX_CLUSTERS + 1))


def test_the_limit_counts_clusters_not_tasks() -> None:
    protocol = DecisionProtocol.model_validate(_protocol(MAX_CLUSTERS, tasks_per_cluster=2))
    assert len(protocol.cohort) == 2 * MAX_CLUSTERS


def test_protocols_too_small_to_decide_still_load() -> None:
    """Descriptive protocols (the M2 slice has 3 clusters) stay valid."""
    for path in sorted((ROOT / "protocols").glob("*/protocol.json")):
        DecisionProtocol.model_validate_json(path.read_bytes())
    DecisionProtocol.model_validate(_protocol(1))


def test_decide_reports_too_many_rows_as_inconclusive() -> None:
    """Rows beyond the limit never crash the gate and never pass."""
    protocol = DecisionProtocol.model_validate(_protocol(6))
    rows = [
        ClusterRow(
            cluster_id=f"x{i}",
            a_confirmed=0,
            a_submitted=1,
            b_confirmed=1,
            b_submitted=1,
            difference=None,
        )
        for i in range(MAX_CLUSTERS + 1)
    ]
    decision = decide(protocol, rows)
    assert decision.outcome == decision.provisional_outcome == "inconclusive"
    assert decision.clusters == MAX_CLUSTERS + 1
    assert "exceed the exact enumeration limit" in decision.reason
    assert decision.ci.lower is None and decision.ci.upper is None


def test_the_vector_is_invalid_only_because_of_its_cluster_count() -> None:
    instance = VECTORS["invalid_protocols"]["too-many-clusters"]["instance"]
    assert len({t["cluster_id"] for t in instance["cohort"]}) == MAX_CLUSTERS + 1
    DecisionProtocol.model_validate({**instance, "cohort": instance["cohort"][:MAX_CLUSTERS]})
