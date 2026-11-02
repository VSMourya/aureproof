# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Per-configuration yield intervals that count clusters, not findings, as independent."""

from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aureproof.contracts.decision import ClusterRow, DecisionProtocol
from aureproof.stats import clustered_wilson, decide, t_upper, wilson

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "conformance/decision/v0.1/vectors.json").read_text("utf-8"))


@pytest.mark.parametrize("alpha", [0.001, 0.025, 0.05, 0.1, 0.25])
def test_t_quantile_matches_the_closed_forms_for_one_and_two_df(alpha: float) -> None:
    # df = 1 is Cauchy; df = 2 has F(t) = 1/2 + t / (2 sqrt(2 + t^2)).
    assert t_upper(alpha, 1) == pytest.approx(math.tan(math.pi * (0.5 - alpha)), rel=1e-12)
    a = 1 - 2 * alpha
    assert t_upper(alpha, 2) == pytest.approx(a * math.sqrt(2 / (1 - a * a)), rel=1e-12)


@pytest.mark.parametrize(
    ("alpha", "df", "published"),
    [
        (0.025, 3, 3.182446),
        (0.025, 5, 2.570582),
        (0.025, 10, 2.228139),
        (0.025, 19, 2.093024),
        (0.025, 30, 2.042272),
        (0.05, 4, 2.131847),
        (0.005, 19, 2.860935),
    ],
)
def test_t_quantile_matches_published_tables(alpha: float, df: int, published: float) -> None:
    assert t_upper(alpha, df) == pytest.approx(published, abs=1e-6)


def test_t_quantile_tends_to_the_normal_quantile() -> None:
    assert t_upper(0.025, 2000) == pytest.approx(1.959964, abs=2e-3)
    with pytest.raises(ValueError, match="degree of freedom"):
        t_upper(0.025, 0)
    for alpha in (0.0, 0.5):
        with pytest.raises(ValueError, match="alpha"):
            t_upper(alpha, 5)


@pytest.mark.parametrize("v", VECTORS["clustered_wilson"], ids=lambda v: v["id"])
def test_clustered_wilson_vectors(v: dict[str, Any]) -> None:
    got = clustered_wilson([tuple(c) for c in v["clusters"]], v["alpha"])
    if v["lower"] is None:
        assert got is None
    else:
        assert got is not None
        assert got[0] == pytest.approx(v["lower"], abs=1e-6)
        assert got[1] == pytest.approx(v["upper"], abs=1e-6)


_cluster = st.tuples(st.integers(0, 8), st.integers(1, 8)).map(lambda t: (min(t), max(t)))


@settings(max_examples=300, deadline=None)
@given(st.lists(_cluster, min_size=2, max_size=14), st.sampled_from([0.025, 0.05, 0.1]))
def test_never_narrower_than_treating_every_finding_as_independent(
    clusters: list[tuple[int, int]], alpha: float
) -> None:
    """Fewer effective trials and a t quantile can only widen the score interval."""
    naive = wilson(sum(c for c, _ in clusters), sum(n for _, n in clusters), alpha)
    clustered = clustered_wilson(clusters, alpha)
    assert naive is not None and clustered is not None
    assert clustered[0] <= naive[0] + 1e-12
    assert clustered[1] >= naive[1] - 1e-12


def test_one_cluster_bounds_nothing_and_empty_clusters_do_not_count() -> None:
    assert clustered_wilson([(3, 10)], 0.025) == (0.0, 1.0)
    assert clustered_wilson([(3, 10), (0, 0), (0, 0)], 0.025) == (0.0, 1.0)
    assert clustered_wilson([(0, 0), (0, 0)], 0.025) is None
    with pytest.raises(ValueError, match="within"):
        clustered_wilson([(5, 4), (1, 2)], 0.025)


def test_cluster_order_does_not_matter() -> None:
    rows = [(0, 4), (4, 4), (1, 3), (2, 7), (5, 6), (0, 1)]
    assert clustered_wilson(rows, 0.025) == clustered_wilson(list(reversed(rows)), 0.025)


def test_the_decision_reports_cluster_counted_intervals() -> None:
    """The M2 live slice shape: yield 1/4 in each of three clusters (3/12 pooled)."""
    case = VECTORS["cases"][0]
    protocol = DecisionProtocol.model_validate(case["protocol"])
    rows = [
        ClusterRow(
            cluster_id=f"c{i}",
            a_confirmed=1,
            a_submitted=4,
            b_confirmed=c,
            b_submitted=n,
            difference=None,
        )
        for i, (c, n) in enumerate([(0, 4), (4, 4), (0, 4)])
    ]
    decision = decide(protocol, rows)
    a = clustered_wilson([(1, 4)] * 3, protocol.test.alpha)
    b = clustered_wilson([(0, 4), (4, 4), (0, 4)], protocol.test.alpha)
    assert a is not None and b is not None
    assert (decision.wilson_a.lower, decision.wilson_a.upper) == a
    assert (decision.wilson_b.lower, decision.wilson_b.upper) == b
    naive = wilson(3, 12, protocol.test.alpha)
    assert naive is not None and a[0] < naive[0] and a[1] > naive[1]
