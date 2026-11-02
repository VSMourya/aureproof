# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""The three-way decision gate (specs/decision §5). Pure."""

from __future__ import annotations

from collections.abc import Sequence
from fractions import Fraction

from aureproof.contracts.decision import ClusterRow, Decision, DecisionProtocol, Interval
from aureproof.stats.permutation import min_clusters, sign_flip
from aureproof.stats.wilson import clustered_wilson


def _rate(confirmed: int, submitted: int, policy: str) -> Fraction | None:
    if submitted:
        return Fraction(confirmed, submitted)
    return Fraction(0) if policy == "zero" else None


def _fmt(x: Fraction | None) -> str | None:
    return None if x is None else f"{x.numerator}/{x.denominator}"


def _interval(bounds: tuple[float, float] | None) -> Interval:
    return (
        Interval(lower=bounds[0], upper=bounds[1]) if bounds else Interval(lower=None, upper=None)
    )


def decide(protocol: DecisionProtocol, rows: Sequence[ClusterRow]) -> Decision:
    """Pass if CI lower > -margin; fail if CI upper < -margin; otherwise inconclusive."""
    policy = protocol.estimand.undefined_yield
    alpha = protocol.test.alpha
    table: list[ClusterRow] = []
    diffs: list[Fraction] = []
    for row in rows:
        a = _rate(row.a_confirmed, row.a_submitted, policy)
        b = _rate(row.b_confirmed, row.b_submitted, policy)
        diff = None if a is None or b is None else b - a
        if diff is not None:
            diffs.append(diff)
        table.append(row.model_copy(update={"difference": _fmt(diff)}))
    needed = min_clusters(alpha)
    # Pooled yield per configuration, with clusters (not findings) as the independent units.
    wa = _interval(clustered_wilson([(r.a_confirmed, r.a_submitted) for r in rows], alpha))
    wb = _interval(clustered_wilson([(r.b_confirmed, r.b_submitted) for r in rows], alpha))

    def build(outcome: str, provisional: str, reason: str, **stats: object) -> Decision:
        return Decision.model_validate(
            {
                "protocol": protocol.identity,
                "outcome": outcome,
                "provisional_outcome": provisional,
                "reason": reason,
                "clusters": len(diffs),
                "min_clusters_for_decision": needed,
                "wilson_a": wa,
                "wilson_b": wb,
                "cluster_table": table,
                "mean_difference": None,
                "p_value_two_sided": None,
                "ci": Interval(lower=None, upper=None),
                **stats,
            }
        )

    if not diffs:
        return build("inconclusive", "inconclusive", "no cluster has a defined difference")
    result = sign_flip(diffs, alpha)
    stats = {
        "mean_difference": _fmt(result.mean),
        "p_value_two_sided": _fmt(result.p_two_sided),
        "ci": Interval(
            lower=None if result.lower is None else float(result.lower),
            upper=None if result.upper is None else float(result.upper),
        ),
    }
    margin = Fraction(str(protocol.margin))  # the decimal as written; Fraction(0.05) > 1/20
    if result.lower is None or result.upper is None:
        reason = f"{result.k} clusters cannot reach a decisive outcome (need >= {needed})"
        return build("inconclusive", "inconclusive", reason, **stats)
    if result.lower > -margin:
        provisional, reason = "pass", f"CI lower bound {result.lower} > -margin {-margin}"
    elif result.upper < -margin:
        provisional, reason = "fail", f"CI upper bound {result.upper} < -margin {-margin}"
    else:
        provisional, reason = "inconclusive", f"CI [{result.lower}, {result.upper}] spans -margin"
    unresolved = sum(r.a_unresolved + r.b_unresolved for r in rows)
    if protocol.require_complete_adjudication and unresolved and provisional != "inconclusive":
        reason = f"provisional {provisional}, but {unresolved} findings are not adjudicated"
        return build("inconclusive", provisional, reason, **stats)
    return build(provisional, provisional, reason, **stats)
