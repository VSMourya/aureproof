# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""The three-way decision gate (specs/decision §5). Pure."""

from __future__ import annotations

from collections.abc import Sequence
from fractions import Fraction

from aureproof.contracts.decision import ClusterRow, Decision, DecisionProtocol, Interval
from aureproof.stats.permutation import min_clusters, sign_flip
from aureproof.stats.wilson import wilson


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
    """Pass if CI lower > -margin and some B could have failed; fail if CI upper < -margin.

    Otherwise inconclusive (specs/decision §5).
    """
    policy = protocol.estimand.undefined_yield
    alpha = protocol.test.alpha
    table: list[ClusterRow] = []
    diffs: list[Fraction] = []
    baseline: list[Fraction] = []  # A's yield in each cluster that enters the test
    for row in rows:
        a = _rate(row.a_confirmed, row.a_submitted, policy)
        b = _rate(row.b_confirmed, row.b_submitted, policy)
        diff = None
        if a is not None and b is not None:
            diff = b - a
            diffs.append(diff)
            baseline.append(a)
        table.append(row.model_copy(update={"difference": _fmt(diff)}))
    needed = min_clusters(alpha)
    wa = _interval(
        wilson(sum(r.a_confirmed for r in rows), sum(r.a_submitted for r in rows), alpha)
    )
    wb = _interval(
        wilson(sum(r.b_confirmed for r in rows), sum(r.b_submitted for r in rows), alpha)
    )

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
    if provisional == "pass":
        # Every subset mean rises with each d_c, so B's worst case on these clusters is a
        # yield of 0 everywhere (d_c = -a_c). If even that passes, the data could not
        # have said anything else: the baseline leaves no room to measure a regression.
        worst = sign_flip([-a for a in baseline], alpha).lower
        if worst is not None and worst > -margin:
            reason = (
                f"provisional pass, but no B could have failed: with B's yield 0 in every "
                f"cluster the CI lower bound would still be {worst} > -margin {-margin}"
            )
            return build("inconclusive", provisional, reason, **stats)
    return build(provisional, provisional, reason, **stats)
