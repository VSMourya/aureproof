# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""The three-way decision gate (specs/decision §5). Pure."""

from __future__ import annotations

from collections.abc import Sequence
from fractions import Fraction
from typing import Literal

from aureproof.contracts.decision import (
    ClusterRow,
    Decision,
    DecisionProtocol,
    Guardrail,
    GuardrailResult,
    Interval,
)
from aureproof.stats.permutation import MAX_CLUSTERS, SignFlipResult, min_clusters, sign_flip
from aureproof.stats.wilson import wilson

Outcome = Literal["pass", "fail", "inconclusive"]


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


def _ci(result: SignFlipResult | None) -> Interval:
    if result is None:
        return Interval(lower=None, upper=None)
    return Interval(
        lower=None if result.lower is None else float(result.lower),
        upper=None if result.upper is None else float(result.upper),
    )


def _three_way(
    diffs: Sequence[Fraction], alpha: float, margin: Fraction
) -> tuple[Outcome, str, SignFlipResult | None]:
    """The exact interval against -margin (§5 rules 1-3)."""
    if not diffs:
        return "inconclusive", "no cluster has a defined difference", None
    if len(diffs) > MAX_CLUSTERS:  # a valid protocol cannot produce this many rows
        reason = f"{len(diffs)} clusters exceed the exact enumeration limit of {MAX_CLUSTERS}"
        return "inconclusive", reason, None
    result = sign_flip(diffs, alpha)
    if result.lower is None or result.upper is None:
        needed = min_clusters(alpha)
        reason = f"{result.k} clusters cannot reach a decisive outcome (need >= {needed})"
        return "inconclusive", reason, result
    if result.lower > -margin:
        return "pass", f"CI lower bound {result.lower} > -margin {-margin}", result
    if result.upper < -margin:
        return "fail", f"CI upper bound {result.upper} < -margin {-margin}", result
    return "inconclusive", f"CI [{result.lower}, {result.upper}] spans -margin", result


def _guardrail(
    guardrail: Guardrail, rows: Sequence[ClusterRow], policy: str, alpha: float
) -> GuardrailResult:
    """Known-defect recall per cluster, B - A, under the same exact test (§5 rule 6)."""
    diffs: list[Fraction] = []
    for row in rows:
        a = _rate(row.a_credited, row.a_positives, policy)
        b = _rate(row.b_credited, row.b_positives, policy)
        if a is not None and b is not None:
            diffs.append(b - a)
    outcome, reason, result = _three_way(diffs, alpha, Fraction(str(guardrail.margin)))
    return GuardrailResult(
        metric=guardrail.metric,
        margin=guardrail.margin,
        outcome=outcome,
        reason=reason,
        clusters=len(diffs),
        mean_difference=None if result is None else _fmt(result.mean),
        ci=_ci(result),
    )


def _combined(primary: Outcome, guardrails: Sequence[GuardrailResult]) -> Outcome:
    """Intersection-union: a pass needs every test to pass; any fail is a fail."""
    outcomes = [primary, *(g.outcome for g in guardrails)]
    if "fail" in outcomes:
        return "fail"
    return "pass" if all(o == "pass" for o in outcomes) else "inconclusive"


def decide(protocol: DecisionProtocol, rows: Sequence[ClusterRow]) -> Decision:
    """Pass if CI lower > -margin and some B could have failed; fail if CI upper < -margin.

    Otherwise inconclusive (specs/decision §5). Every pre-registered guardrail must
    pass too, and any guardrail fail is a fail.
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
    wa = _interval(
        wilson(sum(r.a_confirmed for r in rows), sum(r.a_submitted for r in rows), alpha)
    )
    wb = _interval(
        wilson(sum(r.b_confirmed for r in rows), sum(r.b_submitted for r in rows), alpha)
    )
    margin = Fraction(str(protocol.margin))  # the decimal as written; Fraction(0.05) > 1/20
    provisional, reason, result = _three_way(diffs, alpha, margin)
    outcome = provisional
    unresolved = sum(r.a_unresolved + r.b_unresolved for r in rows)
    if protocol.require_complete_adjudication and unresolved and provisional != "inconclusive":
        outcome = "inconclusive"
        reason = f"provisional {provisional}, but {unresolved} findings are not adjudicated"
    elif provisional == "pass":
        # Every subset mean rises with each d_c, so B's worst case on these clusters is a
        # yield of 0 everywhere (d_c = -a_c). If even that passes, the data could not
        # have said anything else: the baseline leaves no room to measure a regression.
        worst = sign_flip([-a for a in baseline], alpha).lower
        if worst is not None and worst > -margin:
            outcome = "inconclusive"
            reason = (
                f"provisional pass, but no B could have failed: with B's yield 0 in every "
                f"cluster the CI lower bound would still be {worst} > -margin {-margin}"
            )
    guards = [_guardrail(g, rows, policy, alpha) for g in protocol.guardrails]
    for g in guards:
        reason += f"; guardrail {g.metric} {g.outcome}: {g.reason}"
    return Decision.model_validate(
        {
            "protocol": protocol.identity,
            "outcome": _combined(outcome, guards),
            "provisional_outcome": _combined(provisional, guards),
            "reason": reason,
            "clusters": len(diffs),
            "min_clusters_for_decision": min_clusters(alpha),
            "wilson_a": wa,
            "wilson_b": wb,
            "cluster_table": table,
            "mean_difference": None if result is None else _fmt(result.mean),
            "p_value_two_sided": None if result is None else _fmt(result.p_two_sided),
            "ci": _ci(result),
            "guardrails": guards,
        }
    )
