# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Wilson score intervals for a yield (per configuration; specs/decision §4).

``wilson`` is the textbook interval: every trial independent. The findings behind a
yield are not: findings of one episode share its understanding of the task, and the
repetitions and variants of one task share its difficulty. ``clustered_wilson`` keeps
the score interval but counts clusters, the gate's independent units, as the
evidence: the trial count becomes the effective sample size implied by the
between-cluster variance, and the normal quantile becomes Student's t with k - 1
degrees of freedom (Korn and Graubard 1998; Dean and Pagano 2015).
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from fractions import Fraction
from statistics import NormalDist


def _score(p: float, n: float, q: float) -> tuple[float, float]:
    """The Wilson score interval for proportion ``p`` over ``n`` trials, quantile ``q``."""
    denom = 1 + q * q / n
    centre = (p + q * q / (2 * n)) / denom
    half = q * math.sqrt(p * (1 - p) / n + q * q / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def wilson(successes: int, trials: int, alpha: float) -> tuple[float, float] | None:
    """The (1 - 2*alpha) Wilson interval, or None when there are no trials."""
    if trials == 0:
        return None
    if not 0 <= successes <= trials:
        raise ValueError("successes must be within 0..trials")
    return _score(successes / trials, trials, NormalDist().inv_cdf(1 - alpha))


def _t_central(t: float, df: int) -> float:
    """P(-t <= T <= t) for Student's t with integer ``df`` (Abramowitz-Stegun 26.7.3-4)."""
    theta = math.atan(t / math.sqrt(df))
    c2 = math.cos(theta) ** 2
    if df % 2:
        term = total = math.cos(theta)
        for j in range(1, (df - 1) // 2):
            term *= 2 * j / (2 * j + 1) * c2
            total += term
        return 2 / math.pi * (theta + (math.sin(theta) * total if df > 1 else 0.0))
    term = total = 1.0
    for j in range(1, df // 2):
        term *= (2 * j - 1) / (2 * j) * c2
        total += term
    return math.sin(theta) * total


def t_upper(alpha: float, df: int) -> float:
    """The t with P(T > t) = alpha, for Student's t with ``df`` >= 1 degrees of freedom."""
    if df < 1:
        raise ValueError("Student's t needs at least one degree of freedom")
    if not 0 < alpha < 0.5:
        raise ValueError("alpha must be within (0, 0.5)")
    target = 1 - 2 * alpha
    lo, hi = 0.0, math.pi / 2  # bisect on theta = atan(t / sqrt(df)); the CDF rises with it
    for _ in range(200):
        mid = (lo + hi) / 2
        if mid in (lo, hi):
            break
        if _t_central(math.sqrt(df) * math.tan(mid), df) < target:
            lo = mid
        else:
            hi = mid
    return math.sqrt(df) * math.tan(hi)


def clustered_wilson(
    clusters: Sequence[tuple[int, int]], alpha: float
) -> tuple[float, float] | None:
    """The (1 - 2*alpha) Wilson interval for a pooled yield whose trials come in clusters.

    ``clusters`` holds ``(successes, trials)`` per cluster; clusters with no trials do
    not count. None when there are no trials; ``(0, 1)`` with one cluster, which cannot
    bound anything. Otherwise, with ``k`` clusters, pooled yield ``R`` over ``N`` trials
    and residuals ``c - R n``, the linearised cluster-robust variance is
    ``V = k / (k - 1) * sum(residual^2) / N^2``. The effective sample size is
    ``R (1 - R) / V``, capped at ``N`` (and ``N`` when ``V = 0``), and the quantile is
    Student's t with ``k - 1`` degrees of freedom. The interval is never narrower than
    ``wilson`` on the pooled counts.
    """
    if any(not 0 <= c <= n for c, n in clusters):
        raise ValueError("successes must be within 0..trials")
    used = [(c, n) for c, n in clusters if n]
    total = sum(n for _, n in used)
    if total == 0:
        return None
    k = len(used)
    if k == 1:
        return 0.0, 1.0
    p = Fraction(sum(c for c, _ in used), total)
    variance = Fraction(k, k - 1) * sum((c - p * n) ** 2 for c, n in used) / total**2
    effective = Fraction(total)
    if variance:
        effective = min(effective, p * (1 - p) / variance)
    return _score(float(p), float(effective), t_upper(alpha, k - 1))
