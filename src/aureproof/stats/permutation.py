# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Exact paired sign-flip permutation test with a test-inversion interval.

All arithmetic is exact. For cluster differences ``d`` and a hypothesized effect
``delta0``, flipping the signs of a subset ``S`` gives a sum at least as large as
the observed one exactly when ``mean(d over S) <= delta0``. So the one-sided
p-value is ``(1 + #{non-empty S : mean_S(d) <= delta0}) / 2^k``, and the interval
bounds are order statistics of the ``2^k - 1`` subset means (specs/decision §4).

The enumeration runs in integers: the differences are scaled by the least common
denominator ``L``, so every subset sum is an integer, and a subset mean ``s / m``
is ordered by the integer key ``s * (M // m)`` with ``M = lcm(1..k)``. The keys are
the means times ``L * M``, so sorting them sorts the means, and the bound is turned
back into an exact ``Fraction``.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from dataclasses import dataclass
from fractions import Fraction

from aureproof.contracts.decision import MAX_CLUSTERS

__all__ = ["MAX_CLUSTERS", "SignFlipResult", "min_clusters", "p_two_sided", "sign_flip"]


@dataclass(frozen=True, slots=True)
class SignFlipResult:
    k: int
    mean: Fraction
    p_two_sided: Fraction  # at delta0 = 0
    lower: Fraction | None  # None: unbounded at this alpha (too few clusters)
    upper: Fraction | None


def min_clusters(alpha: float) -> int:
    """Smallest k with floor(alpha * 2^k) >= 1, i.e. any finite bound exists."""
    k = 1
    while math.floor(alpha * 2**k) < 1:
        k += 1
    return k


def _scaled(d: Sequence[Fraction]) -> tuple[list[int], int]:
    """The differences as integers over their least common denominator ``L``."""
    exact = [Fraction(x) for x in d]
    scale = math.lcm(*(x.denominator for x in exact))
    return [x.numerator * (scale // x.denominator) for x in exact], scale


def _subset_sums(ints: Sequence[int]) -> tuple[list[int], list[int]]:
    """Sum and size of every subset; index ``mask`` holds the subset of its set bits."""
    sums, sizes = [0], [0]
    for x in ints:
        sums += [s + x for s in sums]
        sizes += [m + 1 for m in sizes]
    return sums, sizes


def _hits(sums: Sequence[int]) -> int:
    """Masks whose flipped total ``T - 2s`` is at least ``|T|`` in absolute value.

    ``|T - 2s| >= |T|`` is ``(T - 2s)^2 >= T^2``, i.e. ``s * (s - T) >= 0``.
    """
    total = sums[-1]
    return sum(1 for s in sums if s * (s - total) >= 0)


def p_two_sided(d: Sequence[Fraction]) -> Fraction:
    """P(|sum of sign-flipped d| >= |sum d|) over all 2^k sign assignments."""
    sums, _ = _subset_sums(_scaled(d)[0])
    return Fraction(_hits(sums), len(sums))


def sign_flip(d: Sequence[Fraction], alpha: float) -> SignFlipResult:
    """Exact test and the (1 - 2*alpha) interval for the mean of cluster differences."""
    k = len(d)
    if not 1 <= k <= MAX_CLUSTERS:
        raise ValueError(f"need 1..{MAX_CLUSTERS} clusters, got {k}")
    ints, scale = _scaled(d)
    sums, sizes = _subset_sums(ints)
    mean = Fraction(sums[-1], scale * k)
    p = Fraction(_hits(sums), len(sums))
    r = math.floor(alpha * 2**k)  # rejected iff #{subset means <= delta0} <= r - 1
    if r < 1:
        return SignFlipResult(k, mean, p, None, None)
    common = math.lcm(*range(1, k + 1))
    per_size = [0] + [common // m for m in range(1, k + 1)]
    keys = [s * per_size[m] for s, m in zip(sums, sizes, strict=True)]
    del keys[0]  # the empty subset has no mean
    keys.sort()
    unit = scale * common
    return SignFlipResult(
        k, mean, p, Fraction(keys[r - 1], unit), Fraction(keys[len(keys) - r], unit)
    )
