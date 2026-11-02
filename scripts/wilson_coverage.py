# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Coverage of the per-configuration yield interval in a clustered cohort (specs/decision §4).

    uv run python scripts/wilson_coverage.py            # 4000 replicates per row, seeded
    uv run python scripts/wilson_coverage.py --replicates 1000

A cluster is one task pair: 3 repetitions x 2 variants = 6 episodes. An episode
submits 1 + Poisson(lam) findings, lam depending on the task. On the vulnerable
variant the findings share one episode-level success probability (an episode either
understood the defect or did not), drawn around the task's difficulty; on the
repaired variant every finding is a false alarm. The target is
E[confirmed] / E[submitted], the quantity the pooled yield estimates. Two designs:
tasks drawn afresh each replicate (clusters as sampled units), and one fixed suite
where only the episodes vary. Pure standard library; deterministic for a seed.
"""

from __future__ import annotations

import argparse
import math
import random

from aureproof.stats import clustered_wilson, wilson

ALPHA = 0.025
REPETITIONS = 3
VARIANTS = ("vulnerable", "repaired")
Params = tuple[float, float]  # (difficulty q, talkativeness lam)


def _poisson(rng: random.Random, lam: float) -> int:
    limit, k, p = math.exp(-lam), 0, 1.0
    while True:
        p *= rng.random()
        if p <= limit:
            return k
        k += 1


def _task(rng: random.Random) -> Params:
    return rng.betavariate(1.2, 1.8), rng.choice((0.5, 1.0, 2.0, 4.0))


# Over tasks drawn as above: q and lam are independent and E[q] = 1.2 / 3, so the
# (1 + lam) factors cancel in E[confirmed] / E[submitted].
POPULATION = (4 * 1.2 / 3 + 0.05) / 4.1 / len(VARIANTS)


def _cluster(rng: random.Random, task: Params) -> tuple[int, int]:
    q, lam = task
    confirmed = submitted = 0
    for variant in VARIANTS:
        for _ in range(REPETITIONS):
            m = 1 + _poisson(rng, lam)
            p = 0.0 if variant == "repaired" else rng.betavariate(4 * q + 0.05, 4 * (1 - q) + 0.05)
            confirmed += sum(rng.random() < p for _ in range(m))
            submitted += m
    return confirmed, submitted


def _target(tasks: list[Params]) -> float:
    """E[confirmed] / E[submitted] for these task parameters."""
    expected_c = sum(REPETITIONS * (1 + lam) * (4 * q + 0.05) / 4.1 for q, lam in tasks)
    expected_n = sum(len(VARIANTS) * REPETITIONS * (1 + lam) for _, lam in tasks)
    return expected_c / expected_n


def _row(k: int, replicates: int, fixed: bool, population: float, seed: int) -> str:
    rng = random.Random(seed)
    tasks = [_task(rng) for _ in range(k)]
    hits = {"naive": 0, "clustered": 0}
    width = {"naive": 0.0, "clustered": 0.0}
    for _ in range(replicates):
        if not fixed:
            tasks = [_task(rng) for _ in range(k)]
        rows = [_cluster(rng, t) for t in tasks]
        target = _target(tasks) if fixed else population
        naive = wilson(sum(c for c, _ in rows), sum(n for _, n in rows), ALPHA)
        for name, interval in (("naive", naive), ("clustered", clustered_wilson(rows, ALPHA))):
            assert interval is not None
            hits[name] += interval[0] <= target <= interval[1]
            width[name] += interval[1] - interval[0]
    design = "fixed suite, episodes vary  " if fixed else "tasks drawn each replicate  "
    cells = "".join(
        f"{hits[n] / replicates:12.3f}{width[n] / replicates:9.3f}" for n in ("naive", "clustered")
    )
    return f"{design}{k:4d}{cells}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--replicates", type=int, default=4000)
    parser.add_argument("--seed", type=int, default=20261101)
    args = parser.parse_args()
    print(f"nominal {1 - 2 * ALPHA:.0%}; population target {POPULATION:.4f}")
    print(f"{'design':28}{'k':>4}{'naive':>12}{'width':>9}{'clustered':>12}{'width':>9}")
    for fixed in (False, True):
        for k in (6, 10, 14):
            print(_row(k, args.replicates, fixed, POPULATION, args.seed + 1000 * k + fixed))


if __name__ == "__main__":
    main()
