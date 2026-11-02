# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Statistics (pure core): exact sign-flip test, cluster-counted Wilson intervals, the gate."""

from aureproof.stats.decide import decide
from aureproof.stats.permutation import MAX_CLUSTERS, SignFlipResult, min_clusters, sign_flip
from aureproof.stats.wilson import clustered_wilson, t_upper, wilson

__all__ = [
    "MAX_CLUSTERS",
    "SignFlipResult",
    "clustered_wilson",
    "decide",
    "min_clusters",
    "sign_flip",
    "t_upper",
    "wilson",
]
