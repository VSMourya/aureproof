# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Scoring-time exclusion by task health (specs/thr §5).

Only health records frozen **before** the protocol freeze decide exclusion.
Episodes of an excluded task leave the cohort before metrics, so an unhealthy
task is reported as a dataset-health status and never as an agent false
positive. Records frozen afterwards are flagged as exploratory, not applied.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from aureproof.contracts.specs import utc_instant
from aureproof.contracts.thr import HealthStatus, TaskHealthRecord
from aureproof.scoring.episode import EpisodeScore


@dataclass(frozen=True, slots=True)
class Partition:
    graded: dict[str, list[EpisodeScore]]  # task identity -> episodes that stay in the cohort
    excluded: dict[str, str]  # task identity -> reason (pre-registered)
    exploratory: dict[str, str]  # task identity -> post-freeze health finding (not applied)


def partition_by_health(
    episodes: Mapping[str, Sequence[EpisodeScore]],
    records: Sequence[TaskHealthRecord],
    *,
    protocol_frozen_at: str,
) -> Partition:
    """Split episodes by their task's frozen health (UTC RFC 3339 timestamps).

    Times are compared as instants, never as strings: a record frozen half a
    second after the protocol is not pre-registered.
    """
    freeze = utc_instant(protocol_frozen_at)  # refuses a malformed freeze time
    by_task = {r.task.task_identity: r for r in records}
    graded: dict[str, list[EpisodeScore]] = {}
    excluded: dict[str, str] = {}
    exploratory: dict[str, str] = {}
    for task, task_episodes in episodes.items():
        record = by_task.get(task)
        pre_registered = (
            record is not None
            and record.frozen_at is not None
            and utc_instant(record.frozen_at) <= freeze
        )
        if record is None or not pre_registered:
            if record is not None and record.status is not HealthStatus.HEALTHY:
                exploratory[task] = f"{record.status.value} after the protocol freeze"
            elif record is None:
                exploratory[task] = "no frozen task-health record"
            graded[task] = list(task_episodes)
            continue
        if record.status is HealthStatus.HEALTHY:
            graded[task] = list(task_episodes)
        else:
            excluded[task] = f"{record.status.value}: {record.status_reason}"
    return Partition(graded, excluded, exploratory)
