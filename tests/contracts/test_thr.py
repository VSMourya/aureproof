# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Task Health Record v0.1, label lint and health-based exclusion (issue #12)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from aureproof.contracts import EpisodeSignals, LabelSet, RunnerOutcome
from aureproof.contracts.labels_lint import lint_labels
from aureproof.contracts.thr import (
    REQUIRED_CONTROLS,
    ControlKind,
    HealthStatus,
    TaskHealthRecord,
    derive_status,
)
from aureproof.contracts.thr_schema import SCHEMA_DIR, export_schemas
from aureproof.oracles.python_spans import line_counts, python_spans
from aureproof.scoring import compute_metrics, score_episode
from aureproof.scoring.health import partition_by_health

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "conformance" / "thr" / "v0.1"
TASK = ROOT / "fixtures" / "security" / "authz-001" / "variants"
LABELS = LabelSet.model_validate_json(
    (ROOT / "fixtures/oracles/authz-001/labels.json").read_text(encoding="utf-8")
)


def _healthy() -> dict[str, Any]:
    return dict(json.loads((VECTORS / "valid/healthy.json").read_text("utf-8"))["instance"])


@pytest.mark.parametrize(
    "path", sorted(VECTORS.glob("*/*.json")), ids=lambda p: f"{p.parent.name}/{p.stem}"
)
def test_conformance_vector(path: Path) -> None:
    instance = json.loads(path.read_text(encoding="utf-8"))["instance"]
    if path.parent.name == "valid":
        TaskHealthRecord.model_validate(instance)
    else:
        with pytest.raises(ValidationError):
            TaskHealthRecord.model_validate(instance)


def test_vectors_cover_healthy_unhealthy_and_unknown() -> None:
    statuses = {
        json.loads(p.read_text("utf-8"))["instance"]["status"]
        for p in (VECTORS / "valid").glob("*.json")
    }
    assert statuses == {"healthy", "unhealthy", "unknown"}


def test_required_controls_include_nop_and_spray_cheat() -> None:
    assert {ControlKind.NOP, ControlKind.SPRAY_CHEAT, ControlKind.LABEL_LINT} <= REQUIRED_CONTROLS


def test_failure_outranks_missing_and_determinism_is_required() -> None:
    record = TaskHealthRecord.model_validate(_healthy())
    controls = [
        c.model_copy(update={"passed": None}) if c.kind == "nop" else c for c in record.controls
    ]
    assert derive_status(controls, record.determinism)[0] is HealthStatus.UNKNOWN
    controls[0] = controls[0].model_copy(update={"passed": False})
    assert derive_status(controls, record.determinism)[0] is HealthStatus.UNHEALTHY
    no_rerun = record.determinism.model_copy(update={"reproduced": None})
    assert derive_status(list(record.controls), no_rerun)[0] is HealthStatus.UNKNOWN


def test_committed_thr_schema_matches_the_model() -> None:
    on_disk = json.loads((ROOT / SCHEMA_DIR / "thr.schema.json").read_text("utf-8"))
    assert on_disk == export_schemas()["thr"]


# ---- Label lint L1-L4 against the real fixture ----------------------------------------


def _views() -> dict[str, dict[str, int]]:
    return {v: line_counts(TASK / v) for v in ("vulnerable", "repaired")}


def _spans() -> dict[str, Any]:
    return {v: python_spans(TASK / v) for v in ("vulnerable", "repaired")}


def test_authz_001_labels_are_lint_clean_against_the_code() -> None:
    assert lint_labels(LABELS, _views(), _spans()) == []


def test_label_drift_is_rejected() -> None:
    raw = LABELS.model_dump(mode="json", by_alias=True)
    start, end = raw["defects"][0]["anchors"][0]["line_range"]
    raw["defects"][0]["anchors"][0]["line_range"] = [start + 1, end + 1]
    problems = lint_labels(LabelSet.model_validate(raw), _views(), _spans())
    assert any(p.startswith("L3") and "drifted" in p for p in problems)


@pytest.mark.parametrize(
    ("mutate", "rule"),
    [
        (lambda r: r["reviewed_negative_scope"].append({"file": "docstore/service.py"}), "L2"),
        (lambda r: r["defects"][0]["anchors"][0].update(file="docstore/missing.py"), "L3"),
        (
            lambda r: r["reviewed_negative_scope"].append(
                {"file": "docstore/service.py", "symbol": "Other.delete_document"}
            ),
            "L1",
        ),
    ],
)
def test_lint_rules(mutate: Any, rule: str) -> None:
    raw = copy.deepcopy(LABELS.model_dump(mode="json", by_alias=True))
    mutate(raw)
    assert any(p.startswith(rule) for p in lint_labels(LabelSet.model_validate(raw), _views()))


# ---- Exclusion: unhealthy tasks never become agent false positives ---------------------

OK = EpisodeSignals(evidence_complete=True, runner_outcome=RunnerOutcome.OK)
FREEZE = "2026-11-01T00:00:00Z"


def _episode(findings: list[Any]) -> Any:
    view = _views()["vulnerable"]
    return score_episode(
        json.dumps(findings).encode(), OK, LABELS, variant="vulnerable", agent_view=view
    )


def _record(task: str, status: str, frozen_at: str | None) -> TaskHealthRecord:
    raw = _healthy()
    raw["task"]["task_identity"] = task
    raw["frozen_at"] = frozen_at
    if status == "unhealthy":
        for c in raw["controls"]:
            if c["kind"] == "spray_cheat":
                c["passed"] = False
        raw["status"], raw["status_reason"] = "unhealthy", "failed controls: spray_cheat"
    return TaskHealthRecord.model_validate(raw)


def test_unhealthy_pre_registered_task_never_counts_against_the_agent() -> None:
    false_alarm = [
        {
            "cwe": 862,
            "locations": [{"file": "docstore/service.py", "symbol": "purge_all"}],
            "description": "d",
        }
    ]
    healthy_task, broken_task = "sha256:" + "1" * 64, "sha256:" + "2" * 64
    episodes = {healthy_task: [_episode([])], broken_task: [_episode(false_alarm)]}
    records = [
        _record(healthy_task, "healthy", "2026-10-30T00:00:00Z"),
        _record(broken_task, "unhealthy", "2026-10-30T00:00:00Z"),
    ]
    part = partition_by_health(episodes, records, protocol_frozen_at=FREEZE)
    assert broken_task in part.excluded and broken_task not in part.graded
    metrics = compute_metrics([e for eps in part.graded.values() for e in eps])
    assert metrics["scoped_false_alarm_rate"].numerator == 0  # the refuted finding is gone


def test_post_freeze_health_findings_are_exploratory_only() -> None:
    task = "sha256:" + "3" * 64
    part = partition_by_health(
        {task: [_episode([])]},
        [_record(task, "unhealthy", "2026-11-02T00:00:00Z")],
        protocol_frozen_at=FREEZE,
    )
    assert task in part.graded and task in part.exploratory and not part.excluded


@pytest.mark.parametrize(
    ("frozen_at", "protocol_frozen_at", "pre_registered"),
    [
        # Half a second after the freeze: '.' sorts before 'Z', so string order says before.
        ("2026-10-31T00:00:00.5Z", "2026-10-31T00:00:00Z", False),
        ("2026-10-31T00:00:00.15Z", "2026-10-31T00:00:00.1Z", False),
        ("2026-10-31T00:00:00Z", "2026-10-31T00:00:00.5Z", True),
        ("2026-10-31T00:00:00.1Z", "2026-10-31T00:00:00.15Z", True),
        # The same instant written with different precision is not after the freeze.
        ("2026-10-31T00:00:00.500Z", "2026-10-31T00:00:00.5Z", True),
        ("2026-10-31T00:00:00.5Z", "2026-10-31T00:00:00.500000000Z", True),
    ],
)
def test_pre_registration_compares_instants_not_strings(
    frozen_at: str, protocol_frozen_at: str, pre_registered: bool
) -> None:
    task = "sha256:" + "4" * 64
    part = partition_by_health(
        {task: [_episode([])]},
        [_record(task, "unhealthy", frozen_at)],
        protocol_frozen_at=protocol_frozen_at,
    )
    assert (task in part.excluded) is pre_registered
    assert (task in part.exploratory) is not pre_registered


def test_a_malformed_protocol_freeze_time_is_refused() -> None:
    task = "sha256:" + "4" * 64
    with pytest.raises(ValueError, match="RFC 3339"):
        partition_by_health(
            {task: [_episode([])]},
            [_record(task, "unhealthy", "2026-10-30T00:00:00Z")],
            protocol_frozen_at="2026-10-31 00:00:00",
        )
