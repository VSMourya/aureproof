# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Task, system, episode and attempt contracts (issue #10, plan v2 §3.7)."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from aureproof.contracts import AttemptRecord, EpisodeSpec, MetricRecord, SystemSpec, TaskSpec
from aureproof.contracts.specs import utc_instant

ROOT = Path(__file__).resolve().parents[2]
VECTORS = ROOT / "conformance" / "contracts" / "v0.1"
MODELS: dict[str, type[BaseModel]] = {
    "task-spec": TaskSpec,
    "system-spec": SystemSpec,
    "episode-spec": EpisodeSpec,
    "attempt-record": AttemptRecord,
    "metric-record": MetricRecord,
}
CASES = sorted(p for kind in MODELS for p in (VECTORS / kind).glob("*/*.json"))


def _instance(kind: str, name: str) -> dict[str, Any]:
    vector = json.loads((VECTORS / kind / "valid" / f"{name}.json").read_text(encoding="utf-8"))
    return dict(vector["instance"])


@pytest.mark.parametrize("path", CASES, ids=lambda p: f"{p.parts[-3]}/{p.parent.name}/{p.stem}")
def test_conformance_vector(path: Path) -> None:
    model = MODELS[path.parts[-3]]
    instance = json.loads(path.read_text(encoding="utf-8"))["instance"]
    if path.parent.name == "valid":
        model.model_validate(instance)
    else:
        with pytest.raises(ValidationError):
            model.model_validate(instance)


@pytest.mark.parametrize(
    "path", [p for p in CASES if p.parent.name == "valid"], ids=lambda p: f"{p.parts[-3]}/{p.stem}"
)
def test_valid_vectors_match_the_published_schema(path: Path) -> None:
    from jsonschema import Draft202012Validator

    schema = json.loads(
        (ROOT / "specs/contracts/v0.1" / f"{path.parts[-3]}.schema.json").read_text(
            encoding="utf-8"
        )
    )
    instance = json.loads(path.read_text(encoding="utf-8"))["instance"]
    assert not list(Draft202012Validator(schema).iter_errors(instance))


def test_every_kind_has_valid_and_invalid_vectors() -> None:
    for kind in MODELS:
        assert list((VECTORS / kind / "valid").glob("*.json")), kind
        assert list((VECTORS / kind / "invalid").glob("*.json")), kind


def _system() -> dict[str, Any]:
    return _instance("system-spec", "claude-code-closed-world")


@pytest.mark.parametrize(
    "change",
    [
        lambda s: s["subject"].update(version="2.1.288"),
        lambda s: s["models"]["main"].update(model="claude-sonnet-5-5"),
        lambda s: s["models"]["main"]["provider_identity"].update(model_snapshot="2026-10-01"),
        lambda s: s.update(hosted_tools="web-search"),
        lambda s: s["settings"].update(effort="high"),
        lambda s: s["prompts"].update(instruction="0" * 64),
        lambda s: s.update(tools=["Bash", "Read"]),
        lambda s: s["runner"].update(version="0.3.284"),
        lambda s: s["telemetry"].update(inspect_sharing="on"),
        lambda s: s.update(budget={"max_tokens": 200_000, "max_seconds": 900, "max_attempts": 1}),
    ],
)
def test_any_system_change_yields_a_new_identity(change: Any) -> None:
    before = SystemSpec.model_validate(_system()).identity
    changed = copy.deepcopy(_system())
    change(changed)
    assert SystemSpec.model_validate(changed).identity != before


def test_identity_is_reproducible_and_order_independent() -> None:
    raw = _system()
    reordered = dict(reversed(list(raw.items())))
    assert SystemSpec.model_validate(raw).identity == SystemSpec.model_validate(reordered).identity
    assert SystemSpec.model_validate(raw).identity.startswith("sha256:")


def test_explicit_unknown_provider_fields_are_part_of_identity() -> None:
    known = _system()
    known["models"]["main"]["provider_identity"]["region"] = "us-east-1"
    assert (
        SystemSpec.model_validate(known).identity != SystemSpec.model_validate(_system()).identity
    )


@pytest.mark.parametrize("field", ["task_revision", "dataset_revision"])
def test_task_and_dataset_revisions_yield_new_identities(field: str) -> None:
    task = _instance("task-spec", "authz-001")
    before = TaskSpec.model_validate(task).identity
    task[field] = task[field] + ".1"
    assert TaskSpec.model_validate(task).identity != before


def test_agent_view_content_is_part_of_task_identity() -> None:
    task = _instance("task-spec", "authz-001")
    before = TaskSpec.model_validate(task).identity
    task["agent_views"]["vulnerable"]["files"][0]["sha256"] = "f" * 64
    assert TaskSpec.model_validate(task).identity != before


def test_episode_ids_bind_every_input_before_dispatch() -> None:
    base = {
        "task": "sha256:" + "1" * 64,
        "variant": "vulnerable",
        "system": "sha256:" + "2" * 64,
        "protocol": "sha256:" + "3" * 64,
        "repetition": 0,
    }
    ids = {EpisodeSpec.plan(**base).episode_id}  # type: ignore[arg-type]
    for key, value in [
        ("task", "sha256:" + "4" * 64),
        ("variant", "repaired"),
        ("system", "sha256:" + "5" * 64),
        ("protocol", "sha256:" + "6" * 64),
        ("repetition", 1),
    ]:
        ids.add(EpisodeSpec.plan(**{**base, key: value}).episode_id)  # type: ignore[arg-type]
    assert len(ids) == 6  # every binding changes the ID
    assert EpisodeSpec.plan(**base).episode_id == EpisodeSpec.plan(**base).episode_id  # type: ignore[arg-type]


def test_attempt_ids_follow_their_episode() -> None:
    episode = EpisodeSpec.plan(
        task="sha256:" + "1" * 64,
        variant="vulnerable",
        system="sha256:" + "2" * 64,
        protocol="sha256:" + "3" * 64,
        repetition=2,
    )
    attempt = AttemptRecord(
        episode_id=episode.episode_id,
        attempt_index=0,
        attempt_id=f"{episode.episode_id}/a0",
        reason="initial",
        status="planned",
    )
    assert attempt.attempt_id.startswith(episode.episode_id)


def _attempt(started_at: str, ended_at: str) -> AttemptRecord:
    return AttemptRecord(
        episode_id="ep-1",
        attempt_index=0,
        attempt_id="ep-1/a0",
        reason="initial",
        status="completed",
        runner_run_id="run-1",
        started_at=started_at,
        ended_at=ended_at,
    )


def test_attempt_times_are_ordered_as_instants() -> None:
    _attempt("2026-10-29T12:00:00Z", "2026-10-29T12:00:00.5Z")  # half a second later
    _attempt("2026-10-29T12:00:00.1Z", "2026-10-29T12:00:00.15Z")
    _attempt("2026-10-29T12:00:00.5Z", "2026-10-29T12:00:00.500Z")  # the same instant
    with pytest.raises(ValidationError, match="precedes"):
        _attempt("2026-10-29T12:00:00.5Z", "2026-10-29T12:00:00Z")
    with pytest.raises(ValidationError, match="precedes"):
        _attempt("2026-10-29T12:00:00.15Z", "2026-10-29T12:00:00.1Z")


@pytest.mark.parametrize(
    ("earlier", "later"),
    [
        ("2026-10-29T12:00:00Z", "2026-10-29T12:00:00.5Z"),
        ("2026-10-29T12:00:00.1Z", "2026-10-29T12:00:00.15Z"),
        ("2026-10-29T23:59:59.999999999Z", "2026-10-30T00:00:00Z"),
        ("1999-12-31T23:59:59Z", "2026-01-01T00:00:00Z"),
    ],
)
def test_utc_instant_orders_like_time(earlier: str, later: str) -> None:
    assert utc_instant(earlier) < utc_instant(later)


def test_utc_instant_ignores_trailing_zeros_and_refuses_other_forms() -> None:
    assert utc_instant("2026-10-29T12:00:00.5Z") == utc_instant("2026-10-29T12:00:00.500000000Z")
    assert utc_instant("1970-01-01T00:00:01.000000001Z") == 1_000_000_001
    for bad in ("2026-10-29T12:00:00+00:00", "2026-10-29 12:00:00Z", "2026-02-30T00:00:00Z"):
        with pytest.raises(ValueError, match="RFC 3339"):
            utc_instant(bad)
