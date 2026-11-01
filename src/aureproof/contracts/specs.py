# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Task, system, episode and attempt contracts (plan v2 §3.7, issue #10).

Identities are **content-derived**: the digest of a record's canonical JSON.
Changing anything that defines a task or a system therefore yields a new
identity, and episode and attempt IDs are bound to their inputs before
dispatch, so they cannot drift afterwards.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal, Self

from pydantic import AfterValidator, Field, JsonValue, model_validator

from aureproof.contracts._base import (
    Contract,
    NonEmptyStr,
    NonNegativeInt,
    PositiveInt,
    Sha256Hex,
    Variant,
)
from aureproof.contracts.canonical import digest_ref

DigestRef = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
UtcTimestamp = Annotated[
    str, Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,9})?Z$")
]  # RFC 3339 UTC. The fraction is optional and of any length, so string order is NOT
# time order ("...00.5Z" sorts before "...00Z"): order and compare with ``utc_instant``.
_UTC_PARTS = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z")
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_ONE_SECOND = timedelta(seconds=1)


def utc_instant(timestamp: str) -> int:
    """Nanoseconds since the Unix epoch of a ``UtcTimestamp``, for ordering.

    Equal instants written with different precision ("...00.5Z", "...00.500Z")
    are equal; anything that is not a real RFC 3339 UTC instant is refused.
    """
    parsed = _UTC_PARTS.fullmatch(timestamp)
    try:
        if parsed is None:
            raise ValueError
        moment = datetime.strptime(parsed[1], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=UTC)
    except ValueError:
        raise ValueError(f"not an RFC 3339 UTC timestamp: {timestamp!r}") from None
    whole_seconds = (moment - _EPOCH) // _ONE_SECOND
    return whole_seconds * 1_000_000_000 + int((parsed[2] or "").ljust(9, "0"))


_REL_PATH = r"^(?!/)(?!.*\\)(?!(.*/)?\.{1,2}(/|$)).+$"


def _relative(path: str) -> str:
    if (
        path.startswith("/")
        or "\\" in path
        or any(seg in ("", ".", "..") for seg in path.split("/"))
    ):
        raise ValueError("must be a relative POSIX path without '.', '..' or empty segments")
    return path


RelPath = Annotated[
    str, Field(min_length=1, json_schema_extra={"pattern": _REL_PATH}), AfterValidator(_relative)
]


def content_identity(record: Contract, *, exclude: set[str] | None = None) -> str:
    """``sha256:<hex>`` of the record's canonical JSON (aliases, ``None`` kept)."""
    return digest_ref(record.model_dump(mode="json", by_alias=True, exclude=exclude))


class Budget(Contract):
    """Per-episode limits (ADR-0007 defaults: 400k tokens, 15 minutes, 1 attempt)."""

    max_tokens: PositiveInt = 400_000
    max_seconds: PositiveInt = 900
    max_attempts: Literal[1] = 1  # only Aureproof re-dispatches, after infra failure (ADR-0003)


class FileDigest(Contract):
    path: RelPath
    sha256: Sha256Hex


class AgentView(Contract):
    """What the agent sees for one variant: a fixture directory, by content."""

    root: RelPath
    instruction: FileDigest
    files: Annotated[list[FileDigest], Field(min_length=1)]

    @model_validator(mode="after")
    def _sorted_unique(self) -> Self:
        paths = [f.path for f in self.files]
        if paths != sorted(set(paths)):
            raise ValueError("agent view files must be sorted by path and unique")
        return self


class TaskSpec(Contract):
    task_id: NonEmptyStr
    task_revision: NonEmptyStr
    dataset_id: NonEmptyStr
    dataset_revision: NonEmptyStr
    family: Literal["security-discovery"]
    cluster_id: NonEmptyStr
    canary_id: NonEmptyStr
    agent_views: dict[Variant, AgentView]
    labels: FileDigest  # evaluator-only; never inside an agent view
    budget: Budget = Budget()

    @model_validator(mode="after")
    def _separate_build_contexts(self) -> Self:
        if set(self.agent_views) != {"vulnerable", "repaired"}:
            raise ValueError("a findings task has exactly a vulnerable and a repaired view")
        for variant, view in self.agent_views.items():
            root = view.root.rstrip("/") + "/"
            if self.labels.path.startswith(root):
                raise ValueError(f"labels are inside the {variant} agent view (build contexts)")
        return self

    @property
    def identity(self) -> str:
        return content_identity(self)


class ProviderIdentity(Contract):
    """Identity fields a hosted provider may or may not return. Every field is
    required; ``None`` records 'not returned' explicitly instead of omitting it."""

    model_snapshot: str | None
    api_version: str | None
    endpoint: str | None
    region: str | None


class ModelBinding(Contract):
    provider: NonEmptyStr
    model: NonEmptyStr
    protocol: Literal["anthropic-messages", "openai-responses", "openai-chat", "inspect"]
    provider_identity: ProviderIdentity


class Runner(Contract):
    name: Literal["inspect", "harbor", "docker"]
    version: NonEmptyStr
    adapter_revision: NonEmptyStr


class Subject(Contract):
    kind: Literal["external", "reference", "baseline"]
    name: NonEmptyStr
    version: NonEmptyStr
    scaffold: NonEmptyStr


class SystemSpec(Contract):
    """Everything that can change an agent's behavior. Any change → new identity."""

    subject: Subject
    interface_mode: Literal["native-capability", "controlled-interface"]
    hosted_tools: Literal["closed-world", "web-search"]
    models: Annotated[dict[NonEmptyStr, ModelBinding], Field(min_length=1)]
    prompts: dict[NonEmptyStr, Sha256Hex]  # prompt name -> digest of its text
    tools: list[NonEmptyStr]  # offered tools, sorted
    memory: NonEmptyStr  # e.g. "none"
    settings: dict[NonEmptyStr, JsonValue]  # e.g. disallowed_tools, retry_refusals
    runner: Runner
    telemetry: dict[NonEmptyStr, NonEmptyStr]  # e.g. {"inspect_log_shared": "off"}
    budget: Budget = Budget()

    @model_validator(mode="after")
    def _invariants(self) -> Self:
        if self.tools != sorted(set(self.tools)):
            raise ValueError("tools must be sorted and unique")
        if self.subject.kind == "external" and self.interface_mode != "native-capability":
            raise ValueError("an external subject runs in native-capability mode (ADR-0007)")
        if self.subject.kind == "reference" and self.interface_mode != "controlled-interface":
            raise ValueError("the reference subject runs in controlled-interface mode (ADR-0007)")
        # Never retry to bypass a provider safeguard (plan §7.4): a refusal is recorded
        # as safety_refusal, not retried away.
        if self.settings.get("retry_refusals") not in (None, 0):
            raise ValueError("retry_refusals must be 0: refusals are never retried (plan §7.4)")
        if self.subject.scaffold.startswith("inspect_swe."):
            # inspect_swe defaults retry refusals and crashes 3 times and enable web search.
            for key in ("retry_refusals", "retry_uncaught_errors"):
                if self.settings.get(key) != 0:
                    raise ValueError(f"inspect_swe subjects must set {key}=0 explicitly (ADR-0007)")
            disallowed = self.settings.get("disallowed_tools")
            withheld = set(disallowed) if isinstance(disallowed, list) else set()
            if self.hosted_tools == "closed-world" and not {"WebSearch", "WebFetch"} <= withheld:
                raise ValueError(
                    "closed-world inspect_swe subjects must disallow WebSearch and WebFetch"
                )
        return self

    @property
    def identity(self) -> str:
        return content_identity(self)


class EpisodeSpec(Contract):
    """The stable scheduled unit: task x variant x system x protocol x repetition."""

    task: DigestRef
    variant: Variant
    system: DigestRef
    protocol: DigestRef
    repetition: NonNegativeInt
    episode_id: NonEmptyStr

    @staticmethod
    def derive_id(task: str, variant: str, system: str, protocol: str, repetition: int) -> str:
        key = {
            "task": task,
            "variant": variant,
            "system": system,
            "protocol": protocol,
            "repetition": repetition,
        }
        return "ep-" + digest_ref(key).removeprefix("sha256:")[:32]

    @classmethod
    def plan(
        cls, *, task: str, variant: Variant, system: str, protocol: str, repetition: int
    ) -> EpisodeSpec:
        return cls(
            task=task,
            variant=variant,
            system=system,
            protocol=protocol,
            repetition=repetition,
            episode_id=cls.derive_id(task, variant, system, protocol, repetition),
        )

    @model_validator(mode="after")
    def _bound(self) -> Self:
        expected = self.derive_id(
            self.task, self.variant, self.system, self.protocol, self.repetition
        )
        if self.episode_id != expected:
            raise ValueError("episode_id is not bound to its task, system, protocol and repetition")
        return self


class AttemptRecord(Contract):
    """One runner dispatch, owned by Aureproof (ADR-0003). Never merged silently."""

    episode_id: NonEmptyStr
    attempt_index: NonNegativeInt
    attempt_id: NonEmptyStr
    reason: Literal["initial", "infra_retry"]
    status: Literal["planned", "dispatched", "completed", "failed", "incomplete"]
    runner_run_id: NonEmptyStr | None = None
    started_at: UtcTimestamp | None = None  # injected by the controller (pure core: no clock)
    ended_at: UtcTimestamp | None = None
    error_class: NonEmptyStr | None = None

    @model_validator(mode="after")
    def _bound(self) -> Self:
        if self.attempt_id != f"{self.episode_id}/a{self.attempt_index}":
            raise ValueError("attempt_id must be <episode_id>/a<attempt_index>")
        if (self.attempt_index == 0) != (self.reason == "initial"):
            raise ValueError("attempt 0 is the initial attempt; later attempts are infra retries")
        if self.status == "planned" and (self.runner_run_id or self.started_at):
            raise ValueError("a planned attempt has not been dispatched")
        if self.status == "failed" and self.error_class is None:
            raise ValueError("a failed attempt records its error_class")
        if (
            self.started_at
            and self.ended_at
            and utc_instant(self.ended_at) < utc_instant(self.started_at)
        ):
            raise ValueError("ended_at precedes started_at")
        return self
