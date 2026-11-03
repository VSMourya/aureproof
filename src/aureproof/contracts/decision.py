# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Decision Protocol v0.1 and the Decision record (specs/decision/README.md, issue #14).

A protocol is pre-registered: its identity is the digest of its content, and
(from M2) its Sigstore signature must predate the first assessment episode.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, Self

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from aureproof.contracts._base import Contract, NonEmptyStr, PositiveInt
from aureproof.contracts.specs import Budget, DigestRef, content_identity

DECISION_VERSION = "0.1"
# The exact gate enumerates all 2^k sign assignments of k cluster differences
# (specs/decision §4), so a cohort may name at most this many clusters.
MAX_CLUSTERS = 20


class Estimand(Contract):
    metric: Literal["strict_confirmed_yield"] = "strict_confirmed_yield"  # ADR-0006
    contrast: Literal["B-A"] = "B-A"
    summary: Literal["mean_of_cluster_differences"] = "mean_of_cluster_differences"
    # How a cluster with no submitted findings (undefined yield) enters a difference.
    undefined_yield: Literal["zero", "exclude_cluster"] = "zero"


class CohortTask(Contract):
    task_identity: DigestRef
    thr_digest: DigestRef  # the frozen Task Health Record this protocol relies on
    cluster_id: NonEmptyStr


class Configurations(Contract):
    A: DigestRef  # SystemSpec identity (baseline)
    B: DigestRef  # SystemSpec identity (candidate)

    @model_validator(mode="after")
    def _distinct(self) -> Self:
        if self.A == self.B:
            raise ValueError("A and B must be different system identities")
        return self


class FailurePolicy(Contract):
    """How non-completed episodes enter (scoring.md §5.3; fixed in v0.1)."""

    infra_failure: Literal["rerun_new_attempt_then_report"] = "rerun_new_attempt_then_report"
    evidence_incomplete: Literal["blocks_sealing"] = "blocks_sealing"
    safety_refusal: Literal["report_separately_not_a_miss"] = "report_separately_not_a_miss"
    budget_exhausted: Literal["graded"] = "graded"
    agent_error: Literal["graded"] = "graded"
    invalid_output: Literal["graded"] = "graded"


class TestSpec(Contract):
    method: Literal["exact_sign_flip"] = "exact_sign_flip"
    ci: Literal["test_inversion"] = "test_inversion"
    alpha: Annotated[float, Field(gt=0, lt=0.5)] = 0.025  # per side: 95% two-sided CI


class Guardrail(Contract):
    """A secondary metric that B must not lose by more than its own margin (§5, rule 6).

    Strict confirmed yield is a precision, so volume cannot raise it, but restraint can:
    reporting only the surest finding, or nothing where A did well (ADR-0006). Known-defect
    recall moves the other way, so requiring both closes both games.
    """

    metric: Literal["known_defect_recall"]
    margin: Annotated[float, Field(ge=0)]


class Stopping(Contract):
    fixed_repetitions: Literal[True] = True
    peeking: Literal[False] = False
    exploratory_analyses: list[NonEmptyStr] = Field(default_factory=list)


class DecisionProtocol(Contract):
    protocol_version: Literal["0.1"]
    name: NonEmptyStr
    estimand: Estimand = Estimand()
    cohort: Annotated[list[CohortTask], Field(min_length=1)]
    configurations: Configurations
    repetitions: PositiveInt
    budget: Budget = Budget()
    failure_policy: FailurePolicy = FailurePolicy()
    test: TestSpec = TestSpec()
    margin: Annotated[float, Field(ge=0)]  # B passes if CI lower bound > -margin
    stopping: Stopping = Stopping()
    require_complete_adjudication: Literal[True] = True
    pilot_mde: Annotated[float, Field(ge=0)] | None = None
    guardrails: list[Guardrail] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_tasks(self) -> Self:
        ids = [t.task_identity for t in self.cohort]
        if len(ids) != len(set(ids)):
            raise ValueError("cohort tasks must be unique")
        metrics = [g.metric for g in self.guardrails]
        if len(metrics) != len(set(metrics)):
            raise ValueError("a guardrail metric appears once")
        return self

    @model_serializer(mode="wrap")
    def _omit_no_guardrails(self, handler: SerializerFunctionWrapHandler) -> dict[str, Any]:
        """No guardrails serialize as no key, so earlier protocols keep their identity."""
        data: dict[str, Any] = handler(self)
        if not self.guardrails:
            data.pop("guardrails", None)
        return data

    @model_validator(mode="after")
    def _evaluable(self) -> Self:
        """Refused when written, not discovered when the gate runs after the assessment."""
        clusters = len({t.cluster_id for t in self.cohort})
        if clusters > MAX_CLUSTERS:
            raise ValueError(
                f"the exact gate decides at most {MAX_CLUSTERS} clusters; "
                f"this cohort names {clusters}"
            )
        return self

    @model_validator(mode="after")
    def _evaluable(self) -> Self:
        """Refused when written, not discovered when the gate runs after the assessment."""
        clusters = len({t.cluster_id for t in self.cohort})
        if clusters > MAX_CLUSTERS:
            raise ValueError(
                f"the exact gate decides at most {MAX_CLUSTERS} clusters; "
                f"this cohort names {clusters}"
            )
        return self

    @property
    def identity(self) -> str:
        return content_identity(self)


class ClusterRow(Contract):
    cluster_id: NonEmptyStr
    a_confirmed: Annotated[int, Field(ge=0)]
    a_submitted: Annotated[int, Field(ge=0)]
    b_confirmed: Annotated[int, Field(ge=0)]
    b_submitted: Annotated[int, Field(ge=0)]
    a_unresolved: Annotated[int, Field(ge=0)] = 0
    b_unresolved: Annotated[int, Field(ge=0)] = 0
    difference: NonEmptyStr | None  # exact rational "p/q"; None when excluded
    # Known-defect recall support, for a guardrail: defects credited / defects present.
    a_credited: Annotated[int, Field(ge=0)] = 0
    a_positives: Annotated[int, Field(ge=0)] = 0
    b_credited: Annotated[int, Field(ge=0)] = 0
    b_positives: Annotated[int, Field(ge=0)] = 0

    @model_validator(mode="after")
    def _credited_within_positives(self) -> Self:
        if self.a_credited > self.a_positives or self.b_credited > self.b_positives:
            raise ValueError("credited defects cannot exceed the defects present")
        return self


class Interval(Contract):
    lower: float | None  # None: unbounded (too few clusters)
    upper: float | None


class GuardrailResult(Contract):
    metric: Literal["known_defect_recall"]
    margin: float
    outcome: Literal["pass", "fail", "inconclusive"]
    reason: NonEmptyStr
    clusters: int
    mean_difference: NonEmptyStr | None  # exact rational
    ci: Interval


class Decision(Contract):
    decision_version: Literal["0.1"] = "0.1"
    protocol: DigestRef
    outcome: Literal["pass", "fail", "inconclusive"]
    provisional_outcome: Literal["pass", "fail", "inconclusive"]
    reason: NonEmptyStr
    clusters: int
    mean_difference: NonEmptyStr | None  # exact rational
    p_value_two_sided: NonEmptyStr | None  # exact rational at delta0 = 0
    ci: Interval
    min_clusters_for_decision: int
    wilson_a: Interval
    wilson_b: Interval
    cluster_table: list[ClusterRow]
    guardrails: list[GuardrailResult] = Field(default_factory=list)
