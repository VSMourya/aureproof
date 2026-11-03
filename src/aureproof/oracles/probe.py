# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Difficulty probes: Bandit and single-shot model baselines on a fixture (issue #44).

Adapter (file, process and network I/O). A baseline is a separately accounted
system, never an agent repetition: it gets one episode per variant, scored by
the same labels and matcher as an agent (``score_episode``), and its metrics
keep their exact denominators. A probe *solves* a task when it credits every
labeled defect on the vulnerable variant and draws no focal refutation (M6) on
the repaired one. A task that both probes solve does not discriminate and must
be redesigned before benchmark expansion (specs/thr §6, plan-review C4).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol

from aureproof.bundle.canonical import digest_ref
from aureproof.contracts import EpisodeSignals, LabelSet, RunnerOutcome
from aureproof.contracts.thr import DifficultyProbe, ProbeResult, TaskHealthRecord
from aureproof.importers import bandit
from aureproof.oracles.calibration import Paths
from aureproof.oracles.python_spans import line_counts
from aureproof.scoring import compute_metrics, score_episode
from aureproof.scoring.episode import EpisodeScore

VARIANTS = ("vulnerable", "repaired")
ProbeKind = Literal["bandit", "single_shot_model"]

SINGLE_SHOT_PROMPT = """\
You are a careful security reviewer. You will receive a task description and the
complete source of a small codebase. You cannot run code or ask questions.
Answer with the JSON array the task asks for and nothing else.
"""


@dataclass(frozen=True)
class Episode:
    variant: str
    disposition: str
    verdicts: list[str]
    note: str | None = None


@dataclass(frozen=True)
class Baseline:
    """One probe's outcome on one task: two episodes and their metrics."""

    probe: ProbeKind
    system_identity: str
    episodes: list[Episode]
    metrics: dict[str, str]  # "numerator/denominator", exact
    solved: bool
    losses: list[str] = field(default_factory=list)

    def result(self) -> ProbeResult:
        per = "; ".join(f"{e.variant}: {e.disposition} {e.verdicts}" for e in self.episodes)
        recall = self.metrics["known_defect_recall"]
        return ProbeResult(
            probe=self.probe,
            system_identity=self.system_identity,
            solved=self.solved,
            detail=f"recall {recall}; {per}",
        )


def _labels(paths: Paths) -> LabelSet:
    return LabelSet.model_validate_json((paths.oracles / "labels.json").read_text("utf-8"))


def _baseline(
    probe: ProbeKind,
    identity: str,
    labels: LabelSet,
    paths: Paths,
    episode: Callable[[str], tuple[bytes | None, EpisodeSignals, str | None]],
    losses: list[str],
) -> Baseline:
    scores: dict[str, EpisodeScore] = {}
    episodes = []
    for variant in VARIANTS:
        data, signals, note = episode(variant)
        view = line_counts(paths.variant(variant))
        score = score_episode(data, signals, labels, variant=variant, agent_view=view)
        scores[variant] = score
        verdicts = [v.verdict.value for v in score.verdicts or ()]
        episodes.append(Episode(variant, score.disposition.value, verdicts, note))
    metrics = {
        name: f"{m.numerator}/{m.denominator}"
        for name, m in sorted(compute_metrics(list(scores.values())).items())
    }
    vulnerable, repaired = scores["vulnerable"], scores["repaired"]
    present = {d.defect_id for d in labels.defects if "vulnerable" in d.variants}
    focal_refuted = any(v.rule.value == "M6" for v in repaired.verdicts or ())
    solved = bool(present) and set(vulnerable.credited) == present and not focal_refuted
    return Baseline(probe, identity, episodes, metrics, solved, losses)


OK = EpisodeSignals(evidence_complete=True, runner_outcome=RunnerOutcome.OK)


def bandit_baseline(
    root: Path, task_id: str, *, runner: Callable[[Path], dict[str, Any]] = bandit.run
) -> Baseline:
    """Pinned Bandit on both variants, imported through SARIF, scored as usual."""
    paths = Paths(root, task_id)

    def episode(variant: str) -> tuple[bytes | None, EpisodeSignals, str | None]:
        imported = bandit.import_sarif(runner(paths.variant(variant)))
        note = f"{imported.without_cwe} result(s) without a CWE" if imported.without_cwe else None
        return json.dumps(imported.findings).encode(), OK, note

    losses = list(bandit.MAPPING_LOSSES)
    return _baseline("bandit", bandit.system_identity(), _labels(paths), paths, episode, losses)


# --- Single-shot model ------------------------------------------------------------


class ProbeError(RuntimeError):
    """The provider refused the call; the probe did not run."""


OPENAI_API = "openai-api"


def provider_model(model: str) -> str:
    """The provider's model ID, from `anthropic/<id>` (as `aureproof run` takes it) or `<id>`."""
    provider, sep, name = model.partition("/")
    if not sep:
        return model
    if provider != "anthropic" or not name:
        raise ValueError(
            "the single-shot probe calls Anthropic models, or an OpenAI-compatible endpoint "
            f"as openai-api/<service>/<model>, not {model!r}"
        )
    return name


def probe_config(model: str, env: Mapping[str, str]) -> SingleShotConfig:
    """The probe's configuration for `--model`.

    `openai-api/<service>/<model>` follows Inspect's convention: the endpoint is
    `<SERVICE>_BASE_URL` and the key `<SERVICE>_API_KEY`, with the service name
    upper-cased and `-` read as `_`. Anything else is an Anthropic model.
    """
    provider, _, rest = model.partition("/")
    if provider != OPENAI_API:
        return SingleShotConfig(model=provider_model(model))
    service, _, name = rest.partition("/")
    if not service or not name:
        raise ValueError(f"expected openai-api/<service>/<model>, not {model!r}")
    prefix = service.upper().replace("-", "_")
    base_url = env.get(f"{prefix}_BASE_URL", "").rstrip("/")
    if not base_url:
        raise ValueError(f"{model!r} needs {prefix}_BASE_URL, the endpoint's base URL")
    if not base_url.startswith("https://"):
        raise ValueError(f"{prefix}_BASE_URL must be an https URL, not {base_url!r}")
    if not env.get(f"{prefix}_API_KEY"):
        raise ValueError(f"{model!r} needs {prefix}_API_KEY")
    return SingleShotConfig(
        model=name,
        provider_protocol="openai-chat-completions",
        service=service,
        base_url=base_url,
    )


@dataclass(frozen=True)
class Reply:
    text: str
    stop_reason: str | None
    request_id: str | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None


class ModelClient(Protocol):
    def complete(self, *, system: str, user: str, max_tokens: int) -> Reply: ...


@dataclass(frozen=True)
class SingleShotConfig:
    model: str
    max_tokens: int = 8192
    provider_protocol: str = "anthropic-messages"
    sampling: str = "provider-default"  # no temperature is sent, on either protocol
    service: str | None = None  # an OpenAI-compatible endpoint, with its base URL
    base_url: str | None = None

    def identity(self) -> str:
        identity: dict[str, Any] = {
            "system": "single_shot_model",
            "provider_protocol": self.provider_protocol,
            "model": self.model,
            "max_tokens": self.max_tokens,
            "sampling": self.sampling,
            "prompt_sha256": hashlib.sha256(SINGLE_SHOT_PROMPT.encode("utf-8")).hexdigest(),
            "provider_retries": 0,
        }
        if self.service is not None:  # absent for Anthropic, so recorded identities hold
            identity |= {"service": self.service, "base_url": self.base_url}
        return digest_ref(identity)


def single_shot_input(paths: Paths, variant: str) -> str:
    """The task instruction and every source file, as one user message."""
    base = paths.variant(variant)
    parts = [(paths.security / "instruction.md").read_text("utf-8")]
    for path in sorted(base.rglob("*.py")):
        rel = path.relative_to(base).as_posix()
        parts.append(f"=== {rel} ===\n{path.read_text('utf-8')}")
    return "\n\n".join(parts)


def _answer(text: str) -> bytes:
    """The reply's JSON array. One surrounding Markdown code fence is removed."""
    body = text.strip()
    if body.startswith("```") and body.endswith("```"):
        body = body.split("\n", 1)[1] if "\n" in body else ""
        body = body.rsplit("```", 1)[0]
    return body.strip().encode("utf-8")


def single_shot_baseline(
    root: Path, task_id: str, config: SingleShotConfig, client: ModelClient
) -> Baseline:
    """One model call per variant, no tools and no retries; a refusal stays a refusal."""
    paths = Paths(root, task_id)

    def episode(variant: str) -> tuple[bytes | None, EpisodeSignals, str | None]:
        reply = client.complete(
            system=SINGLE_SHOT_PROMPT,
            user=single_shot_input(paths, variant),
            max_tokens=config.max_tokens,
        )
        note = (
            f"stop_reason={reply.stop_reason} request_id={reply.request_id} "
            f"tokens={reply.input_tokens}/{reply.output_tokens}"
        )
        if reply.stop_reason == "refusal":
            refused = EpisodeSignals(
                evidence_complete=True, runner_outcome=RunnerOutcome.OK, refusal_signal=True
            )
            return None, refused, note
        if reply.stop_reason == "max_tokens":
            limited = EpisodeSignals(
                evidence_complete=True, runner_outcome=RunnerOutcome.LIMIT_EXCEEDED
            )
            return _answer(reply.text), limited, note
        return _answer(reply.text), OK, note

    losses = ["one surrounding Markdown code fence is removed from the reply"]
    return _baseline("single_shot_model", config.identity(), _labels(paths), paths, episode, losses)


class AnthropicClient:
    """Anthropic Messages, with the SDK's own retries off (no hidden opportunities)."""

    def __init__(self, config: SingleShotConfig) -> None:
        import anthropic  # the `inspect` extra installs it

        self._config = config
        self._client = anthropic.Anthropic(max_retries=0)

    def complete(self, *, system: str, user: str, max_tokens: int) -> Reply:
        import anthropic

        try:
            message = self._client.messages.create(
                model=self._config.model,
                max_tokens=max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
        except anthropic.APIStatusError as error:
            raise ProbeError(f"provider error ({error.status_code}): {error.message}") from error
        except anthropic.APIError as error:
            raise ProbeError(f"provider error: {error.message}") from error
        text = "".join(getattr(block, "text", "") for block in message.content)
        return Reply(
            text=text,
            stop_reason=message.stop_reason,
            request_id=getattr(message, "_request_id", None),
            input_tokens=message.usage.input_tokens,
            output_tokens=message.usage.output_tokens,
        )


Post = Callable[[str, bytes, Mapping[str, str]], tuple[int, Mapping[str, str], bytes]]


def _https_post(
    url: str, body: bytes, headers: Mapping[str, str]
) -> tuple[int, Mapping[str, str], bytes]:
    """POST with the standard library; `probe_config` admits only https base URLs."""
    import urllib.error
    import urllib.request

    request = urllib.request.Request(url, data=body, headers=dict(headers), method="POST")
    try:
        with urllib.request.urlopen(request, timeout=600) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read()


class OpenAICompatibleClient:
    """One Chat Completions request per call, with no retries (no hidden opportunities)."""

    def __init__(
        self, config: SingleShotConfig, env: Mapping[str, str], post: Post = _https_post
    ) -> None:
        if config.service is None or config.base_url is None:
            raise ValueError("an OpenAI-compatible client needs probe_config's service")
        key = env[f"{config.service.upper().replace('-', '_')}_API_KEY"]
        self._config = config
        self._url = f"{config.base_url}/chat/completions"
        self._headers = {"Authorization": f"Bearer {key}", "Content-Type": "application/json"}
        self._post = post

    def complete(self, *, system: str, user: str, max_tokens: int) -> Reply:
        body = {
            "model": self._config.model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        try:
            status, headers, raw = self._post(self._url, json.dumps(body).encode(), self._headers)
        except OSError as error:  # URLError, timeouts, refused connections
            raise ProbeError(f"provider error: {error}") from error
        if status != 200:
            raise ProbeError(f"provider error ({status}): {_error_text(raw)}")
        data = json.loads(raw)
        choice = data["choices"][0]
        message = choice.get("message") or {}
        usage = data.get("usage") or {}
        lower = {k.lower(): v for k, v in headers.items()}
        return Reply(
            text=message.get("content") or "",
            stop_reason=_stop_reason(choice.get("finish_reason"), message),
            request_id=lower.get("x-request-id") or data.get("id"),
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
        )


def _stop_reason(finish_reason: str | None, message: Mapping[str, Any]) -> str | None:
    """Chat Completions finish reasons, in the Messages API's terms."""
    if message.get("refusal") or finish_reason == "content_filter":
        return "refusal"
    if finish_reason == "length":
        return "max_tokens"
    if finish_reason == "stop":
        return "end_turn"
    return finish_reason


def _error_text(raw: bytes) -> str:
    try:
        error = json.loads(raw).get("error")
    except (ValueError, AttributeError):
        return raw[:200].decode("utf-8", "replace")
    if isinstance(error, dict):
        return str(error.get("message", error))
    return str(error or raw[:200].decode("utf-8", "replace"))


# --- Recording ----------------------------------------------------------------------


def with_probe(
    record: TaskHealthRecord, bandit_run: Baseline | None, model_run: Baseline | None
) -> TaskHealthRecord:
    """The THR with its difficulty probe attached; health status is unaffected."""
    probe = DifficultyProbe(
        bandit=bandit_run.result() if bandit_run else None,
        single_shot_model=model_run.result() if model_run else None,
    )
    data = record.model_dump(mode="json")
    data["difficulty_probe"] = probe.model_dump(mode="json")
    return TaskHealthRecord.model_validate(data)


def saturation(bandit_run: Baseline | None, model_run: Baseline | None) -> str:
    """``saturated`` (both solve), ``partial`` (one solves), ``open`` or ``incomplete``."""
    runs = [r for r in (bandit_run, model_run) if r is not None]
    solved = sum(r.solved for r in runs)
    if len(runs) == 2 and solved == 2:
        return "saturated"
    if solved:
        return "partial"
    return "open" if len(runs) == 2 else "incomplete"
