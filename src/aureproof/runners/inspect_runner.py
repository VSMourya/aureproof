# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Inspect AI runner adapter (issue #39; ADR-0002, ADR-0003, ADR-0007).

Requires the ``inspect`` extra; Inspect is imported lazily so the core never
depends on it. One call runs **one** attempt as a one-sample Inspect eval:

- the sandbox is Docker with ``network_mode: none`` and only the variant's
  files; labels never enter it;
- ``retry_on_error=0`` and ``fail_on_error=False`` (Aureproof owns retries);
  Claude Code runs with retry_refusals=0, retry_uncaught_errors=0 and
  attempts=1, so there are no agent-side retries or hidden continuations;
- after the agent, ``collect_findings`` reads ``findings.json`` once as raw
  bytes and stores them (base64) with their SHA-256 in the logged sample store,
  so a saved log can be re-scored without a sandbox;
- facts come from the sample (error, limit, store, model events), never from
  the log header;
- tool calls are journaled by digest (issue #43): ToolEvents the harness
  executed for the reference subject are ``controller_observed``; Claude Code
  runs its own tools, so its tool calls are ``agent_reported``.

Proxy readiness: Inspect's ``sandbox_agent_bridge`` yields before its in-sandbox
proxy accepts connections (inspect-ai 0.3.283, ``agent/_bridge/sandbox/bridge.py``).
A connection failure before any model call is classified ``infra:proxy_not_ready``
and re-dispatched as a recorded attempt, never retried silently.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.metadata as md
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from pydantic_core import to_json

from aureproof import __version__
from aureproof.contracts import Budget, SystemSpec
from aureproof.runners.collect import ARTIFACT, COLLECT_LIMIT, COLLECTOR, interpret
from aureproof.runners.port import (
    AttemptRequest,
    AttemptResult,
    SampleFacts,
    ToolCall,
    ToolSource,
    classify,
)
from aureproof.runners.reference import REFERENCE_PROMPT, reference_prompt_digest

CAPTURE_KEY = "aureproof_capture"
FINDINGS_FILE = "findings.json"
COMPOSE = Path(__file__).with_name("compose.yaml")
REFERENCE_TOOLS = ("bash", "submit")
# Offered by inspect_swe's claude_code 2.1.287 with a real model but not to the scripted
# model of the Docker lane: the in-session task list. Found by the first live slice (#47).
CLAUDE_CODE_LIVE_ONLY_TOOLS = ("TaskCreate", "TaskGet", "TaskList", "TaskUpdate")
# Offered by inspect_swe's claude_code 2.1.287 with WebSearch/WebFetch disallowed (Day-2
# spike, scripted model), plus the live-only tools above.
CLAUDE_CODE_TOOLS = (
    "Agent",
    "Bash",
    "CronCreate",
    "CronDelete",
    "CronList",
    "Edit",
    "EnterWorktree",
    "ExitWorktree",
    "ListAgents",
    "NotebookEdit",
    "Read",
    "ReportFindings",
    "ScheduleWakeup",
    "SendMessage",
    "Skill",
    "TaskStop",
    "Workflow",
    "Write",
    *CLAUDE_CODE_LIVE_ONLY_TOOLS,
)
# The Linux sandbox binaries of each pinned Claude Code version, from
# https://downloads.claude.ai/claude-code-releases/<version>/manifest.json (the manifest
# inspect_swe checks a download against). 2.1.287: build 3c446a1b, 2026-10-01.
CLAUDE_CODE_CHECKSUMS: dict[str, dict[str, str]] = {
    "2.1.287": {
        "linux-arm64": "e4daf793d1e74fb0d9874dd09e98690bbfd7be515f78a87fd05b9e2b4bb33b03",
        "linux-x64": "3920489a5109cff5786a1a392c25277408ff22bc796d5edb9c16a60e5a1718f0",
        "linux-arm64-musl": "83d95a9fa28b1fadd8c012fda873aed8f8998e23dfabe6dd4efd05bcdd7383ba",
        "linux-x64-musl": "ba22ce4b5744c6016e3076ccbd692a059fc4e9f1592f21361859a73938f4e722",
    },
}
CLAUDE_CODE_SETTINGS: dict[str, Any] = {
    "disallowed_tools": ["WebSearch", "WebFetch"],
    "retry_refusals": 0,
    "retry_uncaught_errors": 0,
    "attempts": 1,
}
REFERENCE_SETTINGS: dict[str, Any] = {"retry_refusals": 0, "attempts": 1, "bash_timeout_s": 60}
RUNNER_SETTINGS: dict[str, Any] = {"inspect_retry_on_error": 0, "inspect_fail_on_error": False}


@dataclass
class InspectRunnerConfig:
    subject: Literal["reference", "claude_code"]
    model: Any  # model name, or an Inspect Model (e.g. mockllm in tests)
    log_dir: Path
    model_name: str = "mockllm/model"  # the identity recorded in SystemSpec
    claude_code_version: str = "2.1.287"
    hosted_tools: Literal["closed-world", "web-search"] = "closed-world"
    compose: Path = COMPOSE
    budget: Budget = field(default_factory=Budget)
    binary_cache: Path | None = None  # None: inspect_swe's own download cache


class UnsupportedCapability(ValueError):
    """A requested capability the qualified bridge cannot provide (issue #42)."""


# Claude Code speaks Anthropic Messages; mockllm is the no-cost test double.
CLAUDE_CODE_PROVIDERS = ("anthropic", "mockllm")


def preflight(cfg: InspectRunnerConfig) -> list[str]:
    """The transformations a run applies; raises for any capability not qualified.

    Runs when the runner is built, before any attempt is dispatched, so a
    configuration fault is never mistaken for an infrastructure failure.
    """
    if isinstance(cfg.model, str) and cfg.model != cfg.model_name:
        raise UnsupportedCapability(
            f"model {cfg.model!r} differs from the recorded identity {cfg.model_name!r}"
        )
    provider = cfg.model_name.split("/", 1)[0]
    if cfg.subject == "reference":
        if cfg.hosted_tools != "closed-world":
            raise UnsupportedCapability("the reference subject offers no hosted tools")
        if provider != OPENAI_API:
            return []
        return [
            f"model requests go to the OpenAI-compatible endpoint {openai_api_endpoint(cfg)}"
            " through Inspect's openai-api provider (Chat Completions)"
        ]
    if cfg.hosted_tools != "closed-world":
        raise UnsupportedCapability(
            "web-search is not implemented: the bridge's web_search is never enabled, and"
            " hosted search needs live qualification (#7, #42)"
        )
    if cfg.claude_code_version not in CLAUDE_CODE_CHECKSUMS:
        raise UnsupportedCapability(
            f"Claude Code {cfg.claude_code_version} has no pinned checksums: pin its"
            " manifest checksums in CLAUDE_CODE_CHECKSUMS first"
        )
    if provider not in CLAUDE_CODE_PROVIDERS:
        raise UnsupportedCapability(
            f"Claude Code needs an Anthropic Messages provider, not {provider!r}: an"
            " unqualified protocol translation"
        )
    return [
        "Claude Code's Anthropic Messages requests are served by Inspect's"
        " sandbox_agent_bridge in the sandbox and forwarded to the Inspect model API",
        f"WebSearch and WebFetch are disallowed in Claude Code ({cfg.hosted_tools})",
    ]


def verify_cached_binaries(
    cache: Path, version: str, pins: Mapping[str, Mapping[str, str]] = CLAUDE_CODE_CHECKSUMS
) -> list[str]:
    """Problems with the cached binaries of ``version``; empty when each matches its pin.

    inspect_swe checks a fresh download against the release manifest; this also
    catches a cached binary that changed afterwards.
    """
    problems = []
    for path in sorted(cache.glob(f"claude-{version}-*")):
        platform = path.name.removeprefix(f"claude-{version}-")
        expected = pins.get(version, {}).get(platform)
        if expected is None:
            problems.append(f"{path.name}: no pinned checksum for this platform")
            continue
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1 << 20), b""):
                digest.update(chunk)
        if digest.hexdigest() != expected:
            problems.append(f"{path.name}: sha256 differs from the pinned checksum")
    return problems


def _binary_cache(cfg: InspectRunnerConfig) -> Path | None:
    if cfg.binary_cache is not None:
        return cfg.binary_cache
    try:
        from inspect_swe._util.appdirs import package_cache_dir
    except ModuleNotFoundError:  # without the extra no binary can run at all
        return None
    return Path(package_cache_dir("claude-code-downloads"))


OPENAI_API = "openai-api"


def openai_api_endpoint(cfg: InspectRunnerConfig) -> str:
    """The base URL of `openai-api/<service>/<model>`, as Inspect reads it.

    Inspect takes the endpoint from `<SERVICE>_BASE_URL` and the key from
    `<SERVICE>_API_KEY`. Both are checked here, before any dispatch; the key never
    enters the sandbox, since the reference subject's model calls are the controller's.
    """
    _, _, rest = cfg.model_name.partition("/")
    service, _, model = rest.partition("/")
    if not service or not model:
        raise UnsupportedCapability(
            f"expected openai-api/<service>/<model>, not {cfg.model_name!r}"
        )
    prefix = service.upper().replace("-", "_")
    base_url = os.environ.get(f"{prefix}_BASE_URL", "").rstrip("/")
    if not base_url:
        raise UnsupportedCapability(f"{cfg.model_name!r} needs {prefix}_BASE_URL")
    if not base_url.startswith("https://"):
        raise UnsupportedCapability(f"{prefix}_BASE_URL must be an https URL, not {base_url!r}")
    if not os.environ.get(f"{prefix}_API_KEY"):
        raise UnsupportedCapability(f"{cfg.model_name!r} needs {prefix}_API_KEY")
    return base_url


def _protocol(cfg: InspectRunnerConfig) -> str:
    return "anthropic-messages" if cfg.subject == "claude_code" else "inspect"


def declared_tools(cfg: InspectRunnerConfig) -> list[str]:
    return sorted(CLAUDE_CODE_TOOLS if cfg.subject == "claude_code" else REFERENCE_TOOLS)


def system_spec(cfg: InspectRunnerConfig) -> SystemSpec:
    """The system identity: subject, pins, protocol, tools and effective settings."""
    transformations = preflight(cfg)  # an unqualified system gets no identity
    inspect_version = md.version("inspect-ai")
    if cfg.subject == "claude_code":
        subject = {
            "kind": "external",
            "name": "claude_code",
            "version": cfg.claude_code_version,
            "scaffold": f"inspect_swe.claude_code@{md.version('inspect-swe')}",
        }
        mode, prompts = "native-capability", {}
        settings = {
            **CLAUDE_CODE_SETTINGS,
            **RUNNER_SETTINGS,
            "binary_sha256": dict(CLAUDE_CODE_CHECKSUMS[cfg.claude_code_version]),
        }
    else:
        subject = {
            "kind": "reference",
            "name": "inspect_react",
            "version": inspect_version,
            "scaffold": "inspect_ai.agent.react",
        }
        mode, settings = "controlled-interface", {**REFERENCE_SETTINGS, **RUNNER_SETTINGS}
        prompts = {"system": reference_prompt_digest()}
    settings["transformations"] = transformations
    provider = cfg.model_name.split("/", 1)[0]
    return SystemSpec.model_validate(
        {
            "subject": subject,
            "interface_mode": mode,
            "hosted_tools": cfg.hosted_tools,
            "models": {
                "main": {
                    "provider": provider,
                    "model": cfg.model_name,
                    "protocol": _protocol(cfg),
                    "provider_identity": {
                        "model_snapshot": None,
                        "api_version": None,
                        "endpoint": openai_api_endpoint(cfg) if provider == OPENAI_API else None,
                        "region": None,
                    },
                }
            },
            "prompts": prompts,
            "tools": declared_tools(cfg),
            "memory": "none",
            "settings": settings,
            "runner": {
                "name": "inspect",
                "version": inspect_version,
                "adapter_revision": f"aureproof-{__version__}",
            },
            "telemetry": {"inspect_log_sharing": "off"},
            "budget": cfg.budget.model_dump(),
        }
    )


def _collect_findings() -> Any:
    from inspect_ai.solver import Generate, TaskState, solver
    from inspect_ai.util import sandbox, store

    @solver  # type: ignore[untyped-decorator, unused-ignore]
    def collect_findings() -> Any:
        async def solve(state: TaskState, generate: Generate) -> TaskState:
            # Bounded, symlink-free collection inside the sandbox (issue #40).
            result = await sandbox().exec(
                ["python3", "-c", COLLECTOR, ".", ARTIFACT, str(COLLECT_LIMIT)], timeout=60
            )
            if not result.success:
                store().set(
                    CAPTURE_KEY,
                    {"status": "rejected", "reason": f"collector_failed: {result.stderr[-200:]}"},
                )
                return state
            capture = interpret(result.stdout)
            record: dict[str, Any] = {"status": capture.status, "reason": capture.reason}
            if capture.data is not None:
                record["sha256"] = capture.sha256
                record["b64"] = base64.b64encode(capture.data).decode("ascii")
            store().set(CAPTURE_KEY, record)
            return state

        return solve

    return collect_findings()


def _subject(cfg: InspectRunnerConfig) -> Any:
    from inspect_ai.agent import as_solver, react
    from inspect_ai.tool import bash

    if cfg.subject == "reference":
        return as_solver(
            react(
                prompt=REFERENCE_PROMPT,
                tools=[bash(timeout=REFERENCE_SETTINGS["bash_timeout_s"])],
                attempts=REFERENCE_SETTINGS["attempts"],
                retry_refusals=REFERENCE_SETTINGS["retry_refusals"],
            )
        )
    from inspect_swe import claude_code

    configured = system_spec(cfg).settings["disallowed_tools"]
    disallowed = [str(t) for t in configured] if isinstance(configured, list) else []
    return as_solver(
        claude_code(
            version=cfg.claude_code_version,
            cwd="/work",
            disallowed_tools=disallowed,
            retry_refusals=0,
            retry_uncaught_errors=0,
            attempts=1,
        )
    )


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _args_sha(arguments: Any) -> str:
    return _sha(json.dumps(arguments, sort_keys=True, separators=(",", ":"), default=str).encode())


def tool_calls(sample: Any, subject: str) -> tuple[list[ToolCall], ToolSource]:
    """Tool calls by digest, with the trust tier of whoever observed them."""
    if subject == "reference":
        observed = []
        for e in sample.events:
            if getattr(e, "event", None) != "tool":
                continue
            result = e.result if isinstance(e.result, str) else to_json(e.result).decode()
            observed.append(
                ToolCall(
                    tool=e.function,
                    input_sha256=_args_sha(e.arguments),
                    output_sha256=_sha(result.encode()),
                    error=e.error.type if e.error is not None else None,
                )
            )
        return observed, "controller_observed"
    reported = [
        ToolCall(tool=call.function, input_sha256=_args_sha(call.arguments), output_sha256=None)
        for e in sample.events
        if getattr(e, "event", None) == "model" and e.output is not None and e.output.choices
        for call in (e.output.choices[0].message.tool_calls or [])
    ]
    return reported, "agent_reported"


def facts_from_sample(
    sample: Any, log_path: Path, run_id: str | None, subject: str = "reference"
) -> SampleFacts:
    """Per-sample facts from an Inspect log sample (never the log header)."""
    model_events = [e for e in sample.events if getattr(e, "event", None) == "model"]
    tools = {t.name for e in model_events for t in (e.tools or [])}
    stops = [e.output.stop_reason for e in model_events if e.output is not None]
    request_ids = [
        rid if isinstance(rid, str) else str(rid.id)  # Inspect 0.3.283: ModelRequestId
        for e in model_events
        for rid in (getattr(e, "request_ids", None) or [])
    ]
    capture = (sample.store or {}).get(CAPTURE_KEY)
    submission: bytes | None = None
    status: Literal["captured", "absent", "rejected", "missing"] = "missing"
    detail = None
    if capture is not None:
        status, detail = capture["status"], capture.get("reason")
        if status == "captured":
            submission = base64.b64decode(capture["b64"])
            if hashlib.sha256(submission).hexdigest() != capture["sha256"]:
                status, submission = "missing", None  # corrupt capture: not evidence
    calls, source = tool_calls(sample, subject)
    error = None
    if sample.error is not None:
        error = f"{sample.error.message}\n{sample.error.traceback[-2000:]}"
    return SampleFacts(
        error=error,
        limit_type=sample.limit.type if sample.limit is not None else None,
        capture_status=status,
        capture_detail=detail,
        submission=submission,
        stop_reasons=stops,
        model_requests=len(model_events),
        provider_retries=sum(int(getattr(e, "retries", 0) or 0) for e in model_events),
        request_ids=request_ids,
        offered_tools=frozenset(tools),
        hidden_retries=len(sample.error_retries or []),
        log_path=log_path,
        log_digest="sha256:" + hashlib.sha256(log_path.read_bytes()).hexdigest(),
        runner_run_id=run_id,
        tool_calls=calls,
        tool_source=source,
    )


class InspectRunner:
    def __init__(self, config: InspectRunnerConfig) -> None:
        preflight(config)  # unsupported capabilities fail here, before any dispatch
        cache = _binary_cache(config) if config.subject == "claude_code" else None
        if cache is not None:
            problems = verify_cached_binaries(cache, config.claude_code_version)
            if problems:
                raise UnsupportedCapability("; ".join(problems))
        self.config = config

    def system_spec(self) -> SystemSpec:
        return system_spec(self.config)

    def run_attempt(self, request: AttemptRequest) -> AttemptResult:
        from inspect_ai import Task
        from inspect_ai import eval as inspect_eval
        from inspect_ai.dataset import Sample
        from inspect_ai.log import read_eval_log

        cfg = self.config
        view = request.task.agent_views[request.variant]  # type: ignore[index]
        base = request.root / view.root
        sample = Sample(
            id=request.attempt_id,
            input=(request.root / view.instruction.path).read_text(encoding="utf-8"),
            files={f.path: str(base / f.path) for f in view.files},
            metadata={"episode_id": request.episode.episode_id, "variant": request.variant},
        )
        task = Task(
            dataset=[sample],
            solver=[_subject(cfg), _collect_findings()],
            sandbox=("docker", str(cfg.compose)),
            token_limit=cfg.budget.max_tokens,
            time_limit=cfg.budget.max_seconds,
        )
        [log] = inspect_eval(
            task,
            model=cfg.model,
            log_dir=str(cfg.log_dir),
            display="none",
            retry_on_error=0,
            fail_on_error=False,
        )
        if log.location is None or not log.samples:
            path = Path(str(log.location)) if log.location else None
            facts = SampleFacts(error="inspect produced no sample", log_path=path, log_digest=None)
            return classify(facts, declared_tools=declared_tools(cfg))
        path = Path(str(log.location))
        saved = read_eval_log(str(path))
        sample_log = (saved.samples or log.samples)[0]
        facts = facts_from_sample(sample_log, path, log.eval.run_id, cfg.subject)
        return classify(facts, declared_tools=declared_tools(cfg))
