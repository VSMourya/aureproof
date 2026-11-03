# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Difficulty probes: Bandit SARIF import and the two baselines (issue #44)."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from aureproof.bundle.canonical import digest_ref
from aureproof.cli.main import app
from aureproof.contracts.findings import Finding
from aureproof.contracts.sarif import findings_from_sarif, findings_to_sarif
from aureproof.contracts.thr import TaskHealthRecord
from aureproof.importers import bandit
from aureproof.oracles import probe
from aureproof.oracles.calibration import Paths, calibrate
from aureproof.oracles.probe import (
    SINGLE_SHOT_PROMPT,
    OpenAICompatibleClient,
    ProbeError,
    Reply,
    SingleShotConfig,
    bandit_baseline,
    probe_config,
    provider_model,
    saturation,
    single_shot_baseline,
    single_shot_input,
    with_probe,
)

ROOT = Path(__file__).resolve().parents[2]
runner = CliRunner()


def bandit_log(results: list[dict[str, Any]], version: str = bandit.BANDIT_VERSION) -> dict:
    """The shape Bandit 1.9.4 writes with ``-f sarif``: CWE only in rule tags."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Bandit",
                        "version": version,
                        "rules": [
                            {
                                "id": "B602",
                                "properties": {"tags": ["security", "external/cwe/cwe-78"]},
                            },
                            {"id": "B999", "properties": {"tags": ["security"]}},
                        ],
                    }
                },
                "results": results,
            }
        ],
    }


def result(rule: str, index: int, uri: str, line: int) -> dict[str, Any]:
    return {
        "ruleId": rule,
        "ruleIndex": index,
        "message": {"text": f"{rule} issue"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line, "endLine": line},
                }
            }
        ],
        "properties": {"issue_confidence": "HIGH", "issue_severity": "HIGH"},
    }


# --- Bandit import -----------------------------------------------------------------


def test_bandit_sarif_imports_with_cwe_from_rule_tags_and_counts_losses() -> None:
    log = bandit_log([result("B602", 0, "pkg/mod.py", 6), result("B999", 1, "pkg/mod.py", 9)])
    imported = bandit.import_sarif(log)
    assert imported.without_cwe == 1
    first = imported.findings[0]
    assert first["cwe"] == 78
    assert first["locations"] == [
        {"file": "pkg/mod.py", "start_line": 6, "end_line": 6, "role": "site"}
    ]
    assert first["issue_severity"] == "HIGH"  # kept as an extra field, never scored


def test_bandit_findings_round_trip_through_the_finding_schema() -> None:
    imported = bandit.import_sarif(bandit_log([result("B602", 0, "pkg/mod.py", 6)]))
    findings = [Finding.model_validate(f) for f in imported.findings]
    again = findings_from_sarif(findings_to_sarif(findings, tool_name="x", tool_version="1"))
    assert [Finding.model_validate(f) for f in again] == findings


@pytest.mark.parametrize(
    ("log", "message"),
    [
        (bandit_log([], version="1.8.0"), "not the pinned"),
        ({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "Semgrep"}}}]}, "not a Bandit"),
    ],
)
def test_bandit_import_refuses_other_tools_and_unpinned_versions(log: dict, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        bandit.import_sarif(log)


def test_the_bandit_identity_names_tool_version_and_arguments() -> None:
    assert bandit.system_identity().startswith("sha256:")
    assert bandit.system_identity() == bandit.system_identity()


def test_pinned_bandit_does_not_solve_any_calibrated_pair() -> None:
    """The real run: no pair is solved by the static baseline (difficulty probe)."""
    for task in (
        "authz-001",
        "path-001",
        "authz-002",
        "ssrf-001",
        "redirect-001",
        "massassign-001",
    ):
        run = bandit_baseline(ROOT, task)
        assert run.solved is False, task
        assert run.metrics["known_defect_recall"] == "0/1"
        assert [e.variant for e in run.episodes] == ["vulnerable", "repaired"]


def test_a_bandit_hit_on_the_defect_alone_solves_the_task() -> None:
    def fake(variant_dir: Path) -> dict[str, Any]:
        hits = [result("B602", 0, "reportvault/service.py", 31)]
        return bandit_log(hits if variant_dir.name == "vulnerable" else [])

    run = bandit_baseline(ROOT, "path-001", runner=fake)
    assert run.metrics["known_defect_recall"] == "0/1"  # CWE-78 is not an accepted class
    assert run.solved is False

    def fake_22(variant_dir: Path) -> dict[str, Any]:
        log = fake(variant_dir)
        log["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"] = ["external/cwe/cwe-22"]
        return log

    run = bandit_baseline(ROOT, "path-001", runner=fake_22)
    assert run.solved is True and run.metrics["known_defect_recall"] == "1/1"
    assert run.metrics["strict_confirmed_yield"] == "1/1"


def test_flagging_both_variants_does_not_solve_the_task() -> None:
    def everywhere(variant_dir: Path) -> dict[str, Any]:
        log = bandit_log([result("B602", 0, "reportvault/service.py", 31)])
        log["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"] = ["external/cwe/cwe-22"]
        return log

    run = bandit_baseline(ROOT, "path-001", runner=everywhere)
    assert run.solved is False  # the repaired focal finding is refuted (M6)
    assert run.episodes[1].verdicts == ["refuted"]


# --- Single-shot model ---------------------------------------------------------------


class FakeClient:
    def __init__(self, reply: Reply | dict[str, Reply]) -> None:
        self.reply = reply
        self.calls: list[dict[str, Any]] = []

    def complete(self, *, system: str, user: str, max_tokens: int) -> Reply:
        self.calls.append({"system": system, "user": user, "max_tokens": max_tokens})
        if isinstance(self.reply, Reply):
            return self.reply
        variant = "vulnerable" if "if not is_plain_name(raw_name)" in user else "repaired"
        return self.reply[variant]


CORRECT = json.dumps(
    [
        {
            "cwe": 22,
            "locations": [{"file": "reportvault/service.py", "symbol": "download_attachment"}],
            "description": "decoded after the check",
        }
    ]
)
CONFIG = SingleShotConfig(model="test-model")


def test_single_shot_scores_like_an_agent_and_solves_with_the_right_answer() -> None:
    client = FakeClient(
        {
            "vulnerable": Reply(f"```json\n{CORRECT}\n```", "end_turn", "req-1", 10, 5),
            "repaired": Reply("[]", "end_turn", "req-2", 10, 1),
        }
    )
    run = single_shot_baseline(ROOT, "path-001", CONFIG, client)
    assert run.solved is True
    assert run.metrics["known_defect_recall"] == "1/1"
    assert [e.disposition for e in run.episodes] == [
        "completed_with_findings",
        "completed_no_findings",
    ]
    assert "request_id=req-1" in (run.episodes[0].note or "")
    assert len(client.calls) == 2  # one call per variant, nothing retried
    assert all(c["system"] == SINGLE_SHOT_PROMPT and c["max_tokens"] == 8192 for c in client.calls)


def test_a_refusal_stays_a_refusal_and_a_cutoff_is_budget_exhausted() -> None:
    refused = single_shot_baseline(ROOT, "path-001", CONFIG, FakeClient(Reply("", "refusal")))
    assert [e.disposition for e in refused.episodes] == ["safety_refusal", "safety_refusal"]
    assert refused.solved is False
    cut = single_shot_baseline(ROOT, "path-001", CONFIG, FakeClient(Reply("[{", "max_tokens")))
    assert {e.disposition for e in cut.episodes} == {"budget_exhausted"}


def test_the_model_input_holds_the_agent_view_only() -> None:
    paths = Paths(ROOT, "authz-002")
    text = single_shot_input(paths, "vulnerable")
    assert "=== invoicer/service.py ===" in text and "# Task: security review" in text
    labels = json.loads((paths.oracles / "labels.json").read_text())
    assert labels["oracle_canary"] not in text and "authz-002-d1" not in text


def test_the_single_shot_identity_covers_model_budget_and_prompt() -> None:
    assert CONFIG.identity() != SingleShotConfig(model="other").identity()
    assert CONFIG.identity() != SingleShotConfig(model="test-model", max_tokens=1).identity()


# --- Recording and saturation ----------------------------------------------------------


def test_the_probe_is_recorded_in_the_thr_without_changing_health() -> None:
    record = calibrate(ROOT, "path-001")
    static = bandit_baseline(ROOT, "path-001")
    probed = with_probe(record, static, None)
    assert probed.status is record.status
    assert probed.difficulty_probe is not None and probed.difficulty_probe.single_shot_model is None
    assert probed.difficulty_probe.bandit is not None
    assert probed.difficulty_probe.bandit.system_identity == bandit.system_identity()
    assert probed.task.task_identity == record.task.task_identity


def test_saturation_states() -> None:
    no = bandit_baseline(ROOT, "path-001")
    yes = single_shot_baseline(
        ROOT,
        "path-001",
        CONFIG,
        FakeClient({"vulnerable": Reply(CORRECT, "end_turn"), "repaired": Reply("[]", "end_turn")}),
    )
    assert saturation(no, None) == "incomplete"
    assert saturation(no, no) == "open"
    assert saturation(no, yes) == "partial"
    assert saturation(yes, yes) == "saturated"


def test_task_probe_cli_records_the_bandit_probe(tmp_path: Path) -> None:
    out = tmp_path / "thr.json"
    result = runner.invoke(
        app, ["task", "probe", "path-001", "--root", str(ROOT), "--out", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert "path-001: INCOMPLETE" in result.output
    assert "not run (pass --model" in result.output
    record = TaskHealthRecord.model_validate_json(out.read_text())
    assert record.difficulty_probe is not None and record.difficulty_probe.bandit is not None
    assert record.difficulty_probe.bandit.solved is False

    result = runner.invoke(app, ["task", "probe", "path-001", "--root", str(ROOT), "--json"])
    data = json.loads(result.output)
    assert data["saturation"] == "incomplete"
    assert data["baselines"][0]["mapping_losses"] == list(bandit.MAPPING_LOSSES)


def test_task_probe_cli_refuses_unknown_tasks_and_existing_outputs(tmp_path: Path) -> None:
    assert runner.invoke(app, ["task", "probe", "nope-001", "--root", str(ROOT)]).exit_code == 2
    existing = tmp_path / "thr.json"
    existing.write_text("{}")
    args = ["task", "probe", "path-001", "--root", str(ROOT), "--out", str(existing)]
    assert runner.invoke(app, args).exit_code == 2


def test_the_probe_takes_the_model_with_or_without_its_provider() -> None:
    assert provider_model("anthropic/claude-haiku-4-5-20251001") == "claude-haiku-4-5-20251001"
    assert provider_model("claude-haiku-4-5-20251001") == "claude-haiku-4-5-20251001"
    with pytest.raises(ValueError, match="openai-api/<service>/<model>"):
        provider_model("openai/gpt-5")


# --- OpenAI-compatible endpoints (Inspect's openai-api/<service>/<model>) ---------------

ENV = {"AKASHML_API_KEY": "k-test", "AKASHML_BASE_URL": "https://api.example.test/v1/"}


def test_an_openai_compatible_model_reads_its_endpoint_from_the_environment() -> None:
    config = probe_config("openai-api/akashml/openai/gpt-oss-120b", ENV)
    assert config.model == "openai/gpt-oss-120b"
    assert config.service == "akashml"
    assert config.base_url == "https://api.example.test/v1"
    assert config.provider_protocol == "openai-chat-completions"
    assert probe_config("anthropic/claude-haiku-4-5", {}).service is None


@pytest.mark.parametrize(
    ("model", "env", "message"),
    [
        ("openai-api/akashml", ENV, "openai-api/<service>/<model>"),
        ("openai-api/akashml/m", {"AKASHML_API_KEY": "k"}, "AKASHML_BASE_URL"),
        ("openai-api/akashml/m", {"AKASHML_BASE_URL": "https://x/v1"}, "AKASHML_API_KEY"),
        ("openai-api/my-svc/m", {"MY_SVC_API_KEY": "k"}, "MY_SVC_BASE_URL"),
        ("openai-api/akashml/m", {**ENV, "AKASHML_BASE_URL": "http://x/v1"}, "https"),
    ],
)
def test_an_openai_compatible_model_without_its_endpoint_is_refused(
    model: str, env: dict[str, str], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        probe_config(model, env)


def test_the_endpoint_is_part_of_the_identity_and_anthropic_identities_do_not_move() -> None:
    other = {**ENV, "AKASHML_BASE_URL": "https://elsewhere.test/v1"}
    a = probe_config("openai-api/akashml/m", ENV)
    assert a.identity() != probe_config("openai-api/akashml/m", other).identity()
    assert a.identity() != SingleShotConfig(model="m").identity()
    # the recorded identity of an Anthropic probe, before endpoints existed
    assert SingleShotConfig(model="claude-haiku-4-5-20251001").identity() == digest_ref(
        {
            "system": "single_shot_model",
            "provider_protocol": "anthropic-messages",
            "model": "claude-haiku-4-5-20251001",
            "max_tokens": 8192,
            "sampling": "provider-default",
            "prompt_sha256": hashlib.sha256(SINGLE_SHOT_PROMPT.encode()).hexdigest(),
            "provider_retries": 0,
        }
    )


Sent = tuple[str, dict[str, Any], dict[str, str]]


def openai_client(status: int, body: dict[str, Any]) -> tuple[OpenAICompatibleClient, list[Sent]]:
    seen: list[Sent] = []

    def post(url: str, data: bytes, headers: Any) -> tuple[int, dict[str, str], bytes]:
        seen.append((url, json.loads(data), dict(headers)))
        return status, {"X-Request-Id": "req-9"}, json.dumps(body).encode()

    config = probe_config("openai-api/akashml/openai/gpt-oss-120b", ENV)
    return OpenAICompatibleClient(config, ENV, post=post), seen


def completion(content: str | None, finish: str, **message: Any) -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "choices": [
            {
                "message": {"role": "assistant", "content": content, **message},
                "finish_reason": finish,
            }
        ],
        "usage": {"prompt_tokens": 74, "completion_tokens": 20},
    }


def test_the_openai_client_sends_one_plain_chat_completion() -> None:
    client, seen = openai_client(200, completion(CORRECT, "stop"))
    reply = client.complete(system="sys", user="usr", max_tokens=99)
    assert reply == Reply(CORRECT, "end_turn", "req-9", 74, 20)
    ((url, body, headers),) = seen  # one request: no retries
    assert url == "https://api.example.test/v1/chat/completions"
    assert headers["Authorization"] == "Bearer k-test"
    assert body == {
        "model": "openai/gpt-oss-120b",
        "max_tokens": 99,
        "messages": [{"role": "system", "content": "sys"}, {"role": "user", "content": "usr"}],
    }  # no temperature: provider default, as with the Messages API


@pytest.mark.parametrize(
    ("body", "stop"),
    [
        (completion("[{", "length"), "max_tokens"),
        (completion(None, "content_filter"), "refusal"),
        (completion(None, "stop", refusal="I can't help with that."), "refusal"),
        (completion(None, "stop"), "end_turn"),
    ],
)
def test_the_openai_finish_reasons_map_to_the_probe_outcomes(body: dict, stop: str) -> None:
    client, _ = openai_client(200, body)
    assert client.complete(system="s", user="u", max_tokens=1).stop_reason == stop


def test_an_openai_provider_error_is_a_probe_error() -> None:
    client, _ = openai_client(401, {"error": {"message": "invalid api key"}})
    with pytest.raises(ProbeError, match=r"provider error \(401\): invalid api key"):
        client.complete(system="s", user="u", max_tokens=1)


def test_task_probe_cli_refuses_another_provider_before_any_call() -> None:
    args = ["task", "probe", "path-001", "--root", str(ROOT), "--model", "openai/gpt-5"]
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "openai-api/<service>/<model>" in result.output


def test_task_probe_cli_runs_an_openai_compatible_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    used: list[SingleShotConfig] = []

    class Fake:
        def __init__(self, config: SingleShotConfig, env: Any = None) -> None:
            used.append(config)

        def complete(self, *, system: str, user: str, max_tokens: int) -> Reply:
            return Reply("[]", "end_turn")

    for key, value in ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(probe, "OpenAICompatibleClient", Fake)
    args = ["task", "probe", "path-001", "--root", str(ROOT), "--json"]
    result = runner.invoke(app, [*args, "--model", "openai-api/akashml/openai/gpt-oss-120b"])
    assert result.exit_code == 0, result.output
    assert used[0].service == "akashml" and used[0].model == "openai/gpt-oss-120b"
    assert json.loads(result.output)["saturation"] == "open"


def test_task_probe_cli_reports_a_provider_error_without_a_traceback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Failing:
        def __init__(self, config: SingleShotConfig) -> None:
            self.model = config.model

        def complete(self, *, system: str, user: str, max_tokens: int) -> Reply:
            raise ProbeError(f"provider error (404): model: {self.model}")

    monkeypatch.setattr(probe, "AnthropicClient", Failing)
    args = ["task", "probe", "path-001", "--root", str(ROOT), "--model", "anthropic/m-1"]
    result = runner.invoke(app, args)
    assert result.exit_code == 2
    assert "error: provider error (404): model: m-1" in result.output
    assert "Traceback" not in result.output
