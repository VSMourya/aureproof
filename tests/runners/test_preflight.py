# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Bridge preflight: unsupported capabilities fail before dispatch (issue #42)."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from aureproof.runners.inspect_runner import (
    InspectRunner,
    InspectRunnerConfig,
    UnsupportedCapability,
    preflight,
    system_spec,
)

CC = InspectRunnerConfig(subject="claude_code", model="mockllm/model", log_dir=Path("logs"))
REF = dataclasses.replace(CC, subject="reference")


def test_claude_code_discloses_the_bridge_translation_in_its_identity() -> None:
    pytest.importorskip("inspect_ai")  # system_spec records Inspect's version
    transformations = preflight(CC)
    assert any("sandbox_agent_bridge" in t for t in transformations)
    assert system_spec(CC).settings["transformations"] == transformations
    assert preflight(REF) == []


@pytest.mark.parametrize(
    ("config", "message"),
    [
        (dataclasses.replace(CC, hosted_tools="web-search"), "web-search is not implemented"),
        (dataclasses.replace(REF, hosted_tools="web-search"), "no hosted tools"),
        (
            dataclasses.replace(CC, model="openai/gpt-x", model_name="openai/gpt-x"),
            "needs an Anthropic Messages provider",
        ),
        (dataclasses.replace(CC, model="anthropic/claude-x"), "differs from the recorded"),
    ],
    ids=["cc-web-search", "reference-web-search", "cc-other-provider", "identity-mismatch"],
)
def test_unsupported_capabilities_fail_before_any_dispatch(
    config: InspectRunnerConfig, message: str
) -> None:
    with pytest.raises(UnsupportedCapability, match=message):
        preflight(config)
    with pytest.raises(UnsupportedCapability):
        InspectRunner(config)  # never reaches run_attempt, so never re-dispatched
    with pytest.raises(UnsupportedCapability):
        system_spec(config)  # no identity is minted for an unqualified system


def test_qualified_configurations_pass_preflight() -> None:
    assert preflight(REF) == []
    assert len(preflight(CC)) == 2


def test_anthropic_claude_code_is_qualified() -> None:
    pytest.importorskip("inspect_ai")
    config = dataclasses.replace(CC, model="anthropic/claude-x", model_name="anthropic/claude-x")
    assert InspectRunner(config).system_spec().models["main"].protocol == "anthropic-messages"


# --- The reference subject on an OpenAI-compatible endpoint (openai-api/<service>/<model>) ---

OPENAI_API = "openai-api/akashml/openai/gpt-oss-120b"
ENDPOINT = {"AKASHML_API_KEY": "k-test", "AKASHML_BASE_URL": "https://api.example.test/v1/"}


def reference_on(model: str) -> InspectRunnerConfig:
    return dataclasses.replace(REF, model=model, model_name=model)


def test_the_reference_subject_runs_on_an_openai_compatible_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for key, value in ENDPOINT.items():
        monkeypatch.setenv(key, value)
    (note,) = preflight(reference_on(OPENAI_API))
    assert "https://api.example.test/v1" in note and "openai-api" in note


def test_the_endpoint_is_recorded_in_the_system_identity(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("inspect_ai")
    for key, value in ENDPOINT.items():
        monkeypatch.setenv(key, value)
    spec = system_spec(reference_on(OPENAI_API))
    main = spec.models["main"]
    assert main.provider == "openai-api" and main.model == OPENAI_API
    assert main.provider_identity.endpoint == "https://api.example.test/v1"
    first = spec.identity
    monkeypatch.setenv("AKASHML_BASE_URL", "https://elsewhere.test/v1")
    assert system_spec(reference_on(OPENAI_API)).identity != first
    # an Anthropic system records no endpoint, as before
    anthropic = system_spec(reference_on("anthropic/claude-x")).models["main"]
    assert anthropic.provider_identity.endpoint is None


@pytest.mark.parametrize(
    ("model", "env", "message"),
    [
        ("openai-api/akashml", ENDPOINT, "openai-api/<service>/<model>"),
        (OPENAI_API, {"AKASHML_API_KEY": "k"}, "AKASHML_BASE_URL"),
        (OPENAI_API, {"AKASHML_BASE_URL": "https://x.test/v1"}, "AKASHML_API_KEY"),
        (OPENAI_API, {**ENDPOINT, "AKASHML_BASE_URL": "http://x.test/v1"}, "https"),
    ],
    ids=["no-model", "no-base-url", "no-key", "not-https"],
)
def test_an_openai_compatible_endpoint_without_its_settings_is_refused(
    monkeypatch: pytest.MonkeyPatch, model: str, env: dict[str, str], message: str
) -> None:
    for key in ("AKASHML_API_KEY", "AKASHML_BASE_URL"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    with pytest.raises(UnsupportedCapability, match=message):
        preflight(reference_on(model))
