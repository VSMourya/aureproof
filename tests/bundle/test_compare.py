# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Paired comparison of two run bundles under a protocol (issues #50, #53)."""

from __future__ import annotations

import importlib.util
import itertools
import json
from fractions import Fraction
from pathlib import Path

import pytest

from aureproof.bundle.compare import GateError, compare
from aureproof.contracts.decision import DecisionProtocol
from aureproof.storage import read_bundle

ROOT = Path(__file__).resolve().parents[2]
EXAMPLES = ROOT / "examples" / "gate"
OUTCOMES = ("pass", "fail", "inconclusive")


def _example(name: str) -> tuple[DecisionProtocol, dict[str, bytes], dict[str, bytes]]:
    base = EXAMPLES / name
    protocol = DecisionProtocol.model_validate_json((base / "protocol.json").read_bytes())
    return protocol, read_bundle(base / "a"), read_bundle(base / "b")


def _enumerated_p(diffs: list[Fraction]) -> Fraction:
    """Two-sided exact p by brute force over all 2^k sign flips, independent of stats/."""
    observed = abs(sum(diffs)) / len(diffs)
    flips = list(itertools.product((1, -1), repeat=len(diffs)))
    hits = sum(
        abs(sum(s * d for s, d in zip(signs, diffs, strict=True))) / len(diffs) >= observed
        for signs in flips
    )
    return Fraction(hits, len(flips))


@pytest.mark.parametrize("name", OUTCOMES)
def test_each_example_reaches_its_hand_worked_outcome(name: str) -> None:
    protocol, a, b = _example(name)
    expected = json.loads((EXAMPLES / name / "expected.json").read_text())
    decision = compare(protocol, a, b).decision
    assert decision.outcome == expected["outcome"], decision.reason
    assert decision.mean_difference == expected["mean_difference"]
    assert decision.p_value_two_sided == expected["p_value_two_sided"]
    diffs = [Fraction(row.difference) for row in decision.cluster_table if row.difference]
    assert len(diffs) == decision.clusters == 8
    assert Fraction(decision.p_value_two_sided) == _enumerated_p(diffs)


def test_the_report_separates_quality_from_operational_completion() -> None:
    result = compare(*_example("pass"))
    assert result.a.metrics["strict_confirmed_yield"] == "8/16"
    assert result.b.metrics["strict_confirmed_yield"] == "8/8"
    assert result.a.metrics["operational_completion"] == "16/16"
    assert result.a.dispositions == {"completed_no_findings": 8, "completed_with_findings": 8}
    assert result.cluster_tasks == {f"s{i}": [f"s{i}"] for i in range(1, 9)}
    assert result.a.system_identity == result.protocol.configurations.A


def test_swapped_bundles_fail_closed() -> None:
    protocol, a, b = _example("pass")
    with pytest.raises(GateError) as err:
        compare(protocol, b, a)
    assert any("is not configuration A" in p for p in err.value.problems)
    assert any("is not configuration B" in p for p in err.value.problems)


def test_a_bundle_from_another_protocol_fails_closed() -> None:
    protocol, a, _ = _example("pass")
    _, _, other_b = _example("fail")
    with pytest.raises(GateError) as err:
        compare(protocol, a, other_b)
    assert any("is not this protocol" in p for p in err.value.problems)
    assert any("planned for another run" in p for p in err.value.problems)


def test_missing_episodes_and_tampered_evidence_fail_closed() -> None:
    protocol, a, b = _example("pass")
    episodes = json.loads(b["episodes.json"])
    short = dict(b, **{"episodes.json": json.dumps(episodes[:-1]).encode()})
    with pytest.raises(GateError) as err:
        compare(protocol, a, short)
    problems = " ".join(err.value.problems)
    assert "s8/repaired has 0 episodes" in problems
    assert "offline re-score" in problems  # the edited file no longer re-scores

    tampered = dict(b, **{"verdicts.json": b"[]"})
    with pytest.raises(GateError, match="offline re-score mismatch"):
        compare(protocol, a, tampered)


def test_a_bundle_sealed_as_incomplete_fails_closed() -> None:
    protocol, a, b = _example("pass")
    seal = json.loads(b["seal.intoto.json"])
    seal["predicate"]["completeness"] = "incomplete"
    incomplete = dict(b, **{"seal.intoto.json": json.dumps(seal).encode()})
    with pytest.raises(GateError) as err:
        compare(protocol, a, incomplete)
    assert "B: sealed as incomplete; the gate needs complete evidence" in err.value.problems


def test_a_thr_other_than_the_one_registered_fails_closed() -> None:
    protocol, a, b = _example("pass")
    thr = json.loads(b["tasks/s1/thr.json"])
    thr["known_limits"] = ["edited after registration"]
    edited = dict(b, **{"tasks/s1/thr.json": json.dumps(thr).encode()})
    with pytest.raises(GateError, match="THR digest differs from the protocol"):
        compare(protocol, a, edited)


def test_examples_are_committed_exactly_as_generated() -> None:
    spec = importlib.util.spec_from_file_location("gate", ROOT / "scripts/make_gate_examples.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    on_disk = {
        p.relative_to(EXAMPLES).as_posix(): p.read_bytes()
        for p in EXAMPLES.rglob("*")
        if p.is_file()
    }
    assert module.build() == on_disk


# ---- CLI -----------------------------------------------------------------------------


def _cli(*args: str) -> object:
    from typer.testing import CliRunner

    from aureproof.cli.main import app

    return CliRunner().invoke(app, ["compare", *args])


@pytest.mark.parametrize(("name", "code"), [("pass", 0), ("fail", 1), ("inconclusive", 3)])
def test_compare_cli_exit_codes_and_report(name: str, code: int, tmp_path: Path) -> None:
    base = EXAMPLES / name
    report = tmp_path / "report.md"
    result = _cli(
        "--protocol",
        str(base / "protocol.json"),
        "--a",
        str(base / "a"),
        "--b",
        str(base / "b"),
        "--report",
        str(report),
    )
    assert result.exit_code == code, result.output  # type: ignore[attr-defined]
    text = report.read_text()
    assert f"**Outcome: {name}**" in text
    assert "not a claim about a wider population" in text
    assert "| s1 | s1 |" in text


def test_compare_cli_refuses_evidence_it_cannot_compare() -> None:
    base = EXAMPLES / "pass"
    result = _cli(
        "--protocol", str(base / "protocol.json"), "--a", str(base / "b"), "--b", str(base / "a")
    )
    assert result.exit_code == 2  # type: ignore[attr-defined]
    assert "not comparable" in result.output  # type: ignore[attr-defined]


def test_compare_cli_requires_signatures_when_asked() -> None:
    pytest.importorskip("sigstore")
    base = EXAMPLES / "pass"
    result = _cli(
        "--protocol",
        str(base / "protocol.json"),
        "--a",
        str(base / "a"),
        "--b",
        str(base / "b"),
        "--require-signature",
    )
    assert result.exit_code == 2  # type: ignore[attr-defined]
    assert "not signed" in result.output  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", OUTCOMES)
def test_cluster_rows_carry_the_recall_the_metric_reports(name: str) -> None:
    """The guardrail's per-cluster support adds up to each side's known-defect recall."""
    result = compare(*_example(name))
    rows = result.decision.cluster_table
    for side, summary in (("a", result.a), ("b", result.b)):
        credited = sum(getattr(r, f"{side}_credited") for r in rows)
        present = sum(getattr(r, f"{side}_positives") for r in rows)
        assert f"{credited}/{present}" == summary.metrics["known_defect_recall"]
        assert present > 0


def test_the_report_lists_each_guardrail() -> None:
    import dataclasses

    from aureproof.cli.report import render_comparison
    from aureproof.contracts.decision import GuardrailResult, Interval

    result = compare(*_example("pass"))
    guard = GuardrailResult(
        metric="known_defect_recall",
        margin=0.1,
        outcome="fail",
        reason="CI upper bound -2/3 < -margin -1/10",
        clusters=8,
        mean_difference="-2/3",
        ci=Interval(lower=-2 / 3, upper=-2 / 3),
    )
    decision = result.decision.model_copy(update={"guardrails": [guard]})
    text = render_comparison(dataclasses.replace(result, decision=decision))
    assert "Guardrail known_defect_recall (margin 0.1): fail; mean difference -2/3" in text
    assert "Guardrail" not in render_comparison(result)
