# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Render a run bundle as HTML or Markdown (issue #16).

Every string that can come from an agent (finding descriptions, file paths,
symbols, extra fields) or from the bundle is escaped. The report always shows
denominators, undefined and unresolved outcomes, refusals, and the bundle's
limitations: unsigned, its completeness, and whether a trusted seal digest was
checked.
"""

from __future__ import annotations

import html
import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aureproof.bundle.models import BLOB_PREFIX
from aureproof.bundle.run import EPISODES, METRICS, VERDICTS, Rescore
from aureproof.bundle.validate import Report
from aureproof.contracts.strict_json import JsonInputError, loads_strict


@dataclass
class ReportData:
    validation: Report
    rescore: Rescore | None
    seal: dict[str, Any]
    metrics: dict[str, Any]
    verdicts: list[dict[str, Any]]
    episodes: list[dict[str, Any]]
    findings: dict[str, list[Any]]  # episode_id -> raw submitted findings
    trusted_seal_checked: bool


def _json(files: Mapping[str, bytes], path: str, default: Any) -> Any:
    try:
        return loads_strict(files[path], i_json=True)
    except (KeyError, JsonInputError):
        return default


def collect(
    files: Mapping[str, bytes], validation: Report, rescore: Rescore | None, trusted: bool
) -> ReportData:
    episodes = _json(files, EPISODES, [])
    findings: dict[str, list[Any]] = {}
    for ep in episodes if isinstance(episodes, list) else []:
        ref = ep.get("submission") if isinstance(ep, dict) else None
        if isinstance(ref, str):
            raw = _json(files, BLOB_PREFIX + ref.removeprefix("sha256:"), None)
            findings[str(ep.get("episode_id"))] = raw if isinstance(raw, list) else []
    return ReportData(
        validation=validation,
        rescore=rescore,
        seal=_json(files, "seal.intoto.json", {}),
        metrics=_json(files, METRICS, {}),
        verdicts=_json(files, VERDICTS, []),
        episodes=episodes if isinstance(episodes, list) else [],
        findings=findings,
        trusted_seal_checked=trusted,
    )


def limitations(data: ReportData) -> list[str]:
    predicate = data.seal.get("predicate", {}) if isinstance(data.seal, dict) else {}
    out = ["Unsigned: Sigstore signing arrives in M2. Integrity is relative to the seal digest."]
    if not data.trusted_seal_checked:
        out.append("No trusted seal digest was supplied, so the seal's own metadata is unchecked.")
    completeness = predicate.get("completeness", "unknown")
    out.append(f"Completeness: {completeness}.")
    if completeness == "incomplete":
        out.append(
            "At least one episode is evidence_incomplete. It is reported, never graded, "
            "and a decision gate refuses this bundle."
        )
    if data.rescore is None:
        out.append("Not re-scored.")
    elif data.rescore.status != "reproduced":
        out += [f"Re-score {data.rescore.status}: {p}" for p in data.rescore.problems]
    out.append("Synthetic fixtures measure controlled skills, not real-world capability.")
    return out


def _metric_rows(data: ReportData) -> list[tuple[str, str, str, str]]:
    rows = []
    metrics = data.metrics.get("metrics", {}) if isinstance(data.metrics, dict) else {}
    for name, m in metrics.items():
        value = m.get("value")
        shown = "undefined" if value is None else f"{value:.4f}"
        reason = m.get("undefined_reason") or ""
        rows.append((name, f"{m.get('numerator')}/{m.get('denominator')}", shown, reason))
    return rows


def _finding_rows(data: ReportData) -> list[tuple[str, str, str, str, str]]:
    rows = []
    for record in data.verdicts:
        episode = str(record.get("episode_id"))
        raw = data.findings.get(episode, [])
        for v in record.get("verdicts") or []:
            idx = v.get("finding_index", 0)
            finding = raw[idx] if isinstance(raw, list) and idx < len(raw) else {}
            locs = finding.get("locations", []) if isinstance(finding, dict) else []
            where = ", ".join(
                f"{loc.get('file', '')}::{loc.get('symbol', '')}"
                for loc in locs
                if isinstance(loc, dict)
            )
            desc = finding.get("description", "") if isinstance(finding, dict) else ""
            label = f"{v.get('verdict')} ({v.get('rule')}" + (
                f", {v['defect_id']})" if v.get("defect_id") else ")"
            )
            rows.append((episode, str(idx), label, where, str(desc)))
    return rows


# No scripts, no remote resources: even an unescaped string could not run code.
_CSP = "default-src 'none'; style-src 'unsafe-inline'"


def _dispositions(data: ReportData) -> str:
    counts = Counter(str(r.get("disposition")) for r in data.verdicts)
    return json.dumps(counts, sort_keys=True)


def render_html(data: ReportData) -> str:
    e = html.escape
    status = "VALID" if data.validation.valid else "INVALID"
    rescore = data.rescore.status if data.rescore else "not run"
    parts = [
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        f"<meta http-equiv='Content-Security-Policy' content=\"{_CSP}\">",
        "<title>Aureproof report</title></head><body>",
        f"<h1>Aureproof report</h1><p>Bundle: <strong>{e(status)}</strong>. "
        f"Offline re-score: <strong>{e(rescore)}</strong>.</p>",
        "<h2>Limitations</h2><ul>",
        *[f"<li>{e(item)}</li>" for item in limitations(data)],
        "</ul><h2>Validation</h2><table><tr><th>Check</th><th>Status</th><th>Problems</th></tr>",
        *[
            f"<tr><td>{e(c.id)} {e(c.name)}</td><td>{e(c.status)}</td>"
            f"<td>{e('; '.join(c.problems))}</td></tr>"
            for c in data.validation.checks
        ],
        "</table><h2>Metrics (numerator / denominator)</h2>",
        "<table><tr><th>Metric</th><th>Support</th><th>Value</th><th>Undefined because</th></tr>",
        *[
            f"<tr><td>{e(a)}</td><td>{e(b)}</td><td>{e(c)}</td><td>{e(d)}</td></tr>"
            for a, b, c, d in _metric_rows(data)
        ],
        "</table><h2>Episodes</h2><table><tr><th>Episode</th><th>Disposition</th>"
        "<th>Credited</th><th>Annotations</th></tr>",
        *[
            f"<tr><td>{e(str(r.get('episode_id')))}</td><td>{e(str(r.get('disposition')))}</td>"
            f"<td>{e(', '.join(map(str, r.get('credited', []))))}</td>"
            f"<td>{e(', '.join(map(str, r.get('annotations', []))))}</td></tr>"
            for r in data.verdicts
        ],
        "</table><h2>Findings (agent-authored text is escaped)</h2>",
        "<table><tr><th>Episode</th><th>#</th><th>Verdict</th><th>Location</th>"
        "<th>Description</th></tr>",
        *[
            f"<tr><td>{e(a)}</td><td>{e(b)}</td><td>{e(c)}</td><td>{e(d)}</td><td>{e(f)}</td></tr>"
            for a, b, c, d, f in _finding_rows(data)
        ],
        "</table>",
        f"<h2>Dispositions</h2><pre>{e(_dispositions(data))}</pre>",
        "</body></html>",
    ]
    return "\n".join(parts) + "\n"


def _md(text: str) -> str:
    return html.escape(text).replace("|", "\\|").replace("\n", " ")


def render_markdown(data: ReportData) -> str:
    status = "VALID" if data.validation.valid else "INVALID"
    rescore = data.rescore.status if data.rescore else "not run"
    lines = [
        "# Aureproof report",
        "",
        f"Bundle: **{status}**. Offline re-score: **{rescore}**.",
        "",
        "## Limitations",
        "",
        *[f"- {_md(x)}" for x in limitations(data)],
        "",
        "## Metrics",
        "",
        "| Metric | Support | Value | Undefined because |",
        "| --- | --- | --- | --- |",
        *[f"| {_md(a)} | {_md(b)} | {_md(c)} | {_md(d)} |" for a, b, c, d in _metric_rows(data)],
        "",
        "## Findings",
        "",
        "| Episode | # | Verdict | Location | Description |",
        "| --- | --- | --- | --- | --- |",
        *[
            f"| {_md(a)} | {_md(b)} | {_md(c)} | {_md(d)} | {_md(f)} |"
            for a, b, c, d, f in _finding_rows(data)
        ],
    ]
    return "\n".join(lines) + "\n"


def render_comparison(comparison: Any) -> str:
    """Markdown for ``aureproof compare`` (issue #50). No agent-authored text appears."""
    d, p = comparison.decision, comparison.protocol
    lines = [
        f"# Comparison: {p.name}",
        "",
        f"**Outcome: {d.outcome}** ({d.reason})",
        "",
        f"- Protocol `{d.protocol}`; repetitions {p.repetitions}; margin {p.margin}; "
        f"alpha {p.test.alpha} per side; estimand {p.estimand.metric}, B - A, "
        f"{p.estimand.summary}.",
        f"- A `{comparison.a.system_identity}`; B `{comparison.b.system_identity}`.",
        f"- {d.clusters} clusters with a defined difference; at least "
        f"{d.min_clusters_for_decision} are needed for a decisive outcome.",
        f"- Mean difference {d.mean_difference}; exact two-sided p {d.p_value_two_sided}; "
        f"CI [{d.ci.lower}, {d.ci.upper}].",
        f"- Wilson intervals: A [{d.wilson_a.lower}, {d.wilson_a.upper}], "
        f"B [{d.wilson_b.lower}, {d.wilson_b.upper}].",
    ]
    for g in d.guardrails:
        lines.append(
            f"- Guardrail {g.metric} (margin {g.margin}): {g.outcome}; mean difference "
            f"{g.mean_difference} over {g.clusters} clusters; CI [{g.ci.lower}, {g.ci.upper}]."
        )
    if d.provisional_outcome != d.outcome:
        lines.append(f"- Provisional outcome {d.provisional_outcome}, not final: {d.reason}.")
    lines += [
        "",
        "## Clusters",
        "",
        "| Cluster | Tasks | A confirmed/submitted | B confirmed/submitted | "
        "Unresolved A/B | B - A |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for row in d.cluster_table:
        tasks = ", ".join(comparison.cluster_tasks.get(row.cluster_id, []))
        diff = row.difference if row.difference is not None else "excluded (undefined)"
        lines.append(
            f"| {row.cluster_id} | {tasks} | {row.a_confirmed}/{row.a_submitted} | "
            f"{row.b_confirmed}/{row.b_submitted} | {row.a_unresolved}/{row.b_unresolved} | "
            f"{diff} |"
        )
    lines += ["", "## Quality and operations, per configuration", ""]
    lines += ["| Metric | A | B |", "| --- | --- | --- |"]
    for name in comparison.a.metrics:
        lines.append(f"| {name} | {comparison.a.metrics[name]} | {comparison.b.metrics[name]} |")
    for side in (comparison.a, comparison.b):
        counts = ", ".join(f"{k} {v}" for k, v in side.dispositions.items())
        lines.append(f"\n{side.side}: {side.episodes} episodes ({counts}).")
    lines += [
        "",
        "Uncertainty is over these clusters of this fixed suite only; it is not a claim "
        "about a wider population of tasks.",
    ]
    return "\n".join(lines) + "\n"
