# SPDX-FileCopyrightText: 2026 Bindu Bhargava R Chintam
# SPDX-License-Identifier: Apache-2.0
"""Aureproof command-line interface (plan v2 §3.9, issue #16).

Offline commands work on saved records only; nothing here contacts a model.

Exit codes: 0 = success; 1 = a check failed (invalid bundle, re-score mismatch,
or not re-scorable); 2 = usage or I/O error (missing path, symlink, unsafe path).
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from collections import Counter
from pathlib import Path
from typing import Annotated, Any

import typer

from aureproof import __version__
from aureproof.bundle import validate as validate_bundle
from aureproof.bundle.canonical import canonical_json
from aureproof.bundle.run import rescore
from aureproof.bundle.validate import SignatureCheck
from aureproof.cli.report import collect, render_html, render_markdown
from aureproof.storage import StorageError, read_bundle

app = typer.Typer(
    name="aureproof",
    help="Integrity layer for AI-agent evaluations.",
    no_args_is_help=True,
    add_completion=False,
)

BundleArg = Annotated[Path, typer.Argument(help="Bundle directory.")]
TrustedOpt = Annotated[
    str | None,
    typer.Option(
        "--trusted-seal-digest", help="sha256:<hex> of seal.intoto.json, recorded elsewhere."
    ),
]
JsonOpt = Annotated[bool, typer.Option("--json", help="Machine-readable output.")]


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"aureproof {__version__}")
        raise typer.Exit


@app.callback()
def main(
    _version: bool = typer.Option(
        False,
        "--version",
        "-V",
        help="Show the Aureproof version and exit.",
        callback=_version_callback,
        is_eager=True,
    ),
) -> None:
    """Aureproof: every claim, backed by evidence."""


def _read(bundle: Path) -> dict[str, bytes]:
    try:
        return read_bundle(bundle)
    except StorageError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from exc


IdentityOpt = Annotated[
    str | None,
    typer.Option("--expect-identity", help="Expected signer identity (default: project policy)."),
]
IssuerOpt = Annotated[str | None, typer.Option("--expect-issuer", help="Expected OIDC issuer.")]


def _signature(files: dict[str, bytes], identity: str | None, issuer: str | None) -> SignatureCheck:
    try:
        from aureproof.signing import EXPECTED_IDENTITY, EXPECTED_ISSUER, verify_bundle
    except ImportError as exc:  # pragma: no cover - depends on the installed extras
        typer.echo("error: signature verification needs the `sign` extra", err=True)
        raise typer.Exit(2) from exc
    return verify_bundle(
        files, identity=identity or EXPECTED_IDENTITY, issuer=issuer or EXPECTED_ISSUER
    )


@app.command()
def validate(
    bundle: BundleArg,
    trusted_seal_digest: TrustedOpt = None,
    verify_signature: Annotated[
        bool, typer.Option("--verify-signature", help="Verify seal.sigstore.json offline (V5).")
    ] = False,
    require_signature: Annotated[
        bool,
        typer.Option("--require-signature", help="Fail unless V5 passes (signed-evidence gate)."),
    ] = False,
    public: Annotated[
        bool,
        typer.Option("--public", help="Also require a redacted, label-free, secret-free bundle."),
    ] = False,
    expect_identity: IdentityOpt = None,
    expect_issuer: IssuerOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Validate a bundle offline (checks V1-V6)."""
    from aureproof.bundle.public import public_problems

    files = _read(bundle)
    signature: SignatureCheck | None = None
    if verify_signature or require_signature:
        signature = _signature(files, expect_identity, expect_issuer)
    report = validate_bundle(files, trusted_seal_digest=trusted_seal_digest, signature=signature)
    gate: list[str] = []
    if require_signature and not report.signed:
        gate.append("signed-evidence gate: no verified signature (V5 did not pass)")
    if public:
        gate += [f"public: {p}" for p in public_problems(files)]
    ok = report.valid and not gate
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "valid": report.valid,
                    "signed": report.signed,
                    "ok": ok,
                    "gate_problems": gate,
                    "checks": [
                        {"id": c.id, "name": c.name, "status": c.status, "problems": c.problems}
                        for c in report.checks
                    ],
                },
                indent=2,
            )
        )
    else:
        for c in report.checks:
            typer.echo(f"{c.id} {c.name:<20} {c.status}")
            for p in c.problems:
                typer.echo(f"    - {p}")
        for p in gate:
            typer.echo(f"GATE {p}")
        typer.echo("VALID" if ok else "INVALID")
    raise typer.Exit(0 if ok else 1)


@app.command()
def sign(
    path: Annotated[Path, typer.Argument(help="Bundle directory, or a canonical JSON file.")],
) -> None:
    """Sign keylessly with the ambient OIDC identity (the sign.yml workflow)."""
    from aureproof.bundle.canonical import canonical_json
    from aureproof.bundle.models import SEAL
    from aureproof.contracts.strict_json import JsonInputError, loads_strict

    try:
        from aureproof.signing import sign_bytes, signature_path, verify_bytes
    except ImportError as exc:  # pragma: no cover
        typer.echo("error: signing needs the `sign` extra", err=True)
        raise typer.Exit(2) from exc
    target = path / SEAL if path.is_dir() else path
    if not target.is_file() or target.is_symlink():
        typer.echo(f"error: {target} is not a regular file", err=True)
        raise typer.Exit(2)
    data = target.read_bytes()
    try:
        if canonical_json(loads_strict(data, i_json=True)) != data:
            raise JsonInputError("not RFC 8785 canonical")
    except JsonInputError as exc:
        typer.echo(f"error: refusing to sign non-canonical JSON: {exc}", err=True)
        raise typer.Exit(2) from exc
    out = signature_path(path)
    if out.exists():
        typer.echo(f"error: {out} exists", err=True)
        raise typer.Exit(2)
    bundle_json = sign_bytes(data)
    check = verify_bytes(data, bundle_json)
    out.write_text(bundle_json, encoding="utf-8")
    typer.echo(f"wrote {out}; verified={check.verified} identity={check.identity}")
    raise typer.Exit(0 if check.verified else 1)


@app.command()
def verify(
    path: Annotated[Path, typer.Argument(help="Bundle directory, or a signed file.")],
    expect_identity: IdentityOpt = None,
    expect_issuer: IssuerOpt = None,
) -> None:
    """Verify a signature offline against the expected signer identity."""
    try:
        from aureproof.signing import (
            EXPECTED_IDENTITY,
            EXPECTED_ISSUER,
            signature_path,
            verify_bytes,
        )
    except ImportError as exc:  # pragma: no cover
        typer.echo("error: verification needs the `sign` extra", err=True)
        raise typer.Exit(2) from exc
    from aureproof.bundle.models import SEAL

    target = path / SEAL if path.is_dir() else path
    sig = signature_path(path)
    if not target.is_file() or not sig.is_file():
        typer.echo(f"error: need both {target} and {sig}", err=True)
        raise typer.Exit(2)
    check = verify_bytes(
        target.read_bytes(),
        sig.read_bytes(),
        identity=expect_identity or EXPECTED_IDENTITY,
        issuer=expect_issuer or EXPECTED_ISSUER,
    )
    typer.echo(f"verified={check.verified} identity={check.identity} issuer={check.issuer}")
    for p in check.problems:
        typer.echo(f"  - {p}")
    raise typer.Exit(0 if check.verified else 1)


@app.command()
def score(
    bundle: BundleArg,
    offline: Annotated[
        bool, typer.Option("--offline", help="Re-score from saved records.")
    ] = False,
    trusted_seal_digest: TrustedOpt = None,
    as_json: JsonOpt = False,
) -> None:
    """Re-score a sealed run bundle from saved records and compare byte for byte."""
    if not offline:
        typer.echo("error: only --offline scoring exists in v0.1", err=True)
        raise typer.Exit(2)
    files = _read(bundle)
    report = validate_bundle(files, trusted_seal_digest=trusted_seal_digest)
    if not report.valid:
        typer.echo("INVALID bundle; refusing to re-score:", err=True)
        for p in report.problems():
            typer.echo(f"  - {p}", err=True)
        raise typer.Exit(1)
    result = rescore(files)
    if as_json:
        typer.echo(
            json.dumps(
                {"status": result.status, "problems": result.problems, "metrics": result.metrics},
                indent=2,
            )
        )
    else:
        typer.echo(f"re-score: {result.status}")
        for p in result.problems:
            typer.echo(f"  - {p}")
        for name, m in ((result.metrics or {}).get("metrics") or {}).items():
            value = "undefined" if m.get("value") is None else f"{m['value']:.4f}"
            typer.echo(f"  {name:<28} {m['numerator']}/{m['denominator']}  {value}")
    raise typer.Exit(0 if result.status == "reproduced" else 1)


@app.command()
def report(
    bundle: BundleArg,
    out: Annotated[Path, typer.Option("--out", help="Report file to write.")],
    fmt: Annotated[str, typer.Option("--format", help="html or md.")] = "html",
    trusted_seal_digest: TrustedOpt = None,
    force: Annotated[bool, typer.Option("--force", help="Overwrite an existing report.")] = False,
) -> None:
    """Write an HTML or Markdown report. Exit 1 if the bundle is invalid or does not re-score."""
    if fmt not in ("html", "md"):
        typer.echo("error: --format must be html or md", err=True)
        raise typer.Exit(2)
    if (out.exists() or out.is_symlink()) and not force:
        typer.echo(f"error: {out} exists (use --force)", err=True)
        raise typer.Exit(2)
    files = _read(bundle)
    validation = validate_bundle(files, trusted_seal_digest=trusted_seal_digest)
    result = rescore(files) if validation.valid else None
    data = collect(files, validation, result, trusted_seal_digest is not None)
    text = render_html(data) if fmt == "html" else render_markdown(data)
    tmp = out.parent / f".{out.name}.tmp-{secrets.token_hex(6)}"
    tmp.write_text(text, encoding="utf-8")
    tmp.replace(out)
    ok = validation.valid and result is not None and result.status == "reproduced"
    typer.echo(f"wrote {out} ({'ok' if ok else 'with problems'})")
    raise typer.Exit(0 if ok else 1)


task_app = typer.Typer(help="Task health: calibration and qualification.", no_args_is_help=True)
app.add_typer(task_app, name="task")


@task_app.command("validate")
def task_validate(
    task_id: Annotated[str, typer.Argument(help="Task ID, e.g. authz-001.")],
    root: Annotated[Path, typer.Option("--root", help="Repository root.")] = Path(),
    out: Annotated[Path | None, typer.Option("--out", help="Write the THR JSON here.")] = None,
    as_json: JsonOpt = False,
) -> None:
    """Run every THR control twice, label lint, and canary checks. Exit 1 unless healthy."""
    from aureproof.oracles.calibration import calibrate, qualification_problems

    if not (root / "fixtures" / "security" / task_id).is_dir():
        typer.echo(f"error: no fixture for task {task_id!r} under {root}", err=True)
        raise typer.Exit(2)
    problems = qualification_problems(root, task_id)
    record = calibrate(root, task_id)
    if out is not None:
        if out.exists():
            typer.echo(f"error: {out} exists", err=True)
            raise typer.Exit(2)
        out.write_text(record.model_dump_json(indent=2) + "\n", encoding="utf-8")
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "status": record.status.value,
                    "reason": record.status_reason,
                    "qualification_problems": problems,
                    "record": record.model_dump(mode="json"),
                },
                indent=2,
            )
        )
    else:
        for c in record.controls:
            state = {True: "pass", False: "FAIL", None: "not run"}[c.passed]
            typer.echo(f"{c.kind.value:<20} {state}")
        typer.echo(f"determinism          {record.determinism.reproduced}")
        for p in problems:
            typer.echo(f"  - {p}")
        typer.echo(f"{task_id}: {record.status.value.upper()} ({record.status_reason})")
        typer.echo("note: unreviewed and unfrozen until an independent reviewer signs off (#31)")
    raise typer.Exit(0 if record.status.value == "healthy" and not problems else 1)


@app.command()
def run(
    protocol: Annotated[Path, typer.Option("--protocol", help="Decision Protocol JSON.")],
    thr: Annotated[
        list[Path], typer.Option("--thr", help="A Task Health Record the protocol names.")
    ],
    model: Annotated[str, typer.Option("--model", help="Model, e.g. anthropic/<id>.")],
    out: Annotated[Path, typer.Option("--out", help="Bundle directory to create.")],
    subject: Annotated[
        str, typer.Option("--subject", help="reference or claude_code.")
    ] = "reference",
    log_dir: Annotated[Path, typer.Option("--log-dir", help="Inspect logs.")] = Path("logs"),
    root: Annotated[Path, typer.Option("--root", help="Repository root.")] = Path(),
) -> None:
    """Run a protocol's episodes live and seal them as one bundle (the M2 chain)."""
    from aureproof.contracts.decision import DecisionProtocol
    from aureproof.contracts.thr import TaskHealthRecord
    from aureproof.runners.slice import SliceError, run_slice
    from aureproof.storage import write_bundle

    if out.exists():
        typer.echo(f"error: {out} exists", err=True)
        raise typer.Exit(2)
    if subject not in ("reference", "claude_code"):
        typer.echo(f"error: unknown subject {subject!r}", err=True)
        raise typer.Exit(2)
    try:
        from aureproof.runners.inspect_runner import (
            InspectRunner,
            InspectRunnerConfig,
            UnsupportedCapability,
        )
    except ModuleNotFoundError:
        typer.echo("error: live runs need the `inspect` extra", err=True)
        raise typer.Exit(2) from None
    proto = DecisionProtocol.model_validate_json(protocol.read_bytes())
    records = [TaskHealthRecord.model_validate_json(p.read_bytes()) for p in thr]
    try:
        runner = InspectRunner(
            InspectRunnerConfig(
                subject=subject,  # type: ignore[arg-type]
                model=model,
                model_name=model,
                log_dir=log_dir,
                budget=proto.budget,
            )
        )
        files = run_slice(root, proto, records, runner)
    except (SliceError, UnsupportedCapability) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    write_bundle(files, out)
    report = validate_bundle(files)
    status = rescore(files).status
    typer.echo(f"wrote {out}: valid={report.valid} offline re-score: {status}")
    typer.echo("next: sign it with the sign.yml workflow, then `aureproof verify`")
    raise typer.Exit(0 if report.valid and status == "reproduced" else 1)


adjudicate_app = typer.Typer(
    help="Adjudication of unresolved findings (append-only records).", no_args_is_help=True
)
app.add_typer(adjudicate_app, name="adjudicate")
AdjOpt = Annotated[
    Path | None, typer.Option("--adjudications", help="Adjudication records (JSONL).")
]


def _records(path: Path | None) -> list[Any]:
    from aureproof.contracts.adjudication import Adjudication
    from aureproof.contracts.strict_json import loads_strict

    if path is None or not path.exists():
        return []
    lines = path.read_bytes().splitlines()
    return [Adjudication.model_validate(loads_strict(line, i_json=True)) for line in lines if line]


def _queued(files: dict[str, bytes]) -> tuple[list[Any], list[tuple[str, Any]], str]:
    from aureproof.bundle.canonical import digest_ref
    from aureproof.bundle.models import SEAL
    from aureproof.scoring.adjudication import queue

    redo = rescore(files)
    if redo.status != "reproduced":
        typer.echo(f"error: the bundle does not re-score: {redo.status}", err=True)
        raise typer.Exit(2)
    episodes = [(ep.episode_id, s) for ep, s in redo.scored]
    return queue(episodes), episodes, digest_ref(files[SEAL])


@adjudicate_app.command("queue")
def adjudicate_queue(bundle: BundleArg, adjudications: AdjOpt = None) -> None:
    """Every unresolved finding, with its adjudication status."""
    from aureproof.scoring.adjudication import resolve

    items, _, _ = _queued(_read(bundle))
    for r in resolve(items, _records(adjudications)):
        who = ",".join(r.adjudicators) or "-"
        typer.echo(
            f"{r.item.episode_id} #{r.item.finding_index} {r.item.verdict} "
            f"{r.status} {r.decision.value if r.decision else '-'} [{who}]"
        )
    typer.echo(f"{len(items)} unresolved finding(s)")


@adjudicate_app.command("record")
def adjudicate_record(
    bundle: BundleArg,
    episode: Annotated[str, typer.Option("--episode", help="Episode ID.")],
    finding: Annotated[int, typer.Option("--finding", help="Finding index in the submission.")],
    decision: Annotated[str, typer.Option("--decision", help="confirmed, refuted, label_change.")],
    adjudicator: Annotated[str, typer.Option("--adjudicator", help="Who decided.")],
    rationale: Annotated[str, typer.Option("--rationale", help="Why.")],
    revision: Annotated[str, typer.Option("--revision", help="Dataset revision decided under.")],
    out: Annotated[Path, typer.Option("--out", help="Records file to append to (JSONL).")],
    role: Annotated[str, typer.Option("--role", help="primary, second, resolution.")] = "primary",
    revision_after: Annotated[
        str | None, typer.Option("--revision-after", help="New revision (label_change only).")
    ] = None,
    evidence: Annotated[
        list[str] | None, typer.Option("--evidence", help="Evidence reference.")
    ] = None,
) -> None:
    """Append one adjudication record; existing records are never edited."""
    from datetime import UTC, datetime

    from pydantic import ValidationError

    from aureproof.contracts.adjudication import Adjudication

    files = _read(bundle)
    items, _, seal = _queued(files)
    item = next((i for i in items if (i.episode_id, i.finding_index) == (episode, finding)), None)
    if item is None:
        typer.echo(f"error: {episode} #{finding} is not an unresolved finding", err=True)
        raise typer.Exit(2)
    try:
        record = Adjudication.model_validate(
            {
                "bundle_seal": seal,
                "finding": {"episode_id": episode, "finding_index": finding},
                "original_verdict": item.verdict,
                "adjudicator": adjudicator,
                "role": role,
                "decision": decision,
                "rationale": rationale,
                "evidence_refs": evidence or [],
                "timestamp": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
                "dataset_revision_before": revision,
                "dataset_revision_after": revision_after or revision,
            }
        )
    except ValidationError as exc:
        typer.echo(f"error: {exc.errors()[0]['msg']}", err=True)
        raise typer.Exit(2) from None
    with out.open("ab") as fh:
        fh.write(canonical_json(record.model_dump(mode="json")) + b"\n")
    typer.echo(f"recorded {record.identity} in {out}")


@adjudicate_app.command("report")
def adjudicate_report(
    bundle: BundleArg, adjudications: AdjOpt = None, as_json: JsonOpt = False
) -> None:
    """Coverage, agreement (Cohen's kappa) and post-adjudication metrics. Exit 1 if incomplete."""
    from aureproof.scoring.adjudication import agreement, check, post_adjudication, resolve

    items, episodes, seal = _queued(_read(bundle))
    records = _records(adjudications)
    problems = check(records, items, seal)
    if problems:
        for p in problems:
            typer.echo(f"error: {p}", err=True)
        raise typer.Exit(2)
    resolutions = resolve(items, records)
    agree = agreement(items, records)
    statuses = dict(Counter(r.status for r in resolutions))
    relabel = sorted(
        {
            rec.dataset_revision_after
            for rec in records
            if rec.decision.value == "label_change" and rec.role.value != "second"
        }
    )
    metrics = post_adjudication(episodes, resolutions)
    data = {
        "queued": agree.queued,
        "statuses": statuses,
        "double_adjudicated": agree.double_adjudicated,
        "coverage_ok": agree.coverage_ok,
        "agreed": agree.agreed,
        "kappa": agree.kappa,
        "kappa_undefined_reason": agree.undefined_reason,
        "rescore_under_revisions": relabel,
        "post_adjudication": {k: f"{n}/{d}" for k, (n, d) in metrics.items()},
    }
    if as_json:
        typer.echo(json.dumps(data, indent=2))
    else:
        for key, value in data.items():
            typer.echo(f"{key:<26} {value}")
    complete = statuses.get("decided", 0) == len(items) and agree.coverage_ok
    raise typer.Exit(0 if complete or not items else 1)


@app.command()
def migrate(
    source: Annotated[Path, typer.Argument(help="A record of an older version (JSON).")],
    out: Annotated[Path, typer.Option("--out", help="New file to write; never the input.")],
) -> None:
    """Upgrade a record into a new file with a provenance sidecar; never edits the input."""
    from aureproof.bundle.canonical import digest_ref
    from aureproof.bundle.models import SEAL
    from aureproof.contracts.migrate import MigrationError
    from aureproof.contracts.migrate import migrate as run_migrate
    from aureproof.contracts.strict_json import JsonInputError, loads_strict

    inside = [d for d in source.resolve().parents if (d / SEAL).exists()]
    if source.is_dir() or inside:
        typer.echo("error: sealed evidence is never migrated; re-score into a new bundle", err=True)
        raise typer.Exit(2)
    sidecar = out.with_name(out.name + ".provenance.json")
    if out.exists() or sidecar.exists() or out.resolve() == source.resolve():
        typer.echo(f"error: {out} or its provenance file exists", err=True)
        raise typer.Exit(2)
    data = source.read_bytes()
    try:
        result = run_migrate(loads_strict(data, i_json=True))
    except (JsonInputError, MigrationError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(2) from None
    out.write_text(json.dumps(result.record, indent=2) + "\n", encoding="utf-8")
    provenance = {
        "migrated_from": {"path": source.name, "sha256": digest_ref(data)},
        "source_version": result.source_version,
        "target_version": result.target_version,
        "losses": result.losses,
        "tool": {"name": "aureproof", "version": __version__},
    }
    sidecar.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    typer.echo(f"wrote {out} ({result.source_version} -> {result.target_version})")
    for loss in result.losses:
        typer.echo(f"  loss: {loss}")


@app.command("export-eee")
def export_eee(
    bundle: BundleArg,
    out: Annotated[Path, typer.Option("--out", help="EEE 0.3.0 aggregate record to write.")],
    organization: Annotated[str, typer.Option("--organization", help="Who publishes the record.")],
    timestamp: Annotated[
        str, typer.Option("--timestamp", help="retrieved_timestamp, Unix epoch seconds.")
    ],
) -> None:
    """Export one sealed run bundle as an Every Eval Ever 0.3.0 record; prints the losses."""
    from aureproof.exporters.eee import to_eee

    if out.exists():
        typer.echo(f"error: {out} exists", err=True)
        raise typer.Exit(2)
    if not timestamp.isdigit():
        typer.echo("error: --timestamp is Unix epoch seconds", err=True)
        raise typer.Exit(2)
    files = _read(bundle)
    if not validate_bundle(files).valid:
        typer.echo("error: the bundle does not validate; nothing exported", err=True)
        raise typer.Exit(2)
    try:
        result = to_eee(files, retrieved_timestamp=timestamp, organization=organization)
    except KeyError as exc:
        typer.echo(f"error: not a run bundle with a system spec: missing {exc}", err=True)
        raise typer.Exit(2) from None
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result.record, indent=2) + "\n", encoding="utf-8")
    typer.echo(f"wrote {out} (EEE {result.record['schema_version']}); not carried:")
    for loss in result.losses:
        typer.echo(f"  - {loss}")


EXIT = {"pass": 0, "fail": 1, "inconclusive": 3}  # 2: the evidence cannot be compared


@app.command()
def compare(
    protocol: Annotated[Path, typer.Option("--protocol", help="The frozen Decision Protocol.")],
    a: Annotated[Path, typer.Option("--a", help="Run bundle of configuration A.")],
    b: Annotated[Path, typer.Option("--b", help="Run bundle of configuration B.")],
    require_signature: Annotated[
        bool, typer.Option("--require-signature", help="Fail closed unless both are signed.")
    ] = False,
    report_out: Annotated[
        Path | None, typer.Option("--report", help="Write the Markdown report here.")
    ] = None,
    adjudications_a: Annotated[
        Path | None, typer.Option("--adjudications-a", help="Adjudication records for A.")
    ] = None,
    adjudications_b: Annotated[
        Path | None, typer.Option("--adjudications-b", help="Adjudication records for B.")
    ] = None,
    as_json: JsonOpt = False,
) -> None:
    """Pass, fail or inconclusive for B against A. Exit 0, 1 or 3; 2 if not comparable."""
    from aureproof.bundle.compare import GateError
    from aureproof.bundle.compare import compare as run_compare
    from aureproof.cli.report import render_comparison
    from aureproof.contracts.decision import DecisionProtocol

    proto = DecisionProtocol.model_validate_json(protocol.read_bytes())
    problems = []
    sides = {}
    for name, path in (("A", a), ("B", b)):
        files = _read(path)
        signature = _signature(files, None, None) if require_signature else None
        checked = validate_bundle(files, signature=signature)
        if not checked.valid:
            problems += [f"{name}: {p}" for p in checked.problems()]
        if require_signature and not checked.signed:
            problems.append(f"{name}: not signed by the project's signing workflow")
        sides[name] = files
    if not problems:
        try:
            result = run_compare(
                proto,
                sides["A"],
                sides["B"],
                adjudications_a=_records(adjudications_a),
                adjudications_b=_records(adjudications_b),
            )
        except GateError as exc:
            problems = exc.problems
    if problems:
        for p in problems:
            typer.echo(f"error: {p}", err=True)
        typer.echo("not comparable: no decision (exit 2)", err=True)
        raise typer.Exit(2)
    text = render_comparison(result)
    if report_out is not None:
        report_out.write_text(text, encoding="utf-8")
    if as_json:
        typer.echo(result.decision.model_dump_json(indent=2))
    else:
        typer.echo(text)
    raise typer.Exit(EXIT[result.decision.outcome])


@task_app.command("probe")
def task_probe(
    task_id: Annotated[str, typer.Argument(help="Task ID, e.g. authz-001.")],
    root: Annotated[Path, typer.Option("--root", help="Repository root.")] = Path(),
    model: Annotated[
        str | None,
        typer.Option("--model", help="Also run the single-shot model baseline (needs a key)."),
    ] = None,
    out: Annotated[
        Path | None, typer.Option("--out", help="Write the THR with its probe here.")
    ] = None,
    as_json: JsonOpt = False,
) -> None:
    """Difficulty probe: Bandit and single-shot baselines. Exit 1 if both solve the task."""
    from aureproof.oracles import probe
    from aureproof.oracles.calibration import calibrate
    from aureproof.oracles.probe import (
        ProbeError,
        bandit_baseline,
        probe_config,
        saturation,
        single_shot_baseline,
        with_probe,
    )

    if not (root / "fixtures" / "security" / task_id).is_dir():
        typer.echo(f"error: no fixture for task {task_id!r} under {root}", err=True)
        raise typer.Exit(2)
    if out is not None and out.exists():
        typer.echo(f"error: {out} exists", err=True)
        raise typer.Exit(2)
    try:
        config = probe_config(model, os.environ) if model is not None else None
    except ValueError as error:
        typer.echo(f"error: {error}", err=True)
        raise typer.Exit(2) from None
    try:
        static = bandit_baseline(root, task_id)
    except ModuleNotFoundError:
        typer.echo("error: the Bandit probe needs the `baseline` extra", err=True)
        raise typer.Exit(2) from None
    single = None
    if config is not None:
        try:
            client: probe.ModelClient = (
                probe.AnthropicClient(config)
                if config.service is None
                else probe.OpenAICompatibleClient(config, os.environ)
            )
            single = single_shot_baseline(root, task_id, config, client)
        except ModuleNotFoundError:
            typer.echo("error: the single-shot probe needs the `inspect` extra", err=True)
            raise typer.Exit(2) from None
        except ProbeError as error:
            typer.echo(f"error: {error}", err=True)
            raise typer.Exit(2) from None
    verdict = saturation(static, single)
    record = with_probe(calibrate(root, task_id), static, single)
    if out is not None:
        out.write_text(record.model_dump_json(indent=2) + "\n", encoding="utf-8")
    runs = [r for r in (static, single) if r is not None]
    if as_json:
        typer.echo(
            json.dumps(
                {
                    "task_id": task_id,
                    "task_identity": record.task.task_identity,
                    "saturation": verdict,
                    "baselines": [
                        {
                            "probe": r.probe,
                            "system_identity": r.system_identity,
                            "solved": r.solved,
                            "metrics": r.metrics,
                            "episodes": [vars(e) for e in r.episodes],
                            "mapping_losses": r.losses,
                        }
                        for r in runs
                    ],
                },
                indent=2,
            )
        )
    else:
        for r in runs:
            typer.echo(f"{r.probe:<18} solved={r.solved}  {r.system_identity}")
            for name in ("known_defect_recall", "strict_confirmed_yield"):
                typer.echo(f"  {name:<24} {r.metrics[name]}")
            for e in r.episodes:
                typer.echo(f"  {e.variant:<10} {e.disposition} {e.verdicts}")
        if single is None:
            typer.echo("single_shot_model  not run (pass --model; needs a provider key, #7)")
        typer.echo(f"{task_id}: {verdict.upper()}")
        if verdict == "saturated":
            typer.echo("both baselines solve it: redesign before benchmark expansion (#44)")
    raise typer.Exit(1 if verdict == "saturated" else 0)


if __name__ == "__main__":  # pragma: no cover
    sys.exit(app())
