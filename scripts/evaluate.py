#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Turn Grype JSON report(s) into a summary table, counts and a verdict.

Gating is computed here rather than taken from Grype's ``--fail-on``
exit code, because approved bypasses have to be subtracted from the
findings first, and because a run may report findings as warnings
rather than blocking. Deriving the table, the counts and the verdict
from one place keeps all three consistent.
"""

from __future__ import annotations

import json
import os
import sys

from scripts.model import (
    ADVISORY_INHERITED,
    ADVISORY_UNARMED,
    ADVISORY_UNFIXABLE,
    Report,
    Section,
    Settings,
    emit,
    epss_percent,
    fix_text,
    risk_value,
    severity_rank,
)
from scripts.provenance import DIRECT, TRANSITIVE, build
from scripts.render import write_summary


def load_manifest() -> list[tuple[str, str]]:
    """Parse the 'report.json|artefact' lines from the scan step."""
    entries = []
    for line in (os.environ.get("MANIFEST") or "").splitlines():
        line = line.strip()
        if not line:
            continue
        report, _, artefact = line.partition("|")
        if report:
            entries.append((report, artefact or report))
    return entries


def load_bypasses() -> dict[str, dict]:
    """Index approved bypasses by upper-cased vulnerability ID."""
    try:
        entries = json.loads(os.environ.get("BYPASSES") or "[]")
    except json.JSONDecodeError:
        # Malformed data must not open the gate.
        return {}
    if not isinstance(entries, list):
        return {}
    return {
        str(entry["id"]).upper(): entry
        for entry in entries
        if isinstance(entry, dict) and entry.get("id")
    }


def sibling_reports(report: str) -> list[str]:
    """Every report format sharing this JSON report's stem."""
    stem = report[: -len(".json")] if report.endswith(".json") else report
    found = []
    for suffix in (".json", ".txt", ".sarif", ".cdx.xml", ".cdx.json"):
        candidate = f"{stem}{suffix}"
        if os.path.exists(candidate):
            found.append(candidate)
    return found


def sbom_path(artefact: str) -> str:
    """The SBOM file behind a manifest entry, empty for a target."""
    prefix = "sbom:"
    return artefact[len(prefix) :] if artefact.startswith(prefix) else ""


def build_row(match: dict) -> dict:
    """Flatten a Grype match into the fields the table renders."""
    vulnerability = match.get("vulnerability", {}) or {}
    artifact = match.get("artifact", {}) or {}
    risk = vulnerability.get("risk")
    fix = vulnerability.get("fix") or {}
    return {
        "fixable": bool(fix.get("versions")) or fix.get("state") == "fixed",
        "package": artifact.get("name"),
        "version": artifact.get("version"),
        "type": artifact.get("type"),
        "id": vulnerability.get("id"),
        "severity": (vulnerability.get("severity") or "unknown").lower(),
        "fix": fix_text(vulnerability),
        "epss": epss_percent(vulnerability),
        "risk": risk_value(vulnerability),
        "risk_sort": float(risk) if isinstance(risk, (int, float)) else -1.0,
    }


def verdict_threshold(row: dict, settings: Settings) -> int | None:
    """The bar this finding has to clear to block the run.

    Declared packages answer to fail-on and inherited ones to
    transitive-fail-on. The two are independent bars, not one filter
    layered on the other: a project may hold what it declares to
    'medium' while only stopping for 'critical' in what those
    declarations drag in behind them. None means this finding can
    never gate.
    """
    if settings.threshold is None:
        return None
    if settings.policy_declared and row.get("provenance") == TRANSITIVE:
        return settings.transitive_threshold
    return settings.threshold


def collect(settings: Settings, bypasses: dict[str, dict]) -> Report:
    """Read every report and sort findings into their buckets."""
    report = Report()
    for path, artefact in load_manifest():
        if not os.path.exists(path):
            continue
        report.report_files.extend(sibling_reports(path))

        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)

        section = Section(artefact=artefact)
        # Classified whatever the policy: dependency-policy decides
        # which findings block, not whether the provenance outputs
        # tell the truth. A project still on 'all' can read them to
        # see what switching to 'declared' would change.
        provenance = build(
            sbom_path(artefact), settings.declared_path, settings.declared_source
        )
        section.provenance_source = provenance.source
        for match in data.get("matches", []):
            row = build_row(match)
            row["provenance"] = provenance.classify(match.get("artifact") or {})
            report.total += 1
            report.severity_counts[row["severity"]] = (
                report.severity_counts.get(row["severity"], 0) + 1
            )
            # Keep every finding for reporting; the summary shows them
            # even when the threshold is 'none' or nothing gates.
            section.rows.append(row)

            rank = severity_rank(row["severity"])
            gate_at = verdict_threshold(row, settings)
            gates = gate_at is not None and rank >= gate_at
            # Worth reporting as a warning: clears the project's own
            # bar, but not the one that applies to this finding. An
            # inherited package nobody declared lands here, and so
            # does everything when the gate is unarmed.
            warns = (
                settings.threshold is not None
                and rank >= settings.threshold
                and not gates
            )
            if not gates and not warns:
                continue
            # only-fixed narrows the GATE, not the report. A finding
            # no bump can clear is demoted to a warning rather than
            # dropped, so it stays visible in the summary instead of
            # vanishing from a run that has other findings to show.
            demoted = gates and settings.only_fixed and not row["fixable"]
            if demoted:
                gates = False
                warns = True

            bypass = bypasses.get(str(row["id"]).upper())
            if bypass:
                row["bypass"] = bypass
                section.bypassed.append(row)
            elif gates and settings.gate_active:
                section.gating.append(row)
            else:
                if not settings.gate_active:
                    row["advisory_reason"] = ADVISORY_UNARMED
                elif demoted:
                    row["advisory_reason"] = ADVISORY_UNFIXABLE
                else:
                    row["advisory_reason"] = ADVISORY_INHERITED
                section.advisory.append(row)

        report.sections.append(section)
    return report


def count_provenance(report: Report, value: str) -> int:
    """How many reported findings carry this provenance."""
    return sum(1 for row in report.rows if row.get("provenance") == value)


def provenance_sources(report: Report) -> str:
    """Which classifier answered, keyed by the artefact it scanned.

    A multi-SBOM run can classify one artefact and fail closed on
    another; collapsing that to a set would hide which was which.
    """
    return json.dumps(
        {section.artefact: section.provenance_source for section in report.sections},
        sort_keys=True,
    )


def write_outputs(report: Report, settings: Settings) -> None:
    """Publish the step outputs consumers act on."""
    emit("gating", "true" if report.gating else "false")
    emit("total-matches", str(report.total))
    emit("gating-matches", str(len(report.gating)))
    emit("advisory-matches", str(len(report.advisory)))
    emit("bypassed-matches", str(len(report.bypassed)))
    emit("direct-matches", str(count_provenance(report, DIRECT)))
    emit("transitive-matches", str(count_provenance(report, TRANSITIVE)))
    emit("provenance-source", provenance_sources(report))
    emit("gate-active", "true" if settings.can_gate else "false")
    emit("gate-reason", settings.gate_reason)
    emit("threshold-label", settings.threshold_label)
    emit(
        "bypassed-ids",
        ",".join(sorted({str(row["id"]) for row in report.bypassed})),
    )
    emit("severity-counts", json.dumps(report.severity_counts, sort_keys=True))
    emit("report-files", "\n".join(report.report_files))


def main() -> int:
    """Evaluate the reports, write the summary, publish the outputs."""
    settings = Settings.from_env()
    report = collect(settings, load_bypasses())
    write_summary(report, settings)
    write_outputs(report, settings)
    print(
        f"Total {report.total} match(es); {len(report.gating)} gating, "
        f"{len(report.advisory)} advisory, {len(report.bypassed)} "
        f"bypassed (threshold '{settings.fail_on}')"
    )
    if settings.policy_declared:
        print(
            f"Provenance: {count_provenance(report, DIRECT)} declared, "
            f"{count_provenance(report, TRANSITIVE)} inherited "
            f"(source: {provenance_sources(report)})"
        )
    if not settings.gate_active:
        print(f"Findings do not block this run: {settings.gate_reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
