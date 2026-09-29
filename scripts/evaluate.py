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
    Report,
    Section,
    Settings,
    emit,
    epss_percent,
    fix_text,
    risk_value,
    severity_rank,
)
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
        for match in data.get("matches", []):
            row = build_row(match)
            report.total += 1
            report.severity_counts[row["severity"]] = (
                report.severity_counts.get(row["severity"], 0) + 1
            )
            # Keep every finding for reporting; the summary shows them
            # even when the threshold is 'none' or nothing gates.
            section.rows.append(row)

            if settings.threshold is None:
                continue
            if severity_rank(row["severity"]) < settings.threshold:
                continue
            # only-fixed narrows the GATE, not the report: an advisory
            # nobody can act on still appears in the table, but does
            # not block the run.
            if settings.only_fixed and not row["fixable"]:
                continue

            bypass = bypasses.get(str(row["id"]).upper())
            if bypass:
                row["bypass"] = bypass
                section.bypassed.append(row)
            elif settings.gate_active:
                section.gating.append(row)
            else:
                # Meets the threshold, but nothing blocks this run.
                # The finding still gets reported and annotated; only
                # the verdict changes.
                section.advisory.append(row)

        report.sections.append(section)
    return report


def write_outputs(report: Report, settings: Settings) -> None:
    """Publish the step outputs consumers act on."""
    emit("gating", "true" if report.gating else "false")
    emit("total-matches", str(report.total))
    emit("gating-matches", str(len(report.gating)))
    emit("advisory-matches", str(len(report.advisory)))
    emit("bypassed-matches", str(len(report.bypassed)))
    emit("gate-active", "true" if settings.can_gate else "false")
    emit("gate-reason", settings.gate_reason)
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
    if not settings.gate_active:
        print(f"Findings do not block this run: {settings.gate_reason}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
