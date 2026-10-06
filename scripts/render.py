#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Render Grype findings into the GitHub job step summary."""

from __future__ import annotations

import os

from scripts.model import (
    ADVISORY_INHERITED,
    SEVERITY_ICON,
    Report,
    Settings,
    cell,
    severity_rank,
)


def render_counts(report: Report, settings: Settings) -> list[str]:
    """Severity tally and the overall verdict."""
    if report.total == 0:
        return ["No vulnerabilities reported. ✅"]

    ordered = sorted(
        report.severity_counts.items(),
        key=lambda item: severity_rank(item[0]),
        reverse=True,
    )
    lines = [
        "  ".join(
            f"{SEVERITY_ICON.get(name, '❔')} {name.capitalize()}: {count}"
            for name, count in ordered
        ),
        "",
    ]
    if settings.threshold is None:
        lines.append("Reporting only; no severity gates this scan.")
    elif report.gating:
        lines.append(
            f"**{len(report.gating)} finding(s) at or above "
            f"`{settings.threshold_label}` block this run.**"
        )
    elif report.advisory and settings.gate_active:
        lines.append(
            f"**{len(report.advisory)} finding(s) at or above "
            f"`{settings.threshold_label}` reported as warnings.**"
        )
    elif report.advisory:
        lines.append(
            f"**{len(report.advisory)} finding(s) at or above "
            f"`{settings.threshold_label}` reported as warnings.** "
            f"They do not block this run because "
            f"{settings.gate_reason}."
        )
    else:
        lines.append(f"No findings at or above `{settings.threshold_label}`. ✅")

    if report.gating and report.advisory:
        lines.append(
            f"A further {len(report.advisory)} finding(s) are reported as warnings."
        )
    return lines


def advisory_heading(rows: list[dict]) -> str:
    """Why this table is reported rather than blocking the run.

    A row can land here for more than one reason: an unarmed gate, an
    inherited package, or a finding no bump can clear. Provenance
    alone does not settle it, since only-fixed can demote an inherited
    finding that did clear its own threshold. Name the cause only when
    every row shares it.
    """
    if rows and all(row.get("advisory_reason") == ADVISORY_INHERITED for row in rows):
        return "Inherited dependencies; reported as warnings"
    return "Reported as warnings; not blocking this run"


def render_findings_table(rows: list[dict], max_rows: int) -> list[str]:
    """The main findings table, worst first."""
    lines = [
        "| Severity | Package | Version | Type | Vulnerability | Fix | EPSS | Risk |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    ranked = sorted(
        rows,
        key=lambda row: (
            -severity_rank(row["severity"]),
            -row["risk_sort"],
            str(row["package"]),
        ),
    )
    for row in ranked[:max_rows]:
        icon = SEVERITY_ICON.get(row["severity"], "❔")
        lines.append(
            "| "
            + " | ".join(
                [
                    f"{icon} {cell(row['severity'].capitalize())}",
                    cell(row["package"]),
                    cell(row["version"]),
                    cell(row["type"]),
                    cell(row["id"]),
                    cell(row["fix"]),
                    cell(row["epss"]),
                    cell(row["risk"]),
                ]
            )
            + " |"
        )
    if len(ranked) > max_rows:
        lines.extend(
            [
                "",
                f"_Showing {max_rows} of {len(ranked)} findings; "
                "the full report is attached to this run._",
            ]
        )
    lines.append("")
    return lines


def render_bypassed(rows: list[dict]) -> list[str]:
    """Collapsed list of suppressed findings, linking each issue."""
    lines = [
        f"<details><summary>Suppressed by an approved bypass ({len(rows)})</summary>",
        "",
        "| Vulnerability | Package | Severity | Bypass |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        bypass = row.get("bypass", {})
        reference = (
            f"[#{bypass.get('issue')}]({bypass.get('url')})"
            if bypass.get("url")
            else f"#{bypass.get('issue')}"
        )
        lines.append(
            "| "
            + " | ".join(
                [
                    cell(row["id"]),
                    cell(row["package"]),
                    cell(row["severity"].capitalize()),
                    reference,
                ]
            )
            + " |"
        )
    lines.extend(["", "</details>", ""])
    return lines


def render_summary(report: Report, settings: Settings) -> str:
    """Assemble the whole step summary section."""
    heading = f"## {settings.title}" + (f": {settings.label}" if settings.label else "")
    lines = [heading, ""]
    lines.extend(render_counts(report, settings))
    lines.append("")

    multiple = len(report.sections) > 1
    for section in report.sections:
        if not section.rows:
            continue
        if multiple:
            lines.extend([f"### {section.artefact}", ""])
        if section.gating:
            lines.extend(render_findings_table(section.gating, settings.max_rows))
        if section.advisory:
            lines.append(f"_{advisory_heading(section.advisory)}:_")
            lines.append("")
            lines.extend(render_findings_table(section.advisory, settings.max_rows))
        if not section.gating and not section.advisory:
            # Nothing gates, but the findings still belong on the run
            # page: reporting-only scans and sub-threshold results are
            # exactly when someone wants to see what turned up.
            lines.append("_Findings below the gating threshold:_")
            lines.append("")
            lines.extend(render_findings_table(section.rows, settings.max_rows))
        if section.bypassed:
            lines.extend(render_bypassed(section.bypassed))

    if report.advisory and not settings.gate_active:
        lines.extend(
            [
                "A change that touches the dependency chain re-arms "
                "the gate, so these findings are worth clearing before "
                "the next dependency update rather than after it.",
                "",
            ]
        )
    elif report.advisory and all(
        row.get("advisory_reason") == ADVISORY_INHERITED for row in report.advisory
    ):
        lines.extend(
            [
                "These findings affect packages the project does not "
                "declare. Clearing one means an upstream fix, or "
                "replacing the dependency that pulls it in.",
                "",
            ]
        )

    if report.gating:
        lines.extend(
            [
                "To unblock a finding that has no available fix, open an "
                "issue titled `BYPASS: <VULN-ID>` in "
                f"`{settings.bypass_repo}` and have a maintainer apply "
                "the bypass label.",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def write_summary(report: Report, settings: Settings) -> None:
    """Write the summary when there is something worth showing."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not settings.want_summary or not path:
        return
    interesting = report.gating or report.advisory or report.bypassed
    if not interesting and not settings.summary_on_success:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(render_summary(report, settings))
