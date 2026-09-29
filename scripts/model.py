#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Shared types and field helpers for Grype report evaluation."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

SEVERITY_ORDER = ["negligible", "low", "medium", "high", "critical"]

# Gating modes. 'always' is the historical behaviour and stays the
# default, so upgrading the action cannot change a consumer's verdict.
GATE_ALWAYS = "always"
GATE_ON_CHANGE = "dependencies-changed"
SEVERITY_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "negligible": "⚪",
    "unknown": "❔",
}


def severity_rank(value: str) -> int:
    """Rank a severity; anything unrecognised sorts below negligible."""
    try:
        return SEVERITY_ORDER.index((value or "").lower())
    except ValueError:
        return -1


def read_change_signal(path: str) -> str:
    """Read the dependency-change sidecar; '' when unusable.

    Every failure mode collapses to '', which the caller treats as
    unresolved and therefore gating. A sidecar that cannot be read
    must never be the reason a finding stops blocking.
    """
    if not path or not os.path.exists(path):
        return ""
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        # ValueError covers JSONDecodeError and the UnicodeDecodeError
        # a non-UTF-8 file raises. A sidecar that cannot be decoded is
        # no more trustworthy than one that cannot be parsed, and
        # neither may abort evaluation before the summary is written.
        return ""
    if not isinstance(data, dict):
        return ""
    changed = data.get("changed")
    # Only a real boolean counts: a string 'false' from a hand-written
    # sidecar is ambiguous enough that gating is the safer reading.
    if isinstance(changed, bool):
        return "true" if changed else "false"
    return ""


def resolve_gate(gate_when: str, explicit: str, manifest: str) -> tuple[bool, str]:
    """Decide whether findings can block this run, and say why.

    The explicit input wins over the sidecar so a caller that already
    knows the answer never has to write a file.
    """
    if gate_when != GATE_ON_CHANGE:
        return True, "every scan gates"

    signal = (explicit or "").strip().lower()
    if signal not in ("true", "false"):
        signal = read_change_signal(manifest)

    if signal == "true":
        return True, "this change touched the dependency chain"
    if signal == "false":
        return False, "this change did not touch the dependency chain"
    # Fail closed. Unlike skipping a scan, where inconclusive detection
    # can safely mean 'scan anyway', an unresolved signal here would
    # downgrade real findings to warnings. Keep gating instead.
    return True, "the dependency-change signal was unavailable"


def emit(name: str, value: str) -> None:
    """Append a step output, using the multiline form when needed."""
    out_path = os.environ.get("GITHUB_OUTPUT")
    if not out_path:
        return
    with open(out_path, "a", encoding="utf-8") as handle:
        if "\n" in value:
            delimiter = "ghadelim_eval_end"
            while delimiter in value:
                delimiter += "x"
            handle.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
        else:
            handle.write(f"{name}={value}\n")


def cell(value: object) -> str:
    """Render a table cell, escaping pipes so columns cannot break."""
    text = "-" if value in (None, "", []) else str(value)
    return text.replace("|", "\\|").replace("\n", " ").strip() or "-"


def epss_percent(vulnerability: dict) -> str:
    """Format the EPSS probability as a percentage."""
    entries = vulnerability.get("epss") or []
    if not entries:
        return "-"
    score = entries[0].get("epss")
    if score in (None, ""):
        return "-"
    percent = float(score) * 100
    if percent == 0:
        return "0%"
    if percent < 0.01:
        return "<0.01%"
    return f"{round(percent, 2)}%"


def risk_value(vulnerability: dict) -> str:
    """Format Grype's combined risk score."""
    risk = vulnerability.get("risk")
    if risk is None:
        return "-"
    if isinstance(risk, (int, float)):
        return str(round(float(risk), 2))
    return str(risk)


def fix_text(vulnerability: dict) -> str:
    """Describe the fix: a version where one exists, else the state."""
    fix = vulnerability.get("fix") or {}
    versions = fix.get("versions") or []
    if versions:
        return ", ".join(versions)
    return (fix.get("state") or "").strip() or "-"


@dataclass
class Section:
    """Findings for one scanned artefact.

    ``rows`` holds every finding so the summary can report even when
    nothing gates; ``gating`` and ``bypassed`` are subsets of it.
    """

    artefact: str
    rows: list[dict] = field(default_factory=list)
    gating: list[dict] = field(default_factory=list)
    bypassed: list[dict] = field(default_factory=list)
    advisory: list[dict] = field(default_factory=list)


@dataclass
class Report:
    """Aggregate results across every scanned artefact."""

    sections: list[Section] = field(default_factory=list)
    severity_counts: dict[str, int] = field(default_factory=dict)
    report_files: list[str] = field(default_factory=list)
    total: int = 0

    @property
    def gating(self) -> list[dict]:
        """Findings that block the run."""
        return [row for section in self.sections for row in section.gating]

    @property
    def bypassed(self) -> list[dict]:
        """Findings suppressed by an approved bypass."""
        return [row for section in self.sections for row in section.bypassed]

    @property
    def advisory(self) -> list[dict]:
        """Findings that would block, reported as warnings instead."""
        return [row for section in self.sections for row in section.advisory]

    @property
    def rows(self) -> list[dict]:
        """Every finding across every artefact."""
        return [row for section in self.sections for row in section.rows]


@dataclass
class Settings:
    """Inputs that shape evaluation and rendering."""

    fail_on: str
    threshold: int | None
    label: str
    want_summary: bool
    summary_on_success: bool
    title: str
    max_rows: int
    bypass_repo: str
    only_fixed: bool
    gate_active: bool
    change_reason: str

    @property
    def can_gate(self) -> bool:
        """Whether a qualifying finding could block, before permit-fail.

        ``gate_active`` alone answers only the dependency-change
        question; a threshold of 'none' means nothing gates whatever
        that signal said. ``permit-fail`` is applied later still, by
        the verdict step, and is deliberately not modelled here.
        """
        return self.gate_active and self.threshold is not None

    @property
    def gate_reason(self) -> str:
        """Why findings did or did not block, matching ``can_gate``.

        The threshold answer comes first: with no severity gate
        configured nothing blocks whatever the change signal said, so
        reporting the signal there would explain the wrong thing.
        """
        if self.threshold is None:
            return "no severity threshold is configured"
        return self.change_reason

    @classmethod
    def from_env(cls) -> Settings:
        """Build settings from the action's environment."""
        fail_on = (os.environ.get("INPUT_FAIL_ON") or "medium").lower()
        try:
            max_rows = int(os.environ.get("INPUT_SUMMARY_MAX_ROWS", "50"))
        except ValueError:
            max_rows = 50
        gate_active, change_reason = resolve_gate(
            os.environ.get("INPUT_GATE_WHEN") or GATE_ALWAYS,
            os.environ.get("INPUT_DEPENDENCIES_CHANGED") or "",
            os.environ.get("INPUT_CHANGE_MANIFEST") or "",
        )
        return cls(
            fail_on=fail_on,
            threshold=severity_rank(fail_on) if fail_on != "none" else None,
            label=os.environ.get("INPUT_NAME") or "",
            want_summary=os.environ.get("INPUT_SUMMARY", "true") == "true",
            summary_on_success=(
                os.environ.get("INPUT_SUMMARY_ON_SUCCESS", "true") == "true"
            ),
            title=(os.environ.get("INPUT_SUMMARY_TITLE") or "Grype Vulnerability Scan"),
            max_rows=max_rows,
            bypass_repo=os.environ.get("BYPASS_REPO", ""),
            only_fixed=os.environ.get("INPUT_ONLY_FIXED", "false") == "true",
            gate_active=gate_active,
            change_reason=change_reason,
        )
