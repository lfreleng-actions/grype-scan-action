#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline tests for the remediation window.

The window bounds how long a fixable finding may stay a warning in a
run whose change left the dependency chain alone. These cases cover
each rule in turn, the input validation, and the invariant that the
window only ever adds gating to a run.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
# The entry point the action uses: the helpers run through the launcher
# under -I, as in action.yaml.
LAUNCH = ROOT / "scripts" / "launch.py"
sys.path.insert(0, str(ROOT))

from scripts.evaluate import collect  # noqa: E402
from scripts.model import (  # noqa: E402
    ADVISORY_IN_WINDOW,
    ADVISORY_UNARMED,
    SEVERITY_ORDER,
    Settings,
)
from scripts.window import deadline, fix_date, parse_days, parse_start  # noqa: E402

FAILURES: list[str] = []
TODAY = dt.date(2026, 6, 15)


def check(label: str, condition: bool, detail: object = "") -> None:
    """Record one result."""
    if condition:
        print(f"  ✅ {label}")
    else:
        print(f"  ❌ {label} {detail}")
        FAILURES.append(label)


def raises(func, *args) -> bool:
    """Whether calling func with args raises ValueError."""
    try:
        func(*args)
    except ValueError:
        return True
    return False


def match(
    package: str,
    vuln: str,
    severity: str = "Critical",
    fixed: bool = True,
    dates: list[str] | None = None,
) -> dict:
    """A synthetic Grype match, with fix availability dates."""
    fix: dict = (
        {"versions": ["9.9.9"], "state": "fixed"}
        if fixed
        else {"versions": [], "state": "not-fixed"}
    )
    if dates is not None:
        fix["available"] = [
            {"version": "9.9.9", "date": date, "kind": "first-observed"}
            for date in dates
        ]
    return {
        "vulnerability": {"id": vuln, "severity": severity, "fix": fix},
        "artifact": {"name": package, "version": "1.0.0", "type": "npm"},
    }


BASE_ENV = {
    "INPUT_FAIL_ON": "high",
    "INPUT_NAME": "",
    "INPUT_SUMMARY": "true",
    "INPUT_SUMMARY_TITLE": "Grype Vulnerability Scan",
    "INPUT_SUMMARY_MAX_ROWS": "50",
    "INPUT_SUMMARY_ON_SUCCESS": "true",
    "INPUT_GATE_WHEN": "dependencies-changed",
    "INPUT_DEPENDENCIES_CHANGED": "false",
    "INPUT_CHANGE_MANIFEST": "",
    "INPUT_DEPENDENCY_POLICY": "all",
    "INPUT_TRANSITIVE_FAIL_ON": "none",
    "INPUT_DECLARED_SOURCE": "none",
    "INPUT_DECLARED_DEPENDENCIES": "",
    "INPUT_ONLY_FIXED": "false",
    "INPUT_REMEDIATION_WINDOW_DAYS": "",
    "INPUT_REMEDIATION_WINDOW_START": "",
    "BYPASSES": "[]",
    "BYPASS_REPO": "example/repo",
}


def evaluate(matches: list[dict], **env: str):
    """Route matches through the real collector on a fixed date."""
    with tempfile.TemporaryDirectory() as tmp:
        report = pathlib.Path(tmp) / "report.json"
        report.write_text(json.dumps({"matches": matches}), encoding="utf-8")
        saved = dict(os.environ)
        try:
            os.environ.update(BASE_ENV)
            os.environ.update(env)
            os.environ["MANIFEST"] = f"{report}|{report}"
            # Every start date used here precedes TODAY, which is in
            # the past, so from_env accepts them against the real date.
            settings = dataclasses.replace(Settings.from_env(), today=TODAY)
            return settings, collect(settings, {})
        finally:
            os.environ.clear()
            os.environ.update(saved)


def ids(rows: list[dict]) -> set[str]:
    """The vulnerability IDs in a bucket."""
    return {str(row["id"]) for row in rows}


WINDOW = {"INPUT_REMEDIATION_WINDOW_DAYS": "14"}

print("input validation")
check("empty days turns the window off", parse_days("") is None)
check("whitespace days turns the window off", parse_days("  ") is None)
check("zero days is valid", parse_days("0") == 0)
check("a whole number is accepted", parse_days(" 14 ") == 14)
for bad in ("-1", "1.5", "two", "14d", "+3", "١٤"):
    check(f"days '{bad}' is rejected", raises(parse_days, bad))
check("empty start is unset", parse_start("", TODAY) is None)
check(
    "a past start is accepted", parse_start("2026-01-31", TODAY) == dt.date(2026, 1, 31)
)
check("today is accepted as a start", parse_start("2026-06-15", TODAY) == TODAY)
for bad in ("2026-13-01", "2026-02-30", "2026/01/01", "20260101", "2026-1-1", "soon"):
    check(f"start '{bad}' is rejected", raises(parse_start, bad, TODAY))
check("a future start is rejected", raises(parse_start, "2026-06-16", TODAY))

print("fix dates")
check(
    "earliest date of any kind wins",
    fix_date(
        match("a", "X", dates=["2026-03-01", "2026-01-02T10:00:00Z"])["vulnerability"]
    )
    == dt.date(2026, 1, 2),
)
check(
    "no available list has no date", fix_date(match("a", "X")["vulnerability"]) is None
)
check(
    "unreadable dates are skipped",
    fix_date(match("a", "X", dates=["garbage", ""])["vulnerability"]) is None,
)

print("deadlines")
check("no fix starts no clock", deadline(False, TODAY, 14, None) is None)
check(
    "fixed with no date and no floor arms at once",
    deadline(True, None, 14, None) == dt.date.min,
)
check(
    "fixed with no date uses the floor",
    deadline(True, None, 14, dt.date(2026, 6, 10)) == dt.date(2026, 6, 24),
)
check(
    "the later of fix date and floor starts the clock",
    deadline(True, dt.date(2026, 1, 1), 14, dt.date(2026, 6, 10))
    == dt.date(2026, 6, 24)
    and deadline(True, dt.date(2026, 6, 12), 14, dt.date(2026, 6, 1))
    == dt.date(2026, 6, 26),
)
check(
    "a huge window does not overflow",
    deadline(True, TODAY, 10**12, None) == dt.date.max,
)

print("rule 1: the window applies only to unarmed runs")
OLD = [match("a", "CVE-OLD", dates=["2026-01-01"])]
_, report = evaluate(OLD)
check("without the window an unarmed run warns", not report.gating, report.gating)
for label, env in (
    ("gate-when always", {"INPUT_GATE_WHEN": "always"}),
    ("dependencies changed", {"INPUT_DEPENDENCIES_CHANGED": "true"}),
    ("signal unresolved", {"INPUT_DEPENDENCIES_CHANGED": ""}),
):
    plain_settings, plain = evaluate(OLD, **env)
    window_settings, windowed = evaluate(OLD, **env, **WINDOW)
    check(
        f"{label}: the window changes nothing",
        ids(plain.gating) == ids(windowed.gating) == {"CVE-OLD"}
        and not window_settings.window_applies,
    )
fresh = [match("a", "CVE-NEW", dates=["2026-06-14"])]
_, report = evaluate(fresh, INPUT_GATE_WHEN="always", **WINDOW)
check("an armed run gates a fresh fix regardless", ids(report.gating) == {"CVE-NEW"})

print("rules 2 and 3: an expired window gates")
settings, report = evaluate(OLD, **WINDOW)
check("a fix older than the window gates", ids(report.gating) == {"CVE-OLD"})
check("the run reports it can gate", settings.can_gate)
check(
    "the reason names the window",
    "14 day(s)" in settings.gate_reason,
    settings.gate_reason,
)
_, report = evaluate([match("a", "CVE-EDGE", dates=["2026-06-01"])], **WINDOW)
check("the deadline day itself gates", ids(report.gating) == {"CVE-EDGE"})
_, report = evaluate(
    [match("a", "CVE-LOW", severity="Low", dates=["2026-01-01"])], **WINDOW
)
check("an expired finding below fail-on still does not gate", not report.gating)
bypass = {"CVE-OLD": {"id": "CVE-OLD", "issue": 1, "url": ""}}
settings, _ = evaluate(OLD, **WINDOW)
with tempfile.TemporaryDirectory() as tmp:
    report_file = pathlib.Path(tmp) / "report.json"
    report_file.write_text(json.dumps({"matches": OLD}), encoding="utf-8")
    saved = dict(os.environ)
    try:
        os.environ["MANIFEST"] = f"{report_file}|{report_file}"
        report = collect(settings, bypass)
    finally:
        os.environ.clear()
        os.environ.update(saved)
check(
    "an approved bypass still applies",
    ids(report.bypassed) == {"CVE-OLD"} and not report.gating,
)

print("rule 4: a finding in its window warns")
_, report = evaluate([match("a", "CVE-IN", dates=["2026-06-02"])], **WINDOW)
check("a fix inside the window does not gate", not report.gating)
row = report.advisory[0] if report.advisory else {}
check(
    "it is advisory as in-window", row.get("advisory_reason") == ADVISORY_IN_WINDOW, row
)
check("it carries its deadline", row.get("gates_from") == "2026-06-16", row)

print("rule 2: the start-date floor")
_, report = evaluate(OLD, INPUT_REMEDIATION_WINDOW_START="2026-06-10", **WINDOW)
check("an old fix waits for the floor", not report.gating)
check(
    "its deadline counts from the floor",
    bool(report.advisory) and report.advisory[0].get("gates_from") == "2026-06-24",
    report.advisory,
)
_, report = evaluate(OLD, INPUT_REMEDIATION_WINDOW_START="2026-05-01", **WINDOW)
check("an old floor still lets the window expire", ids(report.gating) == {"CVE-OLD"})

print("rule 5: no fix never starts a clock")
_, report = evaluate(
    [match("a", "CVE-NOFIX", fixed=False)], INPUT_REMEDIATION_WINDOW_DAYS="0"
)
check("an unfixable finding never gates through the window", not report.gating)
row = report.advisory[0] if report.advisory else {}
check("it stays unarmed", row.get("advisory_reason") == ADVISORY_UNARMED, row)

print("rule 6: a fix with no date")
_, report = evaluate([match("a", "CVE-NODATE")], **WINDOW)
check("without a floor it gates at once", ids(report.gating) == {"CVE-NODATE"})
_, report = evaluate(
    [match("a", "CVE-NODATE")], INPUT_REMEDIATION_WINDOW_START="2026-06-10", **WINDOW
)
check("with a floor it waits for the window", not report.gating)
check(
    "and its deadline counts from the floor",
    bool(report.advisory) and report.advisory[0].get("gates_from") == "2026-06-24",
    report.advisory,
)

print("invalid input reaching the evaluator fails closed")
settings, report = evaluate(fresh, INPUT_REMEDIATION_WINDOW_DAYS="soon")
check("a malformed day count reads as a zero-day window", settings.window_days == 0)
check("so a fixed finding gates", ids(report.gating) == {"CVE-NEW"})

print("invariant: the window only adds gating")
corpus = [
    match(f"p{i}", f"CVE-{sev}-{fixed}-{i}", severity=sev, fixed=fixed, dates=dates)
    for sev in SEVERITY_ORDER
    for fixed in (True, False)
    for i, dates in enumerate(
        (None, [], ["2026-01-01"], ["2026-06-14"], ["2026-06-15"], ["bad"])
    )
]
violations: list[str] = []
added = 0
combos = 0
for gate_when, changed in (
    ("always", ""),
    ("dependencies-changed", "true"),
    ("dependencies-changed", "false"),
    ("dependencies-changed", ""),
):
    for only_fixed in ("true", "false"):
        for fail_on in ("low", "high", "none"):
            base = {
                "INPUT_GATE_WHEN": gate_when,
                "INPUT_DEPENDENCIES_CHANGED": changed,
                "INPUT_ONLY_FIXED": only_fixed,
                "INPUT_FAIL_ON": fail_on,
            }
            _, without = evaluate(corpus, **base)
            for days in ("0", "1", "14", "3650"):
                for start in ("", "2026-01-01", "2026-06-15"):
                    combos += 1
                    _, with_window = evaluate(
                        corpus,
                        **base,
                        INPUT_REMEDIATION_WINDOW_DAYS=days,
                        INPUT_REMEDIATION_WINDOW_START=start,
                    )
                    lost = ids(without.gating) - ids(with_window.gating)
                    if lost:
                        violations.append(f"{base} {days}/{start}: {sorted(lost)}")
                    added += len(ids(with_window.gating) - ids(without.gating))
check("every combination exercised", combos == 288, combos)
check("no finding stops gating when the window is set", not violations, violations[:3])
check("the window does add gating, so the check is not vacuous", added > 0, added)

print("reporting")
today = dt.datetime.now(dt.timezone.utc).date()
recent = (today - dt.timedelta(days=2)).isoformat()
expected = (today + dt.timedelta(days=12)).isoformat()
with tempfile.TemporaryDirectory() as tmp:
    report_file = pathlib.Path(tmp) / "report.json"
    report_file.write_text(
        json.dumps(
            {
                "matches": [
                    match("a", "CVE-IN", dates=[recent]),
                    match("b", "CVE-OLD", dates=["2020-01-01"]),
                    match("c", "CVE-NOFIX", fixed=False),
                ]
            }
        ),
        encoding="utf-8",
    )
    out_file = pathlib.Path(tmp) / "out"
    summary_file = pathlib.Path(tmp) / "summary"
    out_file.touch()
    summary_file.touch()
    env = dict(os.environ)
    env.update(BASE_ENV)
    env.update(
        {
            "MANIFEST": f"{report_file}|{report_file}",
            "INPUT_REMEDIATION_WINDOW_DAYS": "14",
            "GITHUB_OUTPUT": str(out_file),
            "GITHUB_STEP_SUMMARY": str(summary_file),
        }
    )
    result = subprocess.run(
        [sys.executable, "-I", str(LAUNCH), "evaluate"],
        cwd=str(ROOT),
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    outputs = dict(
        line.split("=", 1)
        for line in out_file.read_text(encoding="utf-8").splitlines()
        if "=" in line and "<<" not in line
    )
    summary = summary_file.read_text(encoding="utf-8")
check("the expired finding gates", outputs.get("gating-matches") == "1", outputs)
check("both others warn", outputs.get("advisory-matches") == "2", outputs)
check(
    "window-matches counts the in-window finding",
    outputs.get("window-matches") == "1",
    outputs,
)
check(
    "window-next-deadline names its deadline",
    outputs.get("window-next-deadline") == expected,
    outputs,
)
check(
    "gate-active reports the run can gate",
    outputs.get("gate-active") == "true",
    outputs,
)
check("the summary marks the deadline", f"gates from {expected}" in summary, summary)
check(
    "an annotation names the deadline",
    f"::warning::CVE-IN in a 1.0.0 is within its remediation window and gates from {expected}"
    in result.stdout,
    result.stdout,
)
check("no annotation for the unfixable finding", "CVE-NOFIX" not in result.stdout)

env["INPUT_REMEDIATION_WINDOW_DAYS"] = ""
with tempfile.TemporaryDirectory() as tmp:
    report_file = pathlib.Path(tmp) / "report.json"
    report_file.write_text(json.dumps({"matches": []}), encoding="utf-8")
    out_file = pathlib.Path(tmp) / "out"
    out_file.touch()
    env.update(
        {
            "MANIFEST": f"{report_file}|{report_file}",
            "GITHUB_OUTPUT": str(out_file),
            "GITHUB_STEP_SUMMARY": str(pathlib.Path(tmp) / "summary"),
        }
    )
    subprocess.run(
        [sys.executable, "-I", str(LAUNCH), "evaluate"],
        cwd=str(ROOT),
        env=env,
        check=True,
        capture_output=True,
    )
    raw = out_file.read_text(encoding="utf-8")
check(
    "the window outputs are zero and empty when off",
    "window-matches=0\n" in raw and "window-next-deadline=\n" in raw,
    raw,
)

print("validation entry point")
for label, days, start, code in (
    ("valid inputs pass", "14", "", 0),
    ("both empty pass", "", "", 0),
    ("a negative day count fails", "-1", "", 1),
    ("a malformed date fails", "14", "2026-02-30", 1),
    ("a future date fails", "14", (today + dt.timedelta(days=1)).isoformat(), 1),
):
    env = dict(os.environ)
    env.update(
        {
            "INPUT_REMEDIATION_WINDOW_DAYS": days,
            "INPUT_REMEDIATION_WINDOW_START": start,
        }
    )
    result = subprocess.run(
        [sys.executable, "-I", str(LAUNCH), "window"],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
    )
    check(
        label,
        result.returncode == code and (code == 0 or "::error::" in result.stdout),
        result.stdout,
    )

print()
if FAILURES:
    print(f"{len(FAILURES)} test(s) failed ❌")
    sys.exit(1)
print("All remediation window tests passed ✅")
