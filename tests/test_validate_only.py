#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline tests for validate-only mode.

validate-only runs the action's own input checks and nothing else, so
a workflow's early validation job cannot drift from the real scan.
These run the shipped ``Validate inputs`` script, extracted from
``action.yaml``, and check that every later step is guarded.

Like the other tests, this runs with a bare python3 and needs no
network, no Grype binary and no YAML library.
"""

from __future__ import annotations

import os
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUARD = "steps.validate.outputs.validate-only != 'true'"

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    """Record one result."""
    if condition:
        print(f"  ✅ {label}")
    else:
        print(f"  ❌ {label} {detail}")
        FAILURES.append(label)


def steps() -> list[tuple[str, list[str]]]:
    """Return each composite step's name and lines, in order."""
    lines = (ROOT / "action.yaml").read_text().splitlines()
    found: list[tuple[str, list[str]]] = []
    for line in lines[lines.index("  steps:") + 1 :]:
        named = re.fullmatch(r'    - name: "(.+)"', line)
        if named:
            found.append((named.group(1), []))
        elif found:
            found[-1][1].append(line)
    return found


def condition(body: list[str]) -> str:
    """Return a step's if: expression, folded onto one line."""
    for index, line in enumerate(body):
        if line.startswith("      if:"):
            text = line.split(":", 1)[1].strip()
            if text != ">-":
                return text
            folded = []
            for more in body[index + 1 :]:
                if not more.startswith("        "):
                    break
                folded.append(more.strip())
            return " ".join(folded)
    return ""


def extract_run(step_name: str) -> str:
    """Return the ``run:`` script of the named step."""
    body = dict(steps())[step_name]
    run_at = next(i for i, line in enumerate(body) if line.strip() == "run: |")
    out = []
    for line in body[run_at + 1 :]:
        if line.strip() and not line.startswith("        "):
            break
        out.append(line[8:])
    return "\n".join(out)


VALIDATE = extract_run("Validate inputs")

# Every input the workflow families pass, all valid, and no scan target.
POLICY_SET = {
    "INPUT_VALIDATE_ONLY": "true",
    "INPUT_SBOM": "",
    "INPUT_TARGET": "",
    "INPUT_FAIL_ON": "high",
    "INPUT_GATE_WHEN": "dependencies-changed",
    "INPUT_DEPENDENCIES_CHANGED": "",
    "INPUT_DEPENDENCY_POLICY": "declared",
    "INPUT_TRANSITIVE_FAIL_ON": "critical",
    "INPUT_DECLARED_SOURCE": "auto",
    "INPUT_REMEDIATION_WINDOW_DAYS": "30",
    "INPUT_REMEDIATION_WINDOW_START": "2026-01-01",
    "INPUT_SORT_BY": "risk",
    "INPUT_FORMATS": "json,table,sarif",
    "INPUT_PREFIX": "grype-results",
    "INPUT_MAX_ROWS": "50",
    "INPUT_MAX_AGE": "90",
    "INPUT_CACHE_DB": "restore-only",
    "INPUT_EXTRA_ARGS": "",
    "INPUT_RETENTION": "90",
    "INPUT_BYPASS_REPO": "example/bypasses",
}


def run(overrides: dict[str, str]) -> tuple[int, str, str]:
    """Run the validation script; return status, log and outputs."""
    with tempfile.TemporaryDirectory() as tmp:
        outputs = pathlib.Path(tmp) / "github-output"
        outputs.touch()
        env = {
            key: value
            for key, value in os.environ.items()
            if not key.startswith("INPUT_")
        }
        env.update(POLICY_SET)
        env.update(overrides)
        env.update(
            {
                "GITHUB_ACTION_PATH": str(ROOT),
                "GITHUB_OUTPUT": str(outputs),
                "PYTHON": sys.executable,
            }
        )
        result = subprocess.run(
            ["bash", "-c", VALIDATE],
            cwd=tmp,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        return (
            result.returncode,
            result.stdout + result.stderr,
            outputs.read_text(encoding="utf-8"),
        )


print("A valid policy set passes without a scan target")
rc, log, out = run({})
check("the step succeeds", rc == 0, log[-300:])
check("validated is set", "validated=true" in out.splitlines(), out)
check("the mode is published", "validate-only=true" in out.splitlines(), out)

print("A normal run is unchanged")
rc, log, out = run({"INPUT_VALIDATE_ONLY": "false", "INPUT_SBOM": "sbom.json"})
check("valid inputs pass", rc == 0, log[-300:])
check("the mode is published", "validate-only=false" in out.splitlines(), out)
rc, log, out = run({"INPUT_VALIDATE_ONLY": "false"})
check(
    "a missing target still fails",
    rc != 0 and "provide either 'sbom' or 'target'" in log,
    log[-300:],
)
check("validated is not set on failure", "validated=" not in out, out)

print("Mode validation")
for value in ("yes", "TRUE", ""):
    rc, log, out = run({"INPUT_VALIDATE_ONLY": value})
    check(
        f"validate-only '{value}' fails naming the input",
        rc != 0 and "::error::validate-only" in log,
        log[-300:],
    )
rc, log, out = run({"INPUT_SBOM": "sbom.json", "INPUT_TARGET": "dir:."})
check(
    "sbom and target together still fail",
    rc != 0 and "mutually exclusive" in log,
    log[-300:],
)
check(
    "a rejected input still publishes the mode",
    "validate-only=true" in out.splitlines(),
    out,
)

print("Each invalid value fails, naming its input")
INVALID = [
    ("fail-on", "INPUT_FAIL_ON", "catastrophic"),
    ("sort-by", "INPUT_SORT_BY", "alphabetical"),
    ("gate-when", "INPUT_GATE_WHEN", "sometimes"),
    ("dependencies-changed", "INPUT_DEPENDENCIES_CHANGED", "yes"),
    ("dependency-policy", "INPUT_DEPENDENCY_POLICY", "lenient"),
    ("transitive-fail-on", "INPUT_TRANSITIVE_FAIL_ON", "severe"),
    ("declared-source", "INPUT_DECLARED_SOURCE", "guess"),
    ("cache-db", "INPUT_CACHE_DB", "restore_only"),
    ("output-formats", "INPUT_FORMATS", "table,sarif"),
    ("output-prefix", "INPUT_PREFIX", "../escape"),
    ("summary-max-rows", "INPUT_MAX_ROWS", "lots"),
    ("bypass-max-age-days", "INPUT_MAX_AGE", "-1"),
    ("retention-days", "INPUT_RETENTION", "1.5"),
    ("bypass-repository", "INPUT_BYPASS_REPO", "not a repo"),
    ("remediation-window-days", "INPUT_REMEDIATION_WINDOW_DAYS", "-1"),
    ("remediation-window-start", "INPUT_REMEDIATION_WINDOW_START", "2999-01-01"),
    ("remediation-window-start", "INPUT_REMEDIATION_WINDOW_START", "0000-01-01"),
]
for name, variable, value in INVALID:
    rc, log, out = run({variable: value})
    check(
        f"{name} '{value}' fails naming the input",
        rc != 0 and f"::error::{name}" in log,
        log[-300:],
    )
    check(f"{name} '{value}' sets no validated", "validated=" not in out, out)


def escaped(value: str) -> str:
    """The form the step must print a hostile value in."""
    return (
        value.replace("%", "%25")
        .replace("\r", "%0D")
        .replace("\n", "%0A")
        .replace("##[", "##%5B")
    )


print("A rejected value cannot write a workflow command")
# The runner reads a log line starting '::' or '##[' as a command, so
# a caller-controlled value holding a line break could write one.
HOSTILE = (
    "medium\n::warning::injected",
    "medium\r::warning::injected",
    "medium\r\n::error::injected",
    "medium\n##[warning]injected",
    "medium%0A::warning::injected",
)
ECHOED = sorted({(name, variable) for name, variable, _ in INVALID})
MODES: tuple[tuple[str, dict[str, str]], ...] = (
    ("validate-only", {}),
    ("normal", {"INPUT_VALIDATE_ONLY": "false", "INPUT_SBOM": "sbom.json"}),
)
for mode, mode_env in MODES:
    for name, variable in ECHOED + [("validate-only", "INPUT_VALIDATE_ONLY")]:
        for value in HOSTILE:
            rc, log, out = run({**mode_env, variable: value})
            # The label reaches the workflow log too, so it shows the
            # value in the same escaped form the step prints.
            shown = f"'{escaped(value)}'"
            commands = [line for line in log.splitlines() if line.startswith("::")]
            check(
                f"{mode}: {name} {shown} writes only its own error",
                rc != 0
                and len(commands) == 1
                and commands[0].startswith(f"::error::{name}"),
                log[-300:],
            )
            check(f"{mode}: {name} {shown} writes no legacy marker", "##[" not in log)
            check(
                f"{mode}: {name} {shown} still reports the value",
                f"got '{escaped(value)}'" in log,
                log[-300:],
            )

print("Every later step is guarded")
ordered = steps()
# Validation needs the interpreter, so its setup is the one step
# allowed ahead of it, and it too must run in validate-only mode.
check("Python is set up first", ordered[0][0] == "Set up Python", ordered[0][0])
check("the Python setup is unguarded", condition(ordered[0][1]) == "", ordered[0][0])
check("validation runs next", ordered[1][0] == "Validate inputs", ordered[1][0])
check("validation is unguarded", condition(ordered[1][1]) == "", ordered[1][0])
for name, body in ordered[2:]:
    check(f"'{name}' is skipped in validate-only mode", GUARD in condition(body))

print("The validated output")
text = (ROOT / "action.yaml").read_text()
check(
    "is declared from the validation step",
    "value: ${{ steps.validate.outputs.validated }}" in text,
)

print()
if FAILURES:
    print(f"{len(FAILURES)} test(s) failed ❌")
    sys.exit(1)
print("All validate-only tests passed ✅")
