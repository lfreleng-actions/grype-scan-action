#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline tests: the workspace cannot replace the action's Python.

The action's steps run in ``$GITHUB_WORKSPACE``, which can hold a
checkout the caller does not trust. These tests run the shipped step
scripts, extracted from ``action.yaml``, from a workspace planted with
a ``scripts/`` package of its own and with a module for every standard
module name. Each planted module records itself in a marker file and
stops the run, so a step that loads one fails here however the rest
of it behaves.

The steps run the interpreter the action set up, named by $PYTHON,
so a python3 planted on PATH must never run either.

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

FAILURES: list[str] = []

# Every standard module name, planted in the workspace. Those Python
# loads before it reads sys.path (os, sys, io and the like) cannot be
# replaced; the rest cover whatever the helpers import, including
# lazily, so a later import cannot slip past this test.
PLANTED_STDLIB = sorted(sys.stdlib_module_names)

PLANTED_SOURCE = (
    "import os\n"
    "with open(os.environ['PLANT_MARKER'], 'a', encoding='utf-8') as fh:\n"
    "    fh.write(__name__ + '\\n')\n"
    "raise SystemExit(97)\n"
)


def check(label: str, condition: bool, detail: object = "") -> None:
    if condition:
        print(f"  ✅ {label}")
    else:
        print(f"  ❌ {label} {detail}")
        FAILURES.append(label)


def extract_run(step_name: str) -> str:
    """Return the ``run:`` script of the named step in action.yaml."""
    lines = (ROOT / "action.yaml").read_text().splitlines()
    start = next(
        i for i, line in enumerate(lines) if line.strip() == f'- name: "{step_name}"'
    )
    run_at = next(
        i for i in range(start, len(lines)) if lines[i].strip() in ("run: |", "run: |-")
    )
    body_indent = len(lines[run_at + 1]) - len(lines[run_at + 1].lstrip())
    out: list[str] = []
    for line in lines[run_at + 1 :]:
        if line.strip() and (len(line) - len(line.lstrip())) < body_indent:
            break
        out.append(line[body_indent:])
    return "\n".join(out)


def plant(workspace: pathlib.Path) -> None:
    """Fill a workspace with modules that must never be imported."""
    package = workspace / "scripts"
    package.mkdir()
    for name in ("__init__", "collect_bypasses", "evaluate", "model", "launch"):
        (package / f"{name}.py").write_text(PLANTED_SOURCE, encoding="utf-8")
    for name in PLANTED_STDLIB:
        (workspace / f"{name}.py").write_text(PLANTED_SOURCE, encoding="utf-8")


def run_step(step_name: str, extra_env: dict[str, str]) -> tuple[int, str, str, str]:
    """Run a step from a planted workspace.

    Returns the exit status, the combined log, the step's outputs and
    whatever the planted modules recorded.
    """
    with tempfile.TemporaryDirectory() as tmp:
        base = pathlib.Path(tmp)
        workspace = base / "workspace"
        workspace.mkdir()
        plant(workspace)
        marker = base / "planted-ran"
        # A python3 first on PATH that records itself and fails, as a
        # caller's earlier step could leave one; the steps must not
        # resolve their interpreter there.
        shim = base / "bin"
        shim.mkdir()
        planted = shim / "python3"
        planted.write_text(
            f"#!/bin/sh\necho PATH-python3 >> '{marker}'\nexit 97\n",
            encoding="utf-8",
        )
        planted.chmod(0o755)
        outputs = base / "github-output"
        summary = base / "step-summary"
        outputs.touch()
        summary.touch()
        env = {
            key: value
            for key, value in os.environ.items()
            # No proxy: the network case must stay on the host.
            if not key.startswith("PYTHON") and not key.lower().endswith("_proxy")
        }
        env.update(
            {
                "PATH": f"{shim}{os.pathsep}{os.environ.get('PATH', '')}",
                "GITHUB_ACTION_PATH": str(ROOT),
                "GITHUB_WORKSPACE": str(workspace),
                "GITHUB_OUTPUT": str(outputs),
                "GITHUB_STEP_SUMMARY": str(summary),
                "PLANT_MARKER": str(marker),
                # What the setup step's python-path output supplies;
                # this interpreter, so 'python3.11 tests/...' tests 3.11.
                "PYTHON": sys.executable,
                # A PYTHONPATH naming the workspace is what the old
                # invocation amounted to; -I must ignore it.
                "PYTHONPATH": str(workspace),
            }
        )
        env.update(extra_env)
        result = subprocess.run(
            ["bash", "-c", extract_run(step_name)],
            cwd=str(workspace),
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        ran = marker.read_text(encoding="utf-8") if marker.exists() else ""
        return (
            result.returncode,
            result.stdout + result.stderr,
            outputs.read_text(encoding="utf-8"),
            ran,
        )


print("Bypass collection ignores planted modules")
rc, log, out, ran = run_step(
    "Collect approved bypasses",
    # No repository: the helper emits an empty list without any
    # network call.
    {"BYPASS_REPO": "", "BYPASS_LABEL": "cve-bypass", "GH_TOKEN": ""},
)
check("no planted module ran", ran == "", ran.split())
check("the step succeeds", rc == 0, log[-300:])
check("the real helper wrote its output", "bypasses=[]" in out, out)

print("Bypass lookups ignore planted modules")
rc, log, out, ran = run_step(
    "Collect approved bypasses",
    # A closed loopback port: the lookup runs, and with it every lazy
    # import on the network path, then fails without leaving the host.
    {
        "BYPASS_REPO": "example/repo",
        "BYPASS_LABEL": "cve-bypass",
        "BYPASS_PREFIX": "BYPASS:",
        "BYPASS_MAX_AGE": "90",
        "GH_TOKEN": "",
        "API_URL": "http://127.0.0.1:9",
    },
)
check("no planted module ran", ran == "", ran.split())
check("the step succeeds", rc == 0, log[-300:])
check("the lookup was attempted", "Could not read bypass issues" in log, log[-300:])
check("no bypasses result from a failed lookup", "bypasses=[]" in out, out)

VALID_INPUTS = {
    # The action's defaults, plus an SBOM so the scan target check passes.
    "INPUT_SBOM": "sbom.json",
    "INPUT_TARGET": "",
    "INPUT_FAIL_ON": "medium",
    "INPUT_GATE_WHEN": "always",
    "INPUT_DEPENDENCIES_CHANGED": "",
    "INPUT_DEPENDENCY_POLICY": "all",
    "INPUT_TRANSITIVE_FAIL_ON": "none",
    "INPUT_DECLARED_SOURCE": "auto",
    "INPUT_REMEDIATION_WINDOW_DAYS": "14",
    "INPUT_REMEDIATION_WINDOW_START": "",
    "INPUT_SORT_BY": "risk",
    "INPUT_FORMATS": "json,table,sarif",
    "INPUT_PREFIX": "grype-results",
    "INPUT_MAX_ROWS": "50",
    "INPUT_MAX_AGE": "90",
    "INPUT_CACHE_DB": "true",
    "INPUT_EXTRA_ARGS": "",
    "INPUT_RETENTION": "90",
    "INPUT_BYPASS_REPO": "",
}

print("Input validation ignores planted modules")
rc, log, out, ran = run_step("Validate inputs", VALID_INPUTS)
check("no planted module ran", ran == "", ran.split())
check("valid inputs pass", rc == 0 and "Inputs validated" in log, log[-300:])

rc, log, out, ran = run_step(
    "Validate inputs", {**VALID_INPUTS, "INPUT_REMEDIATION_WINDOW_DAYS": "-1"}
)
check("no planted module ran on bad input", ran == "", ran.split())
# The real validator, not a planted stand-in, must be what rejects it.
check(
    "the real validator rejects a bad window",
    rc != 0 and "::error::" in log and "remediation-window-days" in log,
    log[-300:],
)

print("Evaluation ignores planted modules")
rc, log, out, ran = run_step(
    "Evaluate findings",
    {
        "MANIFEST": "",
        "BYPASSES": "[]",
        "INPUT_NAME": "",
        "INPUT_FAIL_ON": "high",
        "INPUT_SUMMARY": "true",
        "INPUT_SUMMARY_TITLE": "Grype",
        "INPUT_SUMMARY_MAX_ROWS": "50",
        "INPUT_SUMMARY_ON_SUCCESS": "true",
        "INPUT_ONLY_FIXED": "false",
        "INPUT_GATE_WHEN": "always",
        "INPUT_DEPENDENCIES_CHANGED": "",
        "INPUT_CHANGE_MANIFEST": "",
        "INPUT_DEPENDENCY_POLICY": "all",
        "INPUT_TRANSITIVE_FAIL_ON": "none",
        "INPUT_DECLARED_SOURCE": "auto",
        "INPUT_DECLARED_DEPENDENCIES": "",
        "BYPASS_REPO": "example/repo",
    },
)
check("no planted module ran", ran == "", ran.split())
check("the step succeeds", rc == 0, log[-300:])
check("the real helper wrote its outputs", "total-matches=0" in out, out[-300:])

print("The launcher")
result = subprocess.run(
    [sys.executable, "-I", str(ROOT / "scripts" / "launch.py"), "not_a_helper"],
    capture_output=True,
    text=True,
    check=False,
)
check("refuses a helper it does not know", result.returncode == 2, result.stderr)

# Every interpreter the action starts must be the one it set up, and
# isolated, so a helper added later cannot reopen either hole. This is
# a tripwire for the forms action.yaml writes, not a shell parser: an
# interpreter reached through another variable ("$py") or a script's
# shebang is not seen.
print("Every Python in action.yaml is the action's own, run isolated")
INTERPRETER = re.compile(r"(?:^|[\s;&|(`/\"'])python3?(?:\.\d+)?(?=[\s<\"']|$)")
OWN_INTERPRETER = re.compile(r"\"\$\{?PYTHON\}?\"")


def isolated(words: list[str]) -> bool:
    """True when -I comes among the options, before the program."""
    skip = False
    for word in words:
        if skip:
            skip = False
            continue
        if word == "--":
            return False
        if word.startswith("--"):
            continue
        if not word.startswith("-") or word == "-":
            return False
        for position, letter in enumerate(word[1:], start=1):
            if letter == "I":
                return True
            if letter in "mc":
                return False
            if letter in "WX":
                skip = position == len(word) - 1
                break
    return False


for words, expected in (
    (["-I", "x.py"], True),
    (["-Ic", "pass"], True),
    (["-u", "-I", "x.py"], True),
    (["-W", "ignore", "-I", "-m", "x"], True),
    (["-m", "x", "-I"], False),
    (["-c", "-I"], False),
    (["x.py", "-I"], False),
    (["--", "-I"], False),
    ([], False),
):
    check(
        f"the check reads {words} as isolated={expected}", isolated(words) is expected
    )

own_runs = 0
for number, line in enumerate((ROOT / "action.yaml").read_text().splitlines(), 1):
    if line.lstrip().startswith("#"):
        continue
    if INTERPRETER.search(line):
        check(f"line {number} runs no Python from PATH", False, line.strip())
    for match in OWN_INTERPRETER.finditer(line):
        own_runs += 1
        rest = line[match.end() :].split()
        if rest and rest[-1] == "\\":
            rest.pop()
        check(f"line {number} passes -I", isolated(rest), line.strip())
check("the tripwire found the action's interpreter", own_runs > 0, own_runs)

print()
if FAILURES:
    print(f"{len(FAILURES)} test(s) failed ❌")
    sys.exit(1)
print("All isolation tests passed ✅")
