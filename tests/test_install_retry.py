#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline tests for the retried Grype install.

The upstream installer downloads once, so ``action.yaml`` unrolls the
install into three attempts with waits between them and resolves the
command from whichever attempt succeeded. These check that structure
in ``action.yaml`` and run the shipped resolver script.

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
ATTEMPTS = ("grype-1", "grype-2", "grype-3")

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


def field(body: list[str], key: str) -> str:
    """Return a step's top-level scalar, a folded one joined up."""
    for index, line in enumerate(body):
        if line.startswith(f"      {key}:"):
            text = line.split(":", 1)[1].split("  #", 1)[0].strip()
            if text != ">-":
                return text
            folded = []
            for more in body[index + 1 :]:
                if not more.startswith("        "):
                    break
                folded.append(more.strip())
            return " ".join(folded)
    return ""


def with_block(body: list[str]) -> list[str]:
    """Return a step's ``with:`` entries, comments dropped."""
    start = body.index("      with:")
    out = []
    for line in body[start + 1 :]:
        if line.strip() and not line.startswith("        "):
            break
        if line.strip() and not line.strip().startswith("#"):
            out.append(line.strip())
    return out


def run_script(body: list[str]) -> str:
    """Return a step's ``run:`` script."""
    run_at = next(i for i, line in enumerate(body) if line.strip() == "run: |")
    out = []
    for line in body[run_at + 1 :]:
        if line.strip() and not line.startswith("        "):
            break
        out.append(line[8:])
    return "\n".join(out)


ORDERED = steps()
BY_ID = {field(body, "id"): (name, body) for name, body in ORDERED if field(body, "id")}
INDEX = {name: i for i, (name, _) in enumerate(ORDERED)}

print("Three attempts on one pinned installer")
present = [step_id for step_id in ATTEMPTS if step_id in BY_ID]
check("all three attempts exist", present == list(ATTEMPTS), present)
if present != list(ATTEMPTS):
    print(f"{len(FAILURES)} test(s) failed ❌")
    sys.exit(1)

bodies = [BY_ID[step_id][1] for step_id in ATTEMPTS]
uses = [field(body, "uses") for body in bodies]
check(
    "every attempt uses the same action",
    len(set(uses)) == 1,
    uses,
)
check(
    "the action is pinned to a commit SHA",
    re.fullmatch(r"[\w./-]+/download-grype@[0-9a-f]{40}", uses[0]) is not None,
    uses[0],
)
inputs = [with_block(body) for body in bodies]
check(
    "every attempt passes the same with:", all(w == inputs[0] for w in inputs), inputs
)
check(
    "the with: is the version and a disabled cache",
    inputs[0] == ["grype-version: ${{ inputs.grype-version }}", 'cache-db: "false"'],
    inputs[0],
)
rationale = sum("Caching is owned below" in "\n".join(body) for body in bodies)
check("the cache-db rationale appears once", rationale == 1, rationale)

print("Only the first two attempts may fail quietly")
for step_id, body in zip(ATTEMPTS, bodies, strict=True):
    tolerated = field(body, "continue-on-error") == "true"
    quiet = step_id != "grype-3"
    check(
        f"{step_id} continue-on-error is {str(quiet).lower()}",
        tolerated == quiet,
        field(body, "continue-on-error"),
    )

print("Each wait and retry follows the previous attempt's outcome")
check(
    "attempt 1 carries only the guard",
    field(bodies[0], "if") == GUARD,
    field(bodies[0], "if"),
)
WAITS = (
    ("Wait before Grype install attempt 2", "grype-1", "grype-2", "10"),
    ("Wait before Grype install attempt 3", "grype-2", "grype-3", "30"),
)
for wait_name, previous, retry, seconds in WAITS:
    expected = f"{GUARD} && steps.{previous}.outcome == 'failure'"
    wait = dict(ORDERED).get(wait_name)
    check(f"'{wait_name}' exists", wait is not None)
    if wait is None:
        continue
    check(
        f"'{wait_name}' runs only after {previous} fails", field(wait, "if") == expected
    )
    check(
        f"'{wait_name}' sleeps {seconds} seconds",
        re.search(rf"^sleep {seconds}$", run_script(wait), re.M) is not None,
    )
    retry_name, retry_body = BY_ID[retry]
    check(
        f"{retry} runs only after {previous} fails", field(retry_body, "if") == expected
    )
    check(
        f"the wait sits between {previous} and {retry}",
        INDEX[BY_ID[previous][0]] < INDEX[wait_name] < INDEX[retry_name],
    )
text = (ROOT / "action.yaml").read_text()
check("no condition tests a conclusion", ".conclusion" not in text)

print("The resolver keeps the grype id")
check("a step has id: grype", "grype" in BY_ID)
resolver_name, resolver = BY_ID["grype"]
check("the resolver is guarded", field(resolver, "if") == GUARD, field(resolver, "if"))
check(
    "the resolver follows the last attempt",
    INDEX[resolver_name] == INDEX[BY_ID["grype-3"][0]] + 1,
)
check(
    "no step reads an attempt's cmd except the resolver",
    all(
        re.search(r"steps\.grype-\d", "\n".join(body)) is None
        for name, body in ORDERED
        if name != resolver_name
        and field(body, "id") not in ATTEMPTS
        and not name.startswith("Wait before")
    ),
)
RESOLVE = run_script(resolver)


def resolve(succeeded: int | None) -> tuple[int, str, str]:
    """Run the resolver as if attempt ``succeeded`` worked."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("OUTCOME_", "CMD_"))
    }
    for attempt in (1, 2, 3):
        if succeeded is None or attempt < succeeded:
            outcome = "failure"
        elif attempt == succeeded:
            outcome = "success"
        else:
            outcome = "skipped"
        env[f"OUTCOME_{attempt}"] = outcome
        env[f"CMD_{attempt}"] = (
            f"/tmp/grype-{attempt}/grype" if attempt == succeeded else ""
        )
    with tempfile.TemporaryDirectory() as tmp:
        outputs = pathlib.Path(tmp) / "github-output"
        outputs.touch()
        env["GITHUB_OUTPUT"] = str(outputs)
        result = subprocess.run(
            ["bash", "-c", RESOLVE],
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


print("The resolver publishes the successful attempt's cmd")
for attempt in (1, 2, 3):
    rc, log, out = resolve(attempt)
    check(f"attempt {attempt}: succeeds", rc == 0, log[-300:])
    check(
        f"attempt {attempt}: publishes its cmd",
        out.splitlines() == [f"cmd=/tmp/grype-{attempt}/grype"],
        out,
    )
    notices = [line for line in log.splitlines() if line.startswith("::notice::")]
    if attempt == 1:
        check("attempt 1: writes no notice", notices == [], notices)
    else:
        check(
            f"attempt {attempt}: a notice names the attempt",
            len(notices) == 1 and f"attempt {attempt} of 3" in notices[0],
            notices,
        )
    check(f"attempt {attempt}: writes no error", "::error::" not in log, log[-300:])

rc, log, out = resolve(None)
check("no attempt: fails", rc != 0, log[-300:])
check("no attempt: writes an error", "::error::" in log, log[-300:])
check("no attempt: publishes no cmd", out == "", out)
check("no attempt: writes no notice", "::notice::" not in log, log[-300:])

print()
if FAILURES:
    print(f"{len(FAILURES)} test(s) failed ❌")
    sys.exit(1)
print("All install retry tests passed ✅")
