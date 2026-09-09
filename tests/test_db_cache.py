#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline tests for the Grype database cache steps.

The two cache steps decide where the database lives, whether an entry
may be written, and under which key. Both are shell embedded in
``action.yaml``, so the scripts are extracted and run for real against
a stub ``grype`` -- these exercise the shipped code rather than a copy
that could drift from it.

No network, no Grype binary and no YAML library are needed: the CI job
runs this file directly with python3, and the project declares no
dependencies.
"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

FAILURES: list[str] = []
LAST_ARGV: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    if condition:
        print(f"  ✅ {label}")
    else:
        print(f"  ❌ {label} {detail}")
        FAILURES.append(label)


def extract_run(step_name: str) -> str:
    """Return the ``run:`` script of the named step in action.yaml.

    Deliberately a small indentation-aware reader rather than a YAML
    parse: the project declares no dependencies, and the CI job invokes
    this file with a bare python3 that has no PyYAML available.
    """
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


RESOLVE = extract_run("Resolve Grype DB cache location")
REFRESH = extract_run("Refresh the Grype DB")

# A stub Grype driven by files in its own directory, so a test can make
# the database change, an update fail, or a database read as invalid,
# without any real binary. 'db status' mirrors the real command in the
# detail that matters here: it prints Built: even for a database Grype
# rejects, signalling invalidity only through the exit status.
STUB = """#!/usr/bin/env bash
set -uo pipefail
state="${STUB_STATE}"
# Record the whole argv, so a test can assert that cache operations
# carry the same --config the scan will use.
printf '%s\\n' "$*" >> "${state}/argv"
args=("$@")
# Consume leading global options as Grype's parser does, so the command
# is found whether or not a --config precedes it.
i=0
while [ ${i} -lt ${#args[@]} ]; do
  case "${args[${i}]}" in
    --config|-c) i=$((i + 2)) ;;
    --config=*|-c=*) i=$((i + 1)) ;;
    *) break ;;
  esac
done
cmd="${args[${i}]:-}"; sub="${args[$((i + 1))]:-}"
if [ "${cmd}" = "version" ]; then
  echo "Version:             0.109.1"
  exit 0
fi
if [ "${cmd}" = "config" ]; then
  # Older Grype releases have no 'config' command at all, which is what
  # no_config models: the call fails and prints nothing.
  [ -f "${state}/no_config" ] && exit 1
  cat "${state}/config"
  exit 0
fi
if [ "${cmd}" = "db" ]; then
  echo "${sub}" >> "${state}/calls"
  case "${sub}" in
    status)
      [ -f "${state}/build" ] || exit 1
      echo "Built: $(cat "${state}/build")"
      [ -f "${state}/invalid" ] && exit 1
      exit 0
      ;;
    update)
      [ -f "${state}/update_fails" ] && exit 1
      # Grype replaces the database only with a *later* build, so an
      # existing newer one survives an update. Modelled by writing the
      # new build when none is present (a download) or when the feed is
      # explicitly newer; otherwise the update is a no-op.
      if [ ! -f "${state}/build" ] || [ -f "${state}/feed_newer" ]; then
        [ -f "${state}/new_build" ] && cp "${state}/new_build" "${state}/build"
      fi
      exit 0
      ;;
  esac
fi
exit 0
"""


def read_outputs(path: pathlib.Path) -> dict[str, str]:
    """Parse a GITHUB_OUTPUT file into a mapping."""
    outputs: dict[str, str] = {}
    for line in path.read_text().splitlines():
        key, sep, value = line.partition("=")
        if sep:
            outputs[key] = value
    return outputs


def _stub_dir(root: pathlib.Path) -> pathlib.Path:
    state = root / "state"
    state.mkdir(parents=True, exist_ok=True)
    stub = root / "bin" / "grype"
    stub.parent.mkdir(parents=True, exist_ok=True)
    stub.write_text(STUB)
    stub.chmod(0o755)
    return stub


def run_resolve(
    *,
    cache_dir: str | None = None,
    update_url: str = "https://grype.anchore.io/databases",
    auto_update: str = "true",
    no_config: bool = False,
) -> tuple[int, str, dict[str, str]]:
    """Run the real resolve script against the stub and report outputs."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        stub = _stub_dir(root)
        state = root / "state"
        cache = cache_dir if cache_dir is not None else str(root / "grype" / "db")
        (state / "config").write_text(
            f"  cache-dir: '{cache}'\n"
            f"  update-url: '{update_url}'\n"
            f"  auto-update: {auto_update}\n"
        )
        if no_config:
            (state / "no_config").touch()
        out_file = root / "gh_output"
        out_file.touch()
        proc = subprocess.run(
            ["bash", "-c", RESOLVE],
            capture_output=True,
            text=True,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "HOME": str(root / "home"),
                "GITHUB_WORKSPACE": str(root / "workspace"),
                "RUNNER_TEMP": str(root / "runnertemp"),
                "STUB_STATE": str(state),
                "GRYPE_CMD": str(stub),
                "INPUT_CONFIG": "",
                "GITHUB_OUTPUT": str(out_file),
            },
        )
        outputs = read_outputs(out_file)
        return proc.returncode, proc.stdout + proc.stderr, outputs


def run_refresh(
    *,
    build: str | None,
    new_build: str | None = None,
    feed_newer: bool = False,
    update_fails: bool = False,
    invalid: bool = False,
    config: str = "",
) -> tuple[int, str, dict[str, str], list[str]]:
    """Run the real refresh script against the stub and report outcomes."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        stub = _stub_dir(root)
        state = root / "state"
        if build is not None:
            (state / "build").write_text(build)
        if new_build is not None:
            (state / "new_build").write_text(new_build)
        if feed_newer:
            (state / "feed_newer").touch()
        if update_fails:
            (state / "update_fails").touch()
        if invalid:
            (state / "invalid").touch()
        out_file = root / "gh_output"
        out_file.touch()
        proc = subprocess.run(
            ["bash", "-c", REFRESH],
            capture_output=True,
            text=True,
            env={
                "PATH": "/usr/bin:/bin:/usr/local/bin",
                "HOME": str(root),
                "STUB_STATE": str(state),
                "GRYPE_CMD": str(stub),
                "PREFIX": "grype-db-v1-abc-",
                "INPUT_CONFIG": config,
                "GITHUB_OUTPUT": str(out_file),
            },
        )
        outputs = read_outputs(out_file)
        argv_file = state / "argv"
        globals()["LAST_ARGV"] = (
            argv_file.read_text().splitlines() if argv_file.is_file() else []
        )
        calls_file = state / "calls"
        calls = calls_file.read_text().split() if calls_file.is_file() else []
        return proc.returncode, proc.stdout + proc.stderr, outputs, calls


print("Grype database cache location")

# The ordinary case, asserted first: without it the refusals below could
# all be passing because the harness is broken rather than because the
# checks work.
rc, log, out = run_resolve()
check("default layout is cacheable", out.get("cacheable") == "true", out)
check(
    "default layout derives a versioned, feed-namespaced prefix",
    out.get("prefix", "").startswith("grype-db-v0.109.1-"),
    out,
)

# A Grype release predating `grype config --load` still scans, so an
# unavailable configuration view must cost the cache and nothing more.
rc, log, out = run_resolve(no_config=True)
check("missing config command does not fail the run", rc == 0, rc)
check("missing config command skips caching", out.get("cacheable") == "false", out)

# A pinned database is left alone: restoring would overwrite what the
# caller deliberately put there.
rc, log, out = run_resolve(auto_update="false")
check("auto-update false skips caching", out.get("cacheable") == "false", out)
check("auto-update false keeps the run passing", rc == 0, rc)

# Without a resolvable feed there is no namespace, and a shared one is
# the cross-feed contamination the segment exists to prevent.
rc, log, out = run_resolve(update_url="")
check("unresolvable feed skips caching", out.get("cacheable") == "false", out)

# Directories broad enough to sweep in unrelated files. Each case also
# asserts *which* refusal fired: a value that reached the wrong check
# would otherwise pass for the wrong reason.
for label, path, reason in (
    ("home directory", "~", "contains"),
    ("filesystem root", "/", "filesystem root"),
    ("shared temp root", "/tmp", "contains"),
    ("relative path", "grype/db", "not an absolute"),
    ("Windows path", "C:\\\\Users\\\\runner\\\\grype\\\\db", "not an absolute"),
):
    rc, log, out = run_resolve(cache_dir=path)
    check(f"{label} skips caching", out.get("cacheable") == "false", (path, out))
    check(f"{label} keeps the run passing", rc == 0, rc)
    check(f"{label} is refused for the stated reason", reason in log, log[-200:])

# An apostrophe is legal in a plain YAML scalar, so stripping every
# quote character would point the cache at a different directory from
# the one the scan uses.
# An apostrophe is legal in a path, and Grype wraps these values in
# single quotes without escaping what is inside them, so collapsing ''
# would corrupt a path that genuinely contains two apostrophes.
for label, path in (
    ("single apostrophe", "/opt/gr'ype/db"),
    ("consecutive apostrophes", "/opt/gr''ype/db"),
):
    rc, log, out = run_resolve(cache_dir=path)
    check(f"{label} in path is preserved", out.get("dir") == path, (path, out))

# A dedicated subdirectory of a shared root is still fine.
rc, log, out = run_resolve(cache_dir="/tmp/grype/db")
check(
    "dedicated subdirectory of a shared root is cacheable",
    out.get("cacheable") == "true",
    out,
)

print()
print("Grype database refresh and save decision")

# A cold runner downloads the database, so the build moves on and the
# entry is saved under its own key.
rc, log, out, calls = run_refresh(build=None, new_build="t5")
check("fresh download saves", out.get("save") == "true", out)
check("fresh download keys on the build", out.get("key") == "grype-db-v1-abc-t5", out)

# A restored entry whose feed has moved on is saved under the new key.
rc, log, out, calls = run_refresh(build="t1", new_build="t2", feed_newer=True)
check("refreshed build saves", out.get("save") == "true", out)
check("refreshed build keys on the new build", out.get("key", "").endswith("t2"), out)

# Nothing new to publish: either the entry restored already holds this
# build, or the database was already on the runner and this run cannot
# say which feed produced it.
rc, log, out, calls = run_refresh(build="t2")
check("unchanged build does not save", out.get("save") == "false", out)
check("unchanged build keeps the run passing", rc == 0, rc)

# A feed outage must not fail a scan that has a usable database.
rc, log, out, calls = run_refresh(build="t2", update_fails=True)
check("failed update keeps the run passing", rc == 0, rc)
check("failed update is reported", "update failed" in log, log[-200:])

# No database at all is fatal in a way a failed refresh is not.
rc, log, out, calls = run_refresh(build=None, update_fails=True)
check("no database at all stops the run", rc != 0, rc)

# Grype prints Built: even for a database it rejects, so reading the
# timestamp alone would cache a corrupt database under a valid key.
rc, log, out, calls = run_refresh(build="t2", new_build="t9", invalid=True)
check("invalid database does not save", out.get("save") == "false", out)
check("invalid database keeps the run passing", rc == 0, rc)
check(
    "invalid database is reported",
    "reports the database as invalid" in log,
    log[-200:],
)

# The scan's configuration must reach every database call, or the cache
# refreshes one configuration while the scan reads another.
rc, log, out, calls = run_refresh(build=None, new_build="t5", config="/tmp/g.yaml")
db_calls = [line for line in LAST_ARGV if " db " in f" {line} "]
check("database calls were made", bool(db_calls), LAST_ARGV)
check(
    "every database call carries the scan's config",
    all("--config /tmp/g.yaml" in line for line in db_calls),
    db_calls,
)

print()
if FAILURES:
    print(f"{len(FAILURES)} test(s) failed ❌")
    sys.exit(1)
print("All cache tests passed ✅")
