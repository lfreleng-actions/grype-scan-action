# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Seed inputs for the fuzz harnesses, kept as literals.

Literals need no REUSE sidecar and no corpus directory in git. Each
harness writes its seeds to a scratch corpus before fuzzing, and
tests/test_fuzz_replay.py runs every one through the same checks
without Atheris, so a seed that stops passing fails the unit suite.
"""

from __future__ import annotations

import json
import pathlib


def encoded(value: object) -> bytes:
    """A JSON value as the bytes a harness reads."""
    return json.dumps(value).encode()


def cyclonedx(
    generator: str,
    root: dict,
    components: list[dict],
    graph: dict[str, list[str]],
    spec: str = "1.5",
) -> dict:
    """A CycloneDX document shaped the way the measured generators emit."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": spec,
        "metadata": {
            "tools": {"components": [{"type": "application", "name": generator}]},
            "component": root,
        },
        "components": components,
        "dependencies": [
            {"ref": ref, "dependsOn": targets} for ref, targets in graph.items()
        ],
    }


def library(ref: str, purl: str = "", scope: str = "") -> dict:
    """One component; empty arguments are left out."""
    entry: dict = {"bom-ref": ref, "type": "library", "name": ref}
    if purl:
        entry["purl"] = purl
    if scope:
        entry["scope"] = scope
    return entry


SINGLE_ROOT = cyclonedx(
    "cyclonedx-py",
    {"bom-ref": "root", "name": "root"},
    [
        library("requests", "pkg:pypi/requests@2.32.0"),
        library("urllib3", "pkg:pypi/urllib3@2.2.0"),
    ],
    {"root": ["requests"], "requests": ["urllib3"], "urllib3": []},
)

REACTOR = cyclonedx(
    "cyclonedx-maven-plugin",
    {"bom-ref": "agg", "name": "agg"},
    [
        library("app"),
        library("core"),
        library("guava", "pkg:maven/com.google/guava@33.0", "required"),
        library("failureaccess", "pkg:maven/com.google/failureaccess@1", "required"),
    ],
    {"agg": [], "app": ["core"], "core": ["guava"], "guava": ["failureaccess"]},
    spec="1.4",
)

GRADLE_PLUGIN = "cyclonedx-gradle-plugin"

GRADLE = cyclonedx(
    GRADLE_PLUGIN,
    {
        "bom-ref": "pkg:maven/org/root@1?project_path=%3A",
        "purl": "pkg:maven/org/root@1?project_path=%3A",
        "name": "root",
    },
    [
        library(
            "pkg:maven/org/sub@1?project_path=%3Asub",
            "pkg:maven/org/sub@1?project_path=%3Asub",
        ),
        library("pkg:maven/org/lib@1", "pkg:maven/org/lib@1"),
        library("pkg:maven/org/deep@1", "pkg:maven/org/deep@1"),
    ],
    {
        "pkg:maven/org/sub@1?project_path=%3Asub": ["pkg:maven/org/lib@1"],
        "pkg:maven/org/lib@1": ["pkg:maven/org/deep@1"],
    },
    spec="1.6",
)

CARGO = cyclonedx(
    "cargo-cyclonedx",
    {"bom-ref": "path+file:///w/cli#0.1.0", "name": "cli"},
    [
        library("path+file:///w/core#0.1.0", scope="required"),
        library(
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0",
            "pkg:cargo/serde@1.0.0",
            "required",
        ),
        library(
            "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.0",
            "pkg:cargo/itoa@1.0.0",
            "required",
        ),
    ],
    {
        "path+file:///w/cli#0.1.0": ["path+file:///w/core#0.1.0"],
        "path+file:///w/core#0.1.0": [
            "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0"
        ],
        "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0": [
            "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.0"
        ],
    },
)

# A Gradle document whose projects cannot be told apart must stay
# unclassified: a root without the marker, as plugins before 2.2.0
# emit, and a component whose marker is blank or repeated.
GRADLE_UNMARKED = {
    **SINGLE_ROOT,
    "metadata": {
        **SINGLE_ROOT["metadata"],
        "tools": {"components": [{"type": "application", "name": GRADLE_PLUGIN}]},
    },
}
GRADLE_BLANK = {
    **GRADLE,
    "components": [
        *GRADLE["components"],
        library("odd", "pkg:maven/org/odd@1?project_path="),
    ],
}
GRADLE_REPEATED = {
    **GRADLE,
    "components": [
        *GRADLE["components"],
        library("odd", "pkg:maven/org/odd@1?project_path=%3Aa&project_path=%3Ab"),
    ],
}

# A transitive namesake sharing a purl with a declared package: the
# stricter answer has to win the purl join.
SHARED_PURL = cyclonedx(
    "cyclonedx-py",
    {"bom-ref": "root", "name": "root"},
    [
        library("a", "pkg:pypi/six@1"),
        library("b", "pkg:pypi/mid@1"),
        library("c", "pkg:pypi/six@1"),
    ],
    {"root": ["a", "b"], "b": ["c"]},
)

SBOM_SEEDS: list[bytes] = [
    encoded(SINGLE_ROOT),
    encoded(REACTOR),
    encoded(GRADLE),
    encoded(CARGO),
    encoded(SHARED_PURL),
    encoded(GRADLE_UNMARKED),
    encoded(GRADLE_BLANK),
    encoded(GRADLE_REPEATED),
    encoded({**SINGLE_ROOT, "specVersion": "1.2"}),
    encoded({**SINGLE_ROOT, "components": [{"bom-ref": "x", "scope": ["required"]}]}),
    encoded({**SINGLE_ROOT, "dependencies": [{"ref": "root", "dependsOn": "x"}]}),
    encoded({**SINGLE_ROOT, "metadata": []}),
    encoded({**SINGLE_ROOT, "artifacts": [{"id": "urllib3"}, {"purl": 7}, {}]}),
    encoded([]),
    b"",
    b"not json",
    b'{"components": "\xff\xfe"}',
    # Deeper than the JSON decoder can recurse before Python 3.14.
    b"[" * 20_000,
]


def bypass_seed(title: str, events: object) -> bytes:
    """A bypass input: the current title, a newline, the event payload."""
    return title.encode() + b"\n" + encoded(events)


def labelled(identifier: int, when: str, name: str = "cve-bypass") -> dict:
    """A 'labeled' issue event."""
    return {
        "id": identifier,
        "event": "labeled",
        "created_at": when,
        "label": {"name": name},
    }


def renamed(identifier: int, when: str, before: object, after: object) -> dict:
    """A 'renamed' issue event."""
    return {
        "id": identifier,
        "event": "renamed",
        "created_at": when,
        "rename": {"from": before, "to": after},
    }


T0 = "2026-01-01T00:00:00Z"
T1 = "2026-01-02T00:00:00Z"
T2 = "2026-01-03T00:00:00Z"
APPROVED = "BYPASS: CVE-2026-0001 no fix upstream"
EDITED = "BYPASS: CVE-2026-9999 GHSA-abcd-efgh-ijkl"

# Edited after a maintainer approved it: APPROVED stands, not EDITED.
RENAMED_AFTER_LABEL = bypass_seed(
    EDITED, [labelled(1, T0), renamed(2, T1, APPROVED, EDITED)]
)
# Renamed both before and after the label: only the later rename counts.
RENAMED_AROUND_LABEL = bypass_seed(
    EDITED,
    [
        renamed(1, T0, "draft", APPROVED),
        labelled(2, T1),
        renamed(3, T2, APPROVED, EDITED),
    ],
)
# Labelled with something other than the bypass label: not approved.
OTHER_LABEL = bypass_seed(APPROVED, [labelled(1, T0, "other")])
# JSON can carry a lone surrogate, which no codec encodes; the warning
# naming the approved title must still print.
SURROGATE_TITLE = bypass_seed(
    APPROVED, [labelled(1, T0), renamed(2, T1, APPROVED + " \ud800", APPROVED)]
)

BYPASS_SEEDS: list[bytes] = [
    bypass_seed(APPROVED, [labelled(1, T0)]),
    RENAMED_AFTER_LABEL,
    RENAMED_AROUND_LABEL,
    bypass_seed(APPROVED, [labelled(1, T0, "CVE-Bypass ")]),
    OTHER_LABEL,
    SURROGATE_TITLE,
    bypass_seed(EDITED, [labelled(1, T0), renamed(2, T1, APPROVED, "elsewhere")]),
    bypass_seed(EDITED, [labelled(1, T0), renamed(2, T1, None, EDITED)]),
    bypass_seed(EDITED, [labelled(1, T0), {"event": "renamed", "rename": []}]),
    bypass_seed(APPROVED, [labelled(n, T0) for n in range(100)]),
    bypass_seed(APPROVED, {"message": "Not Found"}),
    bypass_seed(APPROVED, [1, "two", None]),
    b"ALPINE-CVE-2026-1234, RHSA-2026:1234. ghsa-xxxx-xxxx-xxxx;\nnot json",
    "BYPASS: ß-1 ﬃ-CVE-2 İ-3\n[]".encode(),
    b"\xff\xfe\n\xff",
    b"",
]


def write_corpus(directory: str, seeds: list[bytes]) -> None:
    """Write each seed to its own file, the layout libFuzzer reads."""
    for number, seed in enumerate(seeds):
        (pathlib.Path(directory) / f"seed-{number:03d}").write_bytes(seed)
