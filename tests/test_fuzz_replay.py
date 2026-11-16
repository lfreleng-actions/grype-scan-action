# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Replay every fuzz seed through its harness's checks, offline.

The harnesses import Atheris only in their fuzzing entry point, so
this runs on any platform and keeps the checks from rotting between
fuzz runs. A seed breaking a contract raises ContractBroken; any other
exception is the code under test raising where it promised not to.
Both fail the suite, with the seed that did it.

It then swaps in a classifier, and an approval verifier, that break
their contracts in known ways and checks each oracle rejects every
one, so a weakened oracle fails here rather than passing every fuzz
run.
"""

from __future__ import annotations

import sys
import traceback
from collections.abc import Callable

import fuzz_bypasses
import fuzz_sbom
from fuzz_seeds import (
    BYPASS_SEEDS,
    CARGO,
    GRADLE,
    GRADLE_BLANK,
    GRADLE_REPEATED,
    GRADLE_UNMARKED,
    OTHER_LABEL,
    REACTOR,
    RENAMED_AFTER_LABEL,
    RENAMED_AROUND_LABEL,
    SBOM_SEEDS,
    SINGLE_ROOT,
    cyclonedx,
    encoded,
    library,
)

from scripts import collect_bypasses, provenance

FAILURES: list[str] = []


def replay(name: str, check: Callable[[bytes], None], seeds: list[bytes]) -> None:
    """Run every seed through one harness, recording each that fails."""
    print(name)
    for number, seed in enumerate(seeds):
        label = f"{name} seed {number} ({len(seed)} bytes)"
        try:
            check(seed)
        except Exception:  # noqa: BLE001 - report the seed, then fail below
            print(f"  ❌ {label}: {seed[:120]!r}")
            traceback.print_exc()
            FAILURES.append(label)
        else:
            print(f"  ✅ {label}")


# Two components naming each other, with nothing placed above them.
ORPHAN_CYCLE = cyclonedx(
    "cyclonedx-py",
    {"bom-ref": "root", "name": "root"},
    [library("a"), library("b"), library("c")],
    {"root": ["a"], "a": [], "b": ["c"], "c": ["b"]},
)


def caught(name: str, doc: dict, classes: dict[str, str]) -> None:
    """Fail unless the SBOM oracle rejects a wrong classification.

    The classifier is swapped for one returning ``classes``, so this
    shows the harness would catch that regression in the real code.
    """
    original = provenance.classify_document
    provenance.classify_document = lambda doc: (dict(classes), provenance.SOURCE_GRAPH)
    try:
        fuzz_sbom.check(encoded(doc))
    except fuzz_sbom.ContractBroken as error:
        print(f"  ✅ {name}: {error}")
    else:
        print(f"  ❌ {name}: the oracle accepted it")
        FAILURES.append(name)
    finally:
        provenance.classify_document = original


replay("SBOM reading and classification", fuzz_sbom.check, SBOM_SEEDS)
replay("bypass titles and approval history", fuzz_bypasses.check, BYPASS_SEEDS)

print("SBOM oracle against a broken classifier")
DIRECT, TRANSITIVE = provenance.DIRECT, provenance.TRANSITIVE
caught(
    "declared dependency called transitive",
    SINGLE_ROOT,
    {"root": DIRECT, "requests": TRANSITIVE, "urllib3": TRANSITIVE},
)
caught(
    "subject called transitive",
    SINGLE_ROOT,
    {"root": TRANSITIVE, "requests": DIRECT, "urllib3": TRANSITIVE},
)
caught(
    "transitive with no direct reference above it",
    ORPHAN_CYCLE,
    {"root": DIRECT, "a": DIRECT, "b": TRANSITIVE, "c": TRANSITIVE},
)
caught(
    "orphan called direct to downgrade what it names",
    ORPHAN_CYCLE,
    {"root": DIRECT, "a": DIRECT, "b": DIRECT, "c": TRANSITIVE},
)
SINGLE_ROOT_CLASSES = {"root": DIRECT, "requests": DIRECT, "urllib3": TRANSITIVE}
caught(
    "graph read from an unmeasured schema version",
    {**SINGLE_ROOT, "specVersion": "1.2"},
    SINGLE_ROOT_CLASSES,
)
caught(
    "graph read from an unmeasured producer",
    {
        **SINGLE_ROOT,
        "metadata": {**SINGLE_ROOT["metadata"], "tools": [{"name": "syft"}]},
    },
    SINGLE_ROOT_CLASSES,
)
caught(
    "graph read from a document that is not CycloneDX",
    {**SINGLE_ROOT, "bomFormat": "SPDX"},
    SINGLE_ROOT_CLASSES,
)
caught(
    "graph read despite an undefined scope",
    {
        **SINGLE_ROOT,
        "components": [*SINGLE_ROOT["components"], library("x", scope="dev")],
    },
    SINGLE_ROOT_CLASSES,
)

caught(
    "dependency a reactor module declares called transitive",
    REACTOR,
    {
        "agg": DIRECT,
        "app": DIRECT,
        "core": DIRECT,
        "guava": TRANSITIVE,
        "failureaccess": TRANSITIVE,
    },
)
caught(
    "dependency a Gradle subproject declares called transitive",
    GRADLE,
    {
        "pkg:maven/org/root@1?project_path=%3A": DIRECT,
        "pkg:maven/org/sub@1?project_path=%3Asub": DIRECT,
        "pkg:maven/org/lib@1": TRANSITIVE,
        "pkg:maven/org/deep@1": TRANSITIVE,
    },
)
caught(
    "graph read from a Gradle root without its marker",
    GRADLE_UNMARKED,
    SINGLE_ROOT_CLASSES,
)
GRADLE_CLASSES = {
    "pkg:maven/org/root@1?project_path=%3A": DIRECT,
    "pkg:maven/org/sub@1?project_path=%3Asub": DIRECT,
    "pkg:maven/org/lib@1": DIRECT,
    "pkg:maven/org/deep@1": TRANSITIVE,
}
caught(
    "graph read despite a blank Gradle marker",
    GRADLE_BLANK,
    {**GRADLE_CLASSES, "odd": DIRECT},
)
caught(
    "graph read despite a repeated Gradle marker",
    GRADLE_REPEATED,
    {**GRADLE_CLASSES, "odd": DIRECT},
)
caught(
    "dependency a Cargo workspace member declares called transitive",
    CARGO,
    {
        "path+file:///w/cli#0.1.0": DIRECT,
        "path+file:///w/core#0.1.0": DIRECT,
        "registry+https://github.com/rust-lang/crates.io-index#serde@1.0.0": (
            TRANSITIVE
        ),
        "registry+https://github.com/rust-lang/crates.io-index#itoa@1.0.0": (
            TRANSITIVE
        ),
    },
)


def rejected(name: str, seed: bytes, verifier: Callable[..., str]) -> None:
    """Fail unless the bypass oracle rejects a wrong approved title.

    ``approved_title`` is swapped for ``verifier``, so this shows the
    harness would catch that regression in the real code.
    """
    original = collect_bypasses.approved_title
    collect_bypasses.approved_title = verifier
    try:
        fuzz_bypasses.check(seed)
    except fuzz_bypasses.ContractBroken as error:
        print(f"  ✅ {name}: {error}")
    else:
        print(f"  ❌ {name}: the oracle accepted it")
        FAILURES.append(name)
    finally:
        collect_bypasses.approved_title = original


def current_title(_events: list[dict], _label: str, current: str) -> str:
    """Approve whatever the title shows now."""
    return current


def first_rename(events: list[dict], _label: str, current: str) -> str:
    """Approve the title before the first rename, ignoring the label."""
    for event in events:
        if event.get("event") == "renamed":
            return event["rename"]["from"].strip()
    return current


print("Bypass oracle against a broken approval verifier")
rejected("title edited after the label approved", RENAMED_AFTER_LABEL, current_title)
rejected("title approved without the bypass label", OTHER_LABEL, current_title)
rejected("rename before the label taken", RENAMED_AROUND_LABEL, first_rename)

print()
if FAILURES:
    print(f"{len(FAILURES)} check(s) failed ❌")
    sys.exit(1)
print("All fuzz seeds replayed cleanly ✅")
