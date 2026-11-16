# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Fuzz the CycloneDX reader and the provenance classifier.

Contracts checked, in the modules' own words:

* ``scripts.cyclonedx`` turns every malformed case "into an absence
  ... rather than an exception that would abort the run". Reading any
  bytes as an SBOM, classifying the document, and classifying any
  artifact mapping against it must not raise.
* ``scripts.provenance``: "every uncertainty resolves to ``direct``".
  Every verdict is ``direct`` or ``transitive``. A graph verdict needs
  a CycloneDX document of a measured schema version, from a measured
  generator, whose scopes are all ones CycloneDX defines; from a Gradle
  build, it also needs a usable 'project_path' marker on the root and
  no blank or repeated marker anywhere. The document's own
  subject, each module a supported multi-project shape marks as the
  project's (Maven reactor, Gradle build, Cargo workspace), and every
  reference any of them depends on, is never ``transitive``: what the
  project names is declared. Any other ``transitive`` reference must
  be reachable in the document's own dependency graph from the
  project or what it names.

The evidence is read straight from the raw document here rather than
through ``cyclonedx.edges``, and the project and what it names are
taken from the raw document rather than from the classification, so
the oracle does not share the code it checks.

``check`` needs no Atheris; tests/test_fuzz_replay.py runs every seed
through it. To fuzz, on Linux with Atheris installed (see README):

    python3 tests/fuzz_sbom.py -max_total_time=60 -timeout=10
"""

from __future__ import annotations

import atexit
import pathlib
import shutil
import sys
import tempfile
from collections.abc import Iterator

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from scripts import cyclonedx, provenance  # noqa: E402

VERDICTS = frozenset({provenance.DIRECT, provenance.TRANSITIVE})
SOURCES = frozenset({provenance.SOURCE_NONE, provenance.SOURCE_GRAPH})

# The multi-project generators and the markers they use, spelt out here
# rather than imported so the oracle does not share the classifier's.
GRADLE = "cyclonedx-gradle-plugin"
MARKER = "project_path"
CARGO = "cargo-cyclonedx"
CARGO_REMOTE = ("registry+", "sparse+", "git+")
MAVEN = frozenset({"CycloneDX Maven plugin", "cyclonedx-maven-plugin"})
MEASURED = MAVEN | {GRADLE, CARGO, "cyclonedx-py"}
SPEC_VERSIONS = frozenset({"1.4", "1.5", "1.6"})
SCOPES = frozenset({"required", "optional", "excluded"})

# load_document and build read a path, so each input goes through a
# real file, rewritten in place.
SCRATCH = pathlib.Path(tempfile.mkdtemp(prefix="fuzz-sbom-"))
atexit.register(shutil.rmtree, SCRATCH, True)
SBOM = SCRATCH / "sbom.json"


class ContractBroken(AssertionError):
    """The code under test broke a contract its docstring promises."""


def require(condition: bool, message: str) -> None:
    """Raise ContractBroken unless the condition holds."""
    if not condition:
        raise ContractBroken(message)


def entries(doc: dict) -> list[dict]:
    """The components and the document's own subject, when mappings."""
    listed = doc.get("components")
    found = (
        [c for c in listed if isinstance(c, dict)] if isinstance(listed, list) else []
    )
    metadata = doc.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        found.append(metadata["component"])
    return found


def ref_of(entry: dict, key: str = "bom-ref") -> str:
    """A non-empty string identifier, or empty."""
    value = entry.get(key)
    return value if isinstance(value, str) else ""


def parents(doc: dict) -> dict[str, set[str]]:
    """For each defined reference, the defined references naming it."""
    defined = {ref_of(entry) for entry in entries(doc)} - {""}
    found: dict[str, set[str]] = {}
    listed = doc.get("dependencies")
    for entry in listed if isinstance(listed, list) else []:
        if not isinstance(entry, dict) or ref_of(entry, "ref") not in defined:
            continue
        targets = entry.get("dependsOn")
        for target in targets if isinstance(targets, list) else []:
            if isinstance(target, str) and target in defined:
                found.setdefault(target, set()).add(entry["ref"])
    return found


def marker(purl: str) -> str | None:
    """A purl's 'project_path' qualifier: None absent, '' if unusable.

    Blank and repeated values are unusable: qualifier keys are unique,
    and picking one of two would make the answer depend on their order.
    """
    query = purl.partition("#")[0].partition("?")[2]
    values = [
        value
        for key, _, value in (pair.partition("=") for pair in query.split("&"))
        if key == MARKER
    ]
    if len(values) != 1:
        return "" if values else None
    return values[0]


def gradle_marked(doc: dict) -> bool:
    """Whether a Gradle build marks its projects usably.

    The root's purl must carry the marker, which proves the plugin
    emits it, and no component may carry a blank or repeated one.
    Without that, subprojects are indistinguishable from third-party
    libraries, so the document must stay unclassified.
    """
    metadata = doc.get("metadata")
    root = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(root, dict) or not marker(ref_of(root, "purl")):
        return False
    listed = doc.get("components")
    found = (
        [c for c in listed if isinstance(c, dict)] if isinstance(listed, list) else []
    )
    return all(marker(ref_of(entry, "purl")) != "" for entry in found)


def subject(doc: dict) -> str:
    """The reference of the document's own subject, or empty."""
    metadata = doc.get("metadata")
    if isinstance(metadata, dict) and isinstance(metadata.get("component"), dict):
        return ref_of(metadata["component"])
    return ""


def modules(doc: dict) -> set[str]:
    """Components a supported multi-project shape marks as the project's.

    Each shape's marker is read from the raw document, following the
    precedence ``scripts.provenance`` documents: a Gradle build's
    'project_path' purl qualifier, once the subject carries it; a Cargo
    package ID that does not name a remote source; and, in a Maven
    reactor where any component carries a scope, every unscoped one.
    ``cyclonedx.generators`` only reads a field; it decides nothing.
    """
    named = cyclonedx.generators(doc)
    listed = doc.get("components")
    found = (
        [c for c in listed if isinstance(c, dict)] if isinstance(listed, list) else []
    )
    if GRADLE in named:
        if not gradle_marked(doc):
            return set()
        marked = {ref_of(entry) for entry in found if marker(ref_of(entry, "purl"))}
        return marked - {""}
    if CARGO in named:
        return {
            ref_of(entry)
            for entry in found
            if not ref_of(entry).startswith(CARGO_REMOTE)
        } - {""}
    if MAVEN & named and any(entry.get("scope") for entry in found):
        return {ref_of(entry) for entry in found if not entry.get("scope")} - {""}
    return set()


def anchors(doc: dict, graph: dict[str, set[str]]) -> set[str]:
    """The subject, the project's modules, and what any of them names."""
    root = subject(doc)
    if not root:
        return set()
    project = {root} | modules(doc)
    return project | {child for child, named in graph.items() if named & project}


def reachable(graph: dict[str, set[str]], start: set[str]) -> set[str]:
    """Every reference a raw edge chain reaches from the start set."""
    children: dict[str, set[str]] = {}
    for child, named in graph.items():
        for parent in named:
            children.setdefault(parent, set()).add(child)
    seen = set(start)
    queue = list(start)
    while queue:
        for child in children.get(queue.pop(), set()) - seen:
            seen.add(child)
            queue.append(child)
    return seen


def artifacts(doc: dict) -> Iterator[dict]:
    """Artifact mappings to classify: each entry, raw and Grype-shaped.

    Grype carries a component's bom-ref as ``artifact.id``. A top-level
    ``artifacts`` list, which no SBOM carries, lets the fuzzer supply
    arbitrary mappings too.
    """
    extra = doc.get("artifacts")
    supplied = (
        [a for a in extra if isinstance(a, dict)] if isinstance(extra, list) else []
    )
    for entry in entries(doc) + supplied:
        yield entry
        yield {"id": entry.get("bom-ref"), "purl": entry.get("purl")}


def vouched(doc: dict, classes: dict[str, str], artifact: dict) -> bool:
    """Whether the graph is the evidence for an inherited verdict.

    By reference when the graph placed it; otherwise by purl, and then
    only when every entry carrying that purl was placed as inherited.
    """
    ref = cyclonedx.identifier(artifact.get("id"))
    if ref in classes:
        return classes[ref] == provenance.TRANSITIVE
    purl = cyclonedx.identifier(artifact.get("purl"))
    namesakes = [entry for entry in entries(doc) if entry.get("purl") == purl]
    return bool(purl and namesakes) and all(
        classes.get(ref_of(entry)) == provenance.TRANSITIVE for entry in namesakes
    )


def supported(doc: dict) -> bool:
    """Whether the document is one the graph may classify at all.

    CycloneDX, a measured schema version and generator, no scope
    outside the ones CycloneDX defines, and, from a Gradle build, usable
    project markers; anything else must stay unclassified.
    """
    listed = doc.get("components")
    scopes = [
        entry.get("scope")
        for entry in (listed if isinstance(listed, list) else [])
        if isinstance(entry, dict) and entry.get("scope") is not None
    ]
    return (
        doc.get("bomFormat") == "CycloneDX"
        and doc.get("specVersion") in SPEC_VERSIONS
        and bool(MEASURED & cyclonedx.generators(doc))
        and all(isinstance(scope, str) and scope in SCOPES for scope in scopes)
        and (GRADLE not in cyclonedx.generators(doc) or gradle_marked(doc))
    )


def check(data: bytes) -> None:
    """Read the bytes as an SBOM and hold the classifier to its contracts."""
    SBOM.write_bytes(data)
    doc = cyclonedx.load_document(str(SBOM))
    built = provenance.build(str(SBOM), "", provenance.AUTO)
    if doc is None:
        require(built.source == provenance.SOURCE_NONE, "unusable SBOM classified")
        return

    classes, source = provenance.classify_document(doc)
    require(source in SOURCES, f"unknown source {source!r}")
    require(source == built.source, "build and classify_document disagree")
    require(source == provenance.SOURCE_GRAPH or not classes, "classes without a graph")
    require(set(classes.values()) <= VERDICTS, f"unknown verdict in {classes}")

    graph = parents(doc)
    declared = anchors(doc, graph)
    if source == provenance.SOURCE_GRAPH:
        require(supported(doc), "classified an unsupported document")
        require(bool(declared), "classified without the document's subject")
    for ref in declared:
        require(
            classes.get(ref, provenance.DIRECT) == provenance.DIRECT,
            f"{ref!r} is the project or one it names, yet is transitive",
        )
    rooted = reachable(graph, declared)
    for ref, verdict in classes.items():
        if verdict == provenance.TRANSITIVE:
            require(
                bool(graph.get(ref, set()) & classes.keys()),
                f"{ref!r} is transitive but no placed reference depends on it",
            )
            require(
                ref in rooted,
                f"{ref!r} is transitive but the project does not reach it",
            )

    for artifact in artifacts(doc):
        verdict = built.classify(artifact)
        require(verdict in VERDICTS, f"unknown verdict {verdict!r}")
        if verdict == provenance.TRANSITIVE:
            require(
                cyclonedx.identifier(artifact.get("id")) not in declared,
                f"{artifact!r} is the project or one it names, yet is transitive",
            )
            require(
                vouched(doc, classes, artifact),
                f"{artifact!r} is transitive without the graph's evidence",
            )


def main() -> None:
    """Fuzz ``check`` under Atheris, seeded from tests/fuzz_seeds.py."""
    # Atheris is installed only where fuzzing runs; the checker sees
    # its typeshed stubs alone.
    import atheris  # pyright: ignore[reportMissingModuleSource]
    from atheris.instrument_bytecode import (  # pyright: ignore[reportMissingModuleSource]
        instrument_all,
    )
    from fuzz_seeds import SBOM_SEEDS, write_corpus

    args = sys.argv
    # libFuzzer runs file arguments one by one instead of fuzzing, so
    # add the seed corpus only when no input was named.
    if not any(not arg.startswith("-") for arg in args[1:]):
        corpus = tempfile.mkdtemp(prefix="fuzz-sbom-corpus-")
        write_corpus(corpus, SBOM_SEEDS)
        args = [*args, corpus]
    instrument_all()
    atheris.Setup(args, check)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
