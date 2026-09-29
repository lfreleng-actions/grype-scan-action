#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Classify findings by whether the project declared the dependency.

Grype reports what is vulnerable, not who asked for it. A project can
act on a dependency it declared; one pulled in several levels down by
something else is a different problem, and blocking a merge on it makes
the gate a tax on work that cannot fix it.

CycloneDX carries the answer in its ``dependencies`` graph, and Grype
preserves each component's ``bom-ref`` as ``artifact.id``, so the graph
reaches this action inside the SBOM it already scans. No checkout and
no extra job wiring are needed.

Every uncertainty resolves to ``direct``, which gates. Leniency has to
be earned by evidence, never granted by a gap in it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from scripts.cyclonedx import (
    components,
    edges,
    generators,
    identifier,
    is_cyclonedx,
    known_refs,
    load_document,
    project_path,
    root_component,
    scopes_usable,
)

DIRECT = "direct"
TRANSITIVE = "transitive"

SOURCE_NONE = "none"
SOURCE_GRAPH = "sbom-graph"
SOURCE_FILE = "file"

AUTO = "auto"

# Generators whose output has been measured. Every rule below reads
# conventions rather than guarantees: CycloneDX does not say whether a
# first-level dependency is a third-party package or a sub-component
# of the project, and leaves scope optional throughout. Reading either
# from an unmeasured producer risks calling a declared package
# inherited, which downgrades it. Where a generator is not listed,
# declared-dependencies is the supported route. cyclonedx-maven names
# itself by display name in schema 1.4 and by artifact ID from 1.5.
MEASURED_GENERATORS = frozenset(
    {
        "CycloneDX Maven plugin",
        "cyclonedx-gradle-plugin",
        "cyclonedx-maven-plugin",
        "cyclonedx-py",
    }
)

# The schema versions at which every generator above was measured to
# classify identically. A version outside this set, or a malformed
# one, is refused rather than assumed to share the shape.
MEASURED_SPEC_VERSIONS = frozenset({"1.4", "1.5", "1.6"})

# Of those, the generators that mark third-party components with a
# scope and leave the project's own modules unscoped.
REACTOR_GENERATORS = frozenset({"CycloneDX Maven plugin", "cyclonedx-maven-plugin"})

# Of those, the generators that mark each project in the build with a
# 'project_path' purl qualifier. The plugin sets it from Gradle's own
# ProjectComponentIdentifier, so an external module cannot carry it.
# Verified in the plugin source at every release from 2.2.0, where it
# first appears, through 3.4.1 and master. 1.x and 2.0-2.1 never emit
# it, which the rule detects rather than assumes.
GRADLE_GENERATORS = frozenset({"cyclonedx-gradle-plugin"})


def _gradle_project_refs(doc: dict) -> set[str]:
    """Projects in a Gradle build, identified by their purl marker.

    cyclonedx-gradle-plugin leaves the root project out of the graph
    and sets no scope on anything, so neither of the other rules can
    work here. It does mark every project in the build — the root, the
    subprojects, and any included build — with a 'project_path' purl
    qualifier taken from Gradle's ProjectComponentIdentifier, which an
    external module structurally cannot carry.

    The rule engages only when the root's purl carries the marker,
    which proves the document uses it: plugins before 2.2.0 never emit
    it, and without it every module would look like a third-party
    library and what each one declares would look inherited. A blank
    marker
    anywhere is malformed, and refuses the document outright.
    """
    root = root_component(doc)
    root_ref = identifier(root.get("bom-ref"))
    if not root_ref or not project_path(identifier(root.get("purl"))):
        return set()

    refs = {root_ref}
    for component in components(doc):
        path = project_path(identifier(component.get("purl")))
        if path is None:
            continue
        if not path:
            return set()
        ref = identifier(component.get("bom-ref"))
        if ref:
            refs.add(ref)
    return refs


def _project_refs(doc: dict, graph: dict[str, list[str]]) -> set[str]:
    """References describing the project rather than a dependency.

    Three shapes occur in practice, all measured against real output:

    * A single root. ``cyclonedx-py --pyproject`` names the project in
      ``metadata.component`` and hangs the declared set off it.
    * A reactor. ``cyclonedx-maven makeAggregateBom`` names the
      aggregator POM in ``metadata.component`` but gives it no
      dependencies of its own. The modules are separate components,
      and a module that a sibling module depends on would otherwise be
      indistinguishable from a third-party library.
    * A Gradle build, handled by ``_gradle_project_refs``. It is
      exclusive: a Gradle document that fails its checks is refused
      rather than offered to the single-root rule, which would read
      every subproject as a third-party library.

    ``scope`` separates the reactor case: cyclonedx-maven marks
    third-party components 'required' and leaves modules unscoped.
    That is a property of one generator, not of CycloneDX, which
    leaves ``scope`` optional everywhere — so the rule applies only to
    a document that names a generator whose shape has been measured,
    and only where the named root is part of the graph.
    cyclonedx-maven lists the aggregator with an empty ``dependsOn``,
    whereas syft names the scanned directory, which appears nowhere in
    the graph and must not license promoting anything.
    """
    if GRADLE_GENERATORS & generators(doc):
        return _gradle_project_refs(doc)

    root = identifier(root_component(doc).get("bom-ref"))
    if not root:
        return set()
    refs = {root}
    if root not in graph or not REACTOR_GENERATORS & generators(doc):
        return refs

    listed = components(doc)
    if not any(component.get("scope") for component in listed):
        return refs

    for component in listed:
        if component.get("scope"):
            continue
        ref = identifier(component.get("bom-ref"))
        if ref:
            refs.add(ref)
    return refs


def classify_document(doc: dict) -> tuple[dict[str, str], str]:
    """Classify every reference in a CycloneDX document."""
    if not is_cyclonedx(doc):
        return {}, SOURCE_NONE

    if doc.get("specVersion") not in MEASURED_SPEC_VERSIONS:
        return {}, SOURCE_NONE

    if not MEASURED_GENERATORS & generators(doc):
        return {}, SOURCE_NONE

    if not scopes_usable(doc):
        return {}, SOURCE_NONE

    graph = edges(doc, known_refs(doc))
    if not graph:
        return {}, SOURCE_NONE

    project = _project_refs(doc, graph)
    declared: set[str] = set()
    for ref in project:
        declared.update(graph.get(ref, []))
    declared -= project
    if not declared:
        # Nothing usable to anchor on: an unrooted graph, as a
        # lock-file Python environment produces, or a root that is not
        # part of the graph, as syft produces by naming the scanned
        # directory. Classifying either would be guesswork.
        return {}, SOURCE_NONE

    inherited: set[str] = set()
    seen = set(declared) | project
    queue = list(declared)
    while queue:
        for child in graph.get(queue.pop(), []):
            if child in seen:
                continue
            seen.add(child)
            inherited.add(child)
            queue.append(child)

    classes = dict.fromkeys(project | declared, DIRECT)
    classes.update(dict.fromkeys(inherited, TRANSITIVE))
    return classes, SOURCE_GRAPH


def _purl_index(doc: dict, classes: dict[str, str]) -> dict[str, str]:
    """Index classifications by purl, for joining without a bom-ref.

    Every purl-bearing entry takes part, the document's own subject
    included. An entry the graph never placed, or one with no usable
    ``bom-ref`` at all, cannot vouch for a purl, so it contributes the
    declared answer rather than being skipped: skipping it would leave
    a classified namesake to speak for a purl that does not identify
    either of them.
    """
    index: dict[str, str] = {}
    for entry in [*components(doc), root_component(doc)]:
        purl = identifier(entry.get("purl"))
        if not purl:
            continue
        ref = identifier(entry.get("bom-ref"))
        value = classes.get(ref, DIRECT) if ref else DIRECT
        # Two components can share a purl while sitting at different
        # depths. Let the stricter answer win rather than whichever
        # happens to be listed last, so a trailing inherited duplicate
        # cannot downgrade a package the project also declares.
        if index.get(purl) == DIRECT:
            continue
        index[purl] = value
    return index


def load_declared(path: str) -> set[str] | None:
    """Read a declared-dependency list: one purl or name per line.

    None means no usable list, which leaves every finding declared.

    A readable but empty file counts as no list, rather than as 'this
    project declares nothing'. The second reading would mark every
    package inherited and so hand a producer that wrote the file
    wrongly the power to disable the gate, which is the outcome this
    module exists to prevent. A project genuinely declaring nothing
    has no third-party components to classify in the first place.
    """
    if not path or not os.path.exists(path):
        return None
    entries: set[str] = set()
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    entries.add(stripped)
    except (OSError, ValueError):
        return None
    return entries or None


def _declared_verdict(declared: set[str], artifact: dict) -> str:
    """Classify against a declared list; absence must be provable.

    The list is the declaration of record, so a package absent from it
    is inherited and the list has to be complete. But a purl and a
    name are different identifiers, and absence in one form proves
    nothing about the other: a list naming 'pkg:npm/lodash@4.17.4'
    says nothing about an artifact known only as 'lodash'. So an
    artifact counts as inherited only when it can be checked against
    every form the list uses, and is absent from all of them.
    """
    listed_purls = {entry for entry in declared if entry.startswith("pkg:")}
    listed_names = declared - listed_purls
    purl = identifier(artifact.get("purl"))
    name = identifier(artifact.get("name"))
    if (purl and purl in listed_purls) or (name and name in listed_names):
        return DIRECT
    if (listed_purls and not purl) or (listed_names and not name):
        return DIRECT
    return TRANSITIVE


@dataclass
class Provenance:
    """Answers 'did this project declare that package?' for one SBOM."""

    source: str = SOURCE_NONE
    by_ref: dict[str, str] | None = None
    by_purl: dict[str, str] | None = None
    declared: set[str] | None = None

    def classify(self, artifact: dict) -> str:
        """Classify one Grype artifact; anything unresolved is direct."""
        if self.source == SOURCE_FILE and self.declared is not None:
            return _declared_verdict(self.declared, artifact)

        ref = identifier(artifact.get("id"))
        if ref and self.by_ref and ref in self.by_ref:
            return self.by_ref[ref]
        purl = identifier(artifact.get("purl"))
        if purl and self.by_purl and purl in self.by_purl:
            return self.by_purl[purl]
        return DIRECT


def build(sbom_path: str, declared_path: str, source: str) -> Provenance:
    """Build the classifier for one artefact, honouring the source."""
    if source == SOURCE_NONE:
        return Provenance()

    if source in (AUTO, SOURCE_FILE):
        declared = load_declared(declared_path)
        if declared is not None:
            return Provenance(source=SOURCE_FILE, declared=declared)
        # A list the caller configured but which cannot be read is a
        # misconfiguration, not an invitation to guess from the graph.
        # Only an unset path falls through.
        if declared_path or source == SOURCE_FILE:
            return Provenance()

    if source in (AUTO, SOURCE_GRAPH):
        doc = load_document(sbom_path)
        if doc is not None:
            classes, resolved = classify_document(doc)
            if resolved == SOURCE_GRAPH:
                return Provenance(
                    source=SOURCE_GRAPH,
                    by_ref=classes,
                    by_purl=_purl_index(doc, classes),
                )

    return Provenance()
