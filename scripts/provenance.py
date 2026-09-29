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

import json
import os
from dataclasses import dataclass

DIRECT = "direct"
TRANSITIVE = "transitive"

SOURCE_NONE = "none"
SOURCE_GRAPH = "sbom-graph"
SOURCE_FILE = "file"

AUTO = "auto"

# Generators whose output has been measured. Both rules below read
# conventions rather than guarantees: CycloneDX does not say whether a
# first-level dependency is a third-party package or a sub-component
# of the project, and leaves scope optional throughout. Reading either
# from an unmeasured producer risks calling a declared package
# inherited, which downgrades it. Where a generator is not listed,
# declared-dependencies is the supported route.
MEASURED_GENERATORS = frozenset({"cyclonedx-maven-plugin", "cyclonedx-py"})

# Of those, the generators that mark third-party components with a
# scope and leave the project's own modules unscoped.
REACTOR_GENERATORS = frozenset({"cyclonedx-maven-plugin"})

# The scopes CycloneDX defines. A component carrying anything else is
# not a document we can reason about: the reactor rule reads scope as
# 'third-party', so an unrecognised value would exclude a module from
# the project and downgrade what it declares.
VALID_SCOPES = frozenset({"required", "optional", "excluded"})


def _as_list(value: object) -> list:
    """The value when it is a list, else nothing.

    An SBOM is external input. A document can be valid JSON and still
    carry the wrong type in any field, and raising from here would
    abort the run before the summary rather than leaving every finding
    classified as declared.
    """
    return value if isinstance(value, list) else []


def _as_dict(value: object) -> dict:
    """The value when it is a mapping, else nothing."""
    return value if isinstance(value, dict) else {}


def _identifier(value: object) -> str:
    """The value when it is a usable identifier, else empty.

    An empty string is not an identity. Accepting one lets unrelated
    records collide on it, and on these paths a collision means
    inheriting a classification rather than failing closed.
    """
    return value if isinstance(value, str) and value else ""


def load_document(path: str) -> dict | None:
    """Read a CycloneDX document; None when it cannot be used.

    JSON only. A CycloneDX XML document carries the same graph, but
    reading it is a separate parser, so an XML-only SBOM resolves to
    'no classifier' and every finding stays declared. The
    provenance-source output reports that rather than leaving it to be
    inferred from an absence of warnings.

    ValueError covers both a malformed document and one that is not
    valid UTF-8, neither of which may abort the run: an SBOM we cannot
    interpret means we cannot classify, not that we cannot scan.
    """
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def _known_refs(doc: dict) -> set[str]:
    """Every reference the document actually defines.

    The metadata component counts even though it sits outside the
    component list. A reference to anything else resolves to no
    package, so the graph cannot say whether it is a dependency or a
    module of the project, and an edge through it must not establish
    either.
    """
    refs: set[str] = set()
    root = _identifier(
        _as_dict(_as_dict(doc.get("metadata")).get("component")).get("bom-ref")
    )
    if root:
        refs.add(root)
    for component in _as_list(doc.get("components")):
        if not isinstance(component, dict):
            continue
        ref = _identifier(component.get("bom-ref"))
        if ref:
            refs.add(ref)
    return refs


def _edges(doc: dict, known: set[str]) -> dict[str, list[str]]:
    """Map each component reference to the references it depends on.

    Edges touching a reference the document never defines are
    dropped rather than followed: traversing one would let a gap in
    the component list decide that something is inherited.
    """
    edges: dict[str, list[str]] = {}
    for entry in _as_list(doc.get("dependencies")):
        if not isinstance(entry, dict):
            continue
        ref = _identifier(entry.get("ref"))
        if ref not in known:
            continue
        targets = [
            target
            for target in (
                _identifier(item) for item in _as_list(entry.get("dependsOn"))
            )
            if target in known
        ]
        edges.setdefault(ref, []).extend(targets)
    return edges


def _generators(doc: dict) -> set[str]:
    """Names of the tools that produced this document.

    CycloneDX 1.4 lists tools directly under ``metadata.tools``; 1.5
    wraps them in ``components``. Both shapes are read, since the
    schema version is the caller's choice, not ours.
    """
    tools = _as_dict(doc.get("metadata")).get("tools")
    entries = _as_list(tools) + _as_list(_as_dict(tools).get("components"))
    return {
        entry["name"]
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }


def _project_refs(doc: dict, edges: dict[str, list[str]]) -> set[str]:
    """References describing the project rather than a dependency.

    Two shapes occur in practice, both measured against real output:

    * A single root. ``cyclonedx-py --pyproject`` names the project in
      ``metadata.component`` and hangs the declared set off it.
    * A reactor. ``cyclonedx-maven makeAggregateBom`` names the
      aggregator POM in ``metadata.component`` but gives it no
      dependencies of its own. The modules are separate components,
      and a module that a sibling module depends on would otherwise be
      indistinguishable from a third-party library.

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
    refs: set[str] = set()
    root = _identifier(
        _as_dict(_as_dict(doc.get("metadata")).get("component")).get("bom-ref")
    )
    if root:
        refs.add(root)

    if not root or root not in edges:
        return refs

    if not REACTOR_GENERATORS & _generators(doc):
        return refs

    components = [c for c in _as_list(doc.get("components")) if isinstance(c, dict)]
    if not any(component.get("scope") for component in components):
        return refs

    for component in components:
        if component.get("scope"):
            continue
        ref = _identifier(component.get("bom-ref"))
        if ref:
            refs.add(ref)
    return refs


def _is_cyclonedx(doc: dict) -> bool:
    """Whether the document declares itself a CycloneDX BOM.

    Both fields are mandatory in the CycloneDX JSON schema, and both
    were confirmed present in real cyclonedx-maven and cyclonedx-py
    output. Checking them keeps a JSON document that merely happens to
    carry dependency-shaped fields from being read as a graph.
    """
    return doc.get("bomFormat") == "CycloneDX" and isinstance(
        doc.get("specVersion"), str
    )


def _scopes_usable(doc: dict) -> bool:
    """Whether every scope present is one CycloneDX defines."""
    for component in _as_list(doc.get("components")):
        if not isinstance(component, dict):
            continue
        scope = component.get("scope")
        if scope is not None and scope not in VALID_SCOPES:
            return False
    return True


def classify_document(doc: dict) -> tuple[dict[str, str], str]:
    """Classify every reference in a CycloneDX document."""
    if not _is_cyclonedx(doc):
        return {}, SOURCE_NONE

    if not MEASURED_GENERATORS & _generators(doc):
        return {}, SOURCE_NONE

    if not _scopes_usable(doc):
        return {}, SOURCE_NONE

    edges = _edges(doc, _known_refs(doc))
    if not edges:
        return {}, SOURCE_NONE

    project = _project_refs(doc, edges)
    declared: set[str] = set()
    for ref in project:
        declared.update(edges.get(ref, []))
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
        for child in edges.get(queue.pop(), []):
            if child in seen:
                continue
            seen.add(child)
            inherited.add(child)
            queue.append(child)

    classes = dict.fromkeys(project | declared, DIRECT)
    classes.update(dict.fromkeys(inherited, TRANSITIVE))
    return classes, SOURCE_GRAPH


def _purl_index(doc: dict, classes: dict[str, str]) -> dict[str, str]:
    """Index classifications by purl, for joining without a bom-ref."""
    index: dict[str, str] = {}
    for component in _as_list(doc.get("components")):
        if not isinstance(component, dict):
            continue
        ref = _identifier(component.get("bom-ref"))
        purl = _identifier(component.get("purl"))
        if not (ref and purl):
            continue
        # A component the graph never placed cannot vouch for a purl,
        # so it contributes the declared answer rather than being
        # skipped: skipping it would leave a classified namesake to
        # speak for a purl that does not identify either of them.
        value = classes.get(ref, DIRECT)
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
            # The list is the declaration of record. A package absent
            # from it is inherited, so the list has to be complete;
            # an incomplete one understates what the project owns.
            identifiers = [
                value
                for value in (
                    _identifier(artifact.get("purl")),
                    _identifier(artifact.get("name")),
                )
                if value
            ]
            if not identifiers:
                # Nothing to look up. Absence from the list has to be
                # established, not inferred from an artifact we could
                # not identify in the first place.
                return DIRECT
            if any(value in self.declared for value in identifiers):
                return DIRECT
            return TRANSITIVE

        ref = _identifier(artifact.get("id"))
        if ref and self.by_ref and ref in self.by_ref:
            return self.by_ref[ref]
        purl = _identifier(artifact.get("purl"))
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
