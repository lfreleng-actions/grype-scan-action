#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Read CycloneDX documents defensively, without judging them.

An SBOM is external input: it can be valid JSON and still carry the
wrong type in any field, an empty string where an identifier belongs,
or a reference to a component it never defines. These helpers turn
every such case into an absence, so the caller sees 'nothing usable'
rather than an exception that would abort the run before its summary.

Deciding what a document means is ``provenance``'s job, not this
module's.
"""

from __future__ import annotations

import json
import os

# The scopes CycloneDX defines.
VALID_SCOPES = frozenset({"required", "optional", "excluded"})

# The purl qualifier cyclonedx-gradle-plugin sets on each project.
PROJECT_PATH = "project_path"


def as_list(value: object) -> list:
    """The value when it is a list, else nothing."""
    return value if isinstance(value, list) else []


def as_dict(value: object) -> dict:
    """The value when it is a mapping, else nothing."""
    return value if isinstance(value, dict) else {}


def identifier(value: object) -> str:
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


def is_cyclonedx(doc: dict) -> bool:
    """Whether the document declares itself a CycloneDX BOM.

    Both fields are mandatory in the CycloneDX JSON schema, and both
    were confirmed present in real cyclonedx-maven, cyclonedx-gradle
    and cyclonedx-py output. Checking them keeps a JSON document that
    merely happens to carry dependency-shaped fields from being read as
    a graph. Which versions are trusted is policy, and is decided in
    ``provenance`` against the versions actually measured.
    """
    return doc.get("bomFormat") == "CycloneDX" and isinstance(
        doc.get("specVersion"), str
    )


def scopes_usable(doc: dict) -> bool:
    """Whether every scope present is one CycloneDX defines.

    The type is checked before the set lookup: a list or object here
    is unhashable, and would raise rather than read as malformed.
    """
    for component in as_list(doc.get("components")):
        if not isinstance(component, dict):
            continue
        scope = component.get("scope")
        if scope is None:
            continue
        if not isinstance(scope, str) or scope not in VALID_SCOPES:
            return False
    return True


def generators(doc: dict) -> set[str]:
    """Names of the tools that produced this document.

    CycloneDX 1.4 lists tools directly under ``metadata.tools``; 1.5
    wraps them in ``components``. Both shapes are read, since the
    schema version is the caller's choice, not ours.
    """
    tools = as_dict(doc.get("metadata")).get("tools")
    entries = as_list(tools) + as_list(as_dict(tools).get("components"))
    return {
        entry["name"]
        for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }


def root_component(doc: dict) -> dict:
    """The document's own subject, ``metadata.component``."""
    return as_dict(as_dict(doc.get("metadata")).get("component"))


def components(doc: dict) -> list[dict]:
    """Every component entry that is at least a mapping."""
    return [c for c in as_list(doc.get("components")) if isinstance(c, dict)]


def known_refs(doc: dict) -> set[str]:
    """Every reference the document actually defines.

    The metadata component counts even though it sits outside the
    component list. A reference to anything else resolves to no
    package, so the graph cannot say whether it is a dependency or a
    module of the project, and an edge through it must not establish
    either.
    """
    refs = {identifier(component.get("bom-ref")) for component in components(doc)}
    refs.add(identifier(root_component(doc).get("bom-ref")))
    refs.discard("")
    return refs


def edges(doc: dict, known: set[str]) -> dict[str, list[str]]:
    """Map each component reference to the references it depends on.

    Edges touching a reference the document never defines are
    dropped rather than followed: traversing one would let a gap in
    the component list decide that something is inherited.
    """
    graph: dict[str, list[str]] = {}
    for entry in as_list(doc.get("dependencies")):
        if not isinstance(entry, dict):
            continue
        ref = identifier(entry.get("ref"))
        if ref not in known:
            continue
        targets = [
            target
            for target in (identifier(item) for item in as_list(entry.get("dependsOn")))
            if target in known
        ]
        graph.setdefault(ref, []).extend(targets)
    return graph


def project_path(purl: str) -> str | None:
    """The purl's 'project_path' qualifier: None absent, '' if unusable.

    Matched as a qualifier key, never as a substring, so a package that
    merely has 'project_path' in its name does not count. A blank value
    is reported distinctly so the caller can treat it as malformed
    rather than as either answer. So is a repeated key: purl qualifier
    keys are unique, and choosing between two values would make the
    answer depend on their order.
    """
    _, _, query = purl.partition("#")[0].partition("?")
    values = [
        value
        for key, _, value in (pair.partition("=") for pair in query.split("&"))
        if key == PROJECT_PATH
    ]
    if not values:
        return None
    if len(values) > 1:
        return ""
    return values[0]
