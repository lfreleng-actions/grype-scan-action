#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline tests for dependency provenance classification.

The document shapes here are not invented: each mirrors output
measured from a real generator, named in the case that uses it. The
classifier decides whether a finding gates or only warns, so a shape
it misreads would silently downgrade a finding the project owns.
"""

from __future__ import annotations

import json
import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from scripts.provenance import (  # noqa: E402
    DIRECT,
    SOURCE_FILE,
    SOURCE_GRAPH,
    SOURCE_NONE,
    TRANSITIVE,
    build,
    classify_document,
)

FAILURES: list[str] = []


def check(label: str, condition: bool, detail: object = "") -> None:
    if condition:
        print(f"  ✅ {label}")
    else:
        print(f"  ❌ {label} {detail}")
        FAILURES.append(label)


def component(ref: str, purl: str | None = None, scope: str | None = None) -> dict:
    """One CycloneDX component.

    An explicitly supplied empty purl is preserved rather than
    dropped, so a fixture can carry one: that is the shape the index
    has to refuse.
    """
    entry: dict = {"bom-ref": ref, "type": "library", "name": ref}
    if purl is not None:
        entry["purl"] = purl
    if scope is not None:
        entry["scope"] = scope
    return entry


def document(
    root: str | None,
    components: list[dict],
    graph: dict,
    generator: str | None = None,
) -> dict:
    """A CycloneDX document with the given root and dependency graph."""
    doc: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": components,
        "dependencies": [
            {"ref": ref, "dependsOn": targets} for ref, targets in graph.items()
        ],
    }
    metadata: dict = {}
    if root is not None:
        metadata["component"] = {"bom-ref": root, "name": root}
    if generator is not None:
        metadata["tools"] = {"components": [{"type": "library", "name": generator}]}
    if metadata:
        doc["metadata"] = metadata
    return doc


def written(text: str) -> str:
    """Write a declared-dependency list and return its path."""
    handle = tempfile.NamedTemporaryFile(
        "w", suffix=".txt", delete=False, encoding="utf-8"
    )
    handle.write(text)
    handle.close()
    return handle.name


print("single-root graph (cyclonedx-py --pyproject)")
doc = document(
    "root",
    [component("root"), component("requests"), component("urllib3")],
    {"root": ["requests"], "requests": ["urllib3"], "urllib3": []},
    generator="cyclonedx-py",
)
classes, source = classify_document(doc)
check("source is the graph", source == SOURCE_GRAPH, source)
check("declared dependency is direct", classes.get("requests") == DIRECT, classes)
check("its dependency is transitive", classes.get("urllib3") == TRANSITIVE, classes)
check("the project itself is direct", classes.get("root") == DIRECT, classes)

# CycloneDX does not say whether a first-level dependency is a
# third-party package or a module of the project, so the same shape
# from an unmeasured producer could be an aggregate BOM whose modules
# would wrongly make their own declarations look inherited.
classes, source = classify_document(
    document(
        "root",
        [component("root"), component("requests"), component("urllib3")],
        {"root": ["requests"], "requests": ["urllib3"], "urllib3": []},
    )
)
check(
    "an unnamed generator refuses the single-root rule",
    source == SOURCE_NONE and not classes,
    classes,
)

print("reactor graph (cyclonedx-maven makeAggregateBom)")
# The aggregator names itself in metadata.component but depends on
# nothing; the modules are separate components, and 'core' is depended
# on by 'app'. Only the absence of scope separates a module from a
# third-party library, so this is the case that must not regress.
REACTOR_COMPONENTS = [
    component("project"),
    component("parent"),
    component("core"),
    component("app"),
    component("jackson-databind", scope="required"),
    component("jackson-core", scope="required"),
]
REACTOR_GRAPH = {
    "project": [],
    "parent": ["core", "app"],
    "app": ["core"],
    "core": ["jackson-databind"],
    "jackson-databind": ["jackson-core"],
    "jackson-core": [],
}
doc = document(
    "project",
    REACTOR_COMPONENTS,
    REACTOR_GRAPH,
    generator="cyclonedx-maven-plugin",
)
classes, source = classify_document(doc)
check("source is the graph", source == SOURCE_GRAPH, source)
check(
    "a module depended on by a sibling stays part of the project",
    classes.get("core") == DIRECT,
    classes,
)
check(
    "the module's declared dependency is direct",
    classes.get("jackson-databind") == DIRECT,
    classes,
)
check(
    "what that dependency pulls in is transitive",
    classes.get("jackson-core") == TRANSITIVE,
    classes,
)

# scope is optional throughout CycloneDX, so a partly scoped document
# from an unmeasured generator must not license the same promotion.
classes, source = classify_document(
    document("project", REACTOR_COMPONENTS, REACTOR_GRAPH)
)
check(
    "an unnamed generator refuses the reactor rule",
    source == SOURCE_NONE and not classes,
    classes,
)

classes, source = classify_document(
    document("project", REACTOR_COMPONENTS, REACTOR_GRAPH, generator="syft")
)
check(
    "an unmeasured generator refuses the reactor rule",
    source == SOURCE_NONE and not classes,
    classes,
)

# A scope CycloneDX does not define cannot be read as 'third-party',
# and reading it that way would exclude a module from the project and
# downgrade what that module declares. A list or object is unhashable
# too, so it must be refused rather than crash the set lookup.
for label, bad in (
    ("a numeric scope", 7),
    ("an unknown scope", "runtime"),
    ("a list scope", ["required"]),
    ("an object scope", {"value": "required"}),
):
    broken = document(
        "project",
        [
            component("project"),
            component("core", scope=None),
            component("jackson-databind", scope="required"),
        ],
        REACTOR_GRAPH,
        generator="cyclonedx-maven-plugin",
    )
    broken["components"][1]["scope"] = bad
    classes, source = classify_document(broken)
    check(
        f"{label} refuses classification",
        source == SOURCE_NONE and not classes,
        classes,
    )

# An edge may name a reference the component list never defines. The
# graph then cannot say whether that reference is a third-party
# package or a module of the project, so nothing beyond it is
# established either.
broken = document(
    "project",
    [
        component("project"),
        component("parent"),
        # 'core' is deliberately absent from the component list
        component("app"),
        component("jackson-databind", scope="required"),
        component("jackson-core", scope="required"),
    ],
    REACTOR_GRAPH,
    generator="cyclonedx-maven-plugin",
)
classes, source = classify_document(broken)
check(
    "an undefined reference does not downgrade what hangs off it",
    classes.get("jackson-databind") != TRANSITIVE,
    classes,
)
check(
    "and leaves the document unclassified",
    source == SOURCE_NONE and not classes,
    classes,
)

print("gradle build (cyclonedx-gradle-plugin cyclonedxBom)")
# Mirrors real 3.4.1 output for lfreleng-actions/test-gradle-project,
# as sbom-action generates it. Unlike Maven, the root project is left
# out of the graph and nothing carries a scope; every project in the
# build is marked instead by a 'project_path' purl qualifier, which
# the plugin takes from Gradle's ProjectComponentIdentifier.
G = "pkg:maven/org.lfreleng.test/"
J = "pkg:maven/com.fasterxml.jackson.core/"
G_ROOT = G + "test-gradle-project@1.0.0-SNAPSHOT?project_path=%3A"
G_APP = G + "app@1.0.0-SNAPSHOT?project_path=%3Aapp"
G_CORE = G + "core@1.0.0-SNAPSHOT?project_path=%3Acore"
G_NESTED = G + "nested@1.0.0-SNAPSHOT?project_path=%3Aapp%3Anested"
G_DATABIND = J + "jackson-databind@2.9.10?type=jar"
G_JCORE = J + "jackson-core@2.9.10?type=jar"
G_ANNOTATIONS = J + "jackson-annotations@2.9.10?type=jar"
G_BOM = "pkg:maven/com.fasterxml.jackson/jackson-bom@2.9.10?type=pom"
G_LANG = "pkg:maven/org.apache.commons/commons-lang3@3.20.0?type=jar"


def gradle_document(root_purl: str = G_ROOT, extra: list | None = None) -> dict:
    """A document in the shape cyclonedx-gradle-plugin emits."""
    refs = [
        G_ANNOTATIONS,
        G_JCORE,
        G_DATABIND,
        G_BOM,
        G_LANG,
        G_APP,
        G_CORE,
        G_NESTED,
    ] + (extra or [])
    doc = document(
        G_ROOT,
        [component(ref, purl=ref) for ref in refs],
        {
            G_ANNOTATIONS: [],
            G_JCORE: [],
            G_DATABIND: [G_ANNOTATIONS, G_JCORE],
            G_BOM: [],
            G_LANG: [],
            G_APP: [G_CORE],
            G_CORE: [G_DATABIND, G_BOM],
            G_NESTED: [G_LANG],
        },
        generator="cyclonedx-gradle-plugin",
    )
    doc["metadata"]["component"]["purl"] = root_purl
    return doc


classes, source = classify_document(gradle_document())
check("source is the graph", source == SOURCE_GRAPH, source)
check(
    "a subproject depended on by a sibling stays part of the build",
    classes.get(G_CORE) == DIRECT,
    classes,
)
check(
    "what a subproject declares is direct",
    classes.get(G_DATABIND) == DIRECT and classes.get(G_BOM) == DIRECT,
    classes,
)
check(
    "a nested subproject's declaration is direct",
    classes.get(G_LANG) == DIRECT,
    classes,
)
check(
    "what those declarations pull in is transitive",
    classes.get(G_JCORE) == TRANSITIVE and classes.get(G_ANNOTATIONS) == TRANSITIVE,
    classes,
)

# Plugins before 2.2.0 never emit the marker. Without it every
# subproject would look third-party and what each declares would look
# inherited, so the rule has to see the marker on the root first.
unmarked = gradle_document(root_purl=G + "test-gradle-project@1.0.0-SNAPSHOT")
classes, source = classify_document(unmarked)
check(
    "a root without the marker refuses classification",
    source == SOURCE_NONE and not classes,
    classes,
)

# The rule is exclusive. A Gradle document failing it must not be
# offered to the single-root rule, which would read the subprojects as
# third-party libraries by another route.
rooted = gradle_document(root_purl=G + "test-gradle-project@1.0.0-SNAPSHOT")
rooted["dependencies"].append({"ref": G_ROOT, "dependsOn": [G_APP, G_CORE]})
classes, source = classify_document(rooted)
check(
    "a failing Gradle document does not fall through to another rule",
    source == SOURCE_NONE and not classes,
    classes,
)

blank = "pkg:maven/org.example/oddity@1.0.0?project_path="
classes, source = classify_document(gradle_document(extra=[blank]))
check(
    "a blank marker anywhere refuses classification",
    source == SOURCE_NONE and not classes,
    classes,
)

# Purl qualifier keys are unique, so a repeated marker is malformed
# whatever its values and in whichever order they appear.
for label, repeated in (
    ("a valid value then a blank", "?project_path=%3Ax&project_path="),
    ("a blank then a valid value", "?project_path=&project_path=%3Ax"),
    ("two valid values", "?project_path=%3Ax&project_path=%3Ay"),
):
    classes, source = classify_document(
        gradle_document(extra=["pkg:maven/org.example/twice@1.0.0" + repeated])
    )
    check(
        f"a repeated marker ({label}) refuses classification",
        source == SOURCE_NONE and not classes,
        classes,
    )

# The same holds on the root, whose marker is what engages the rule.
for label, suffix in (
    ("a second valid value", "&project_path=%3Ay"),
    ("a second blank value", "&project_path="),
):
    classes, source = classify_document(gradle_document(root_purl=G_ROOT + suffix))
    check(
        f"a root repeating its marker with {label} refuses classification",
        source == SOURCE_NONE and not classes,
        classes,
    )

# The marker is a qualifier key. A package whose name merely contains
# it is an ordinary dependency, not part of the build.
namesake = "pkg:maven/org.example/project_path@1.0.0?type=jar"
doc = gradle_document(extra=[namesake])
doc["dependencies"].append({"ref": namesake, "dependsOn": []})
for entry in doc["dependencies"]:
    if entry["ref"] == G_DATABIND:
        entry["dependsOn"].append(namesake)
classes, source = classify_document(doc)
check(
    "a package named after the marker is not a project",
    classes.get(namesake) == TRANSITIVE,
    classes,
)

# Nor is one carrying a different qualifier whose key merely contains
# the marker: only an exact 'project_path' key counts.
lookalike = "pkg:maven/org.example/lib@1.0.0?type=jar&not_project_path=%3Ax"
doc = gradle_document(extra=[lookalike])
doc["dependencies"].append({"ref": lookalike, "dependsOn": []})
for entry in doc["dependencies"]:
    if entry["ref"] == G_DATABIND:
        entry["dependsOn"].append(lookalike)
classes, source = classify_document(doc)
check(
    "a lookalike qualifier key is not the marker",
    classes.get(lookalike) == TRANSITIVE,
    classes,
)

print("the document must say it is CycloneDX")
for label, mutate in (
    ("a missing bomFormat", "bomFormat"),
    ("a missing specVersion", "specVersion"),
):
    broken = document(
        "root",
        [component("root"), component("requests"), component("urllib3")],
        {"root": ["requests"], "requests": ["urllib3"], "urllib3": []},
        generator="cyclonedx-py",
    )
    del broken[mutate]
    check(
        f"{label} refuses classification",
        classify_document(broken)[1] == SOURCE_NONE,
        broken.get(mutate),
    )

broken = document(
    "root",
    [component("root"), component("requests"), component("urllib3")],
    {"root": ["requests"], "requests": ["urllib3"], "urllib3": []},
    generator="cyclonedx-py",
)
broken["bomFormat"] = "SPDX"
check(
    "another format refuses classification",
    classify_document(broken)[1] == SOURCE_NONE,
)

# Only the schema versions every producer was measured at classify.
# A malformed or unmeasured version could carry a different shape.
for label, version in (
    ("an empty specVersion", ""),
    ("a malformed specVersion", "not-a-version"),
    ("an unmeasured specVersion", "1.3"),
):
    broken = document(
        "root",
        [component("root"), component("requests"), component("urllib3")],
        {"root": ["requests"], "requests": ["urllib3"], "urllib3": []},
        generator="cyclonedx-py",
    )
    broken["specVersion"] = version
    check(
        f"{label} refuses classification",
        classify_document(broken)[1] == SOURCE_NONE,
    )

# cyclonedx-maven names itself by display name at schema 1.4, in the
# list form of metadata.tools. Measured; the shape is otherwise the same.
legacy_maven = document("project", REACTOR_COMPONENTS, REACTOR_GRAPH)
legacy_maven["specVersion"] = "1.4"
legacy_maven["metadata"]["tools"] = [{"name": "CycloneDX Maven plugin"}]
classes, source = classify_document(legacy_maven)
check(
    "cyclonedx-maven's 1.4 display name classifies",
    source == SOURCE_GRAPH and classes.get("jackson-core") == TRANSITIVE,
    classes,
)

# The 1.4 shape lists tools directly rather than under components.
legacy = document("project", REACTOR_COMPONENTS, REACTOR_GRAPH)
legacy["metadata"]["tools"] = [{"name": "cyclonedx-maven-plugin"}]
classes, source = classify_document(legacy)
check(
    "the 1.4 tools shape is recognised too",
    source == SOURCE_GRAPH and classes.get("jackson-core") == TRANSITIVE,
    classes,
)

print("unclassifiable shapes fall back to gating")
# cyclonedx-py against a lock-file project: real edges, but no root to
# anchor them to.
doc = document(
    None,
    [component("requests"), component("urllib3")],
    {"requests": ["urllib3"], "urllib3": []},
    generator="cyclonedx-py",
)
classes, source = classify_document(doc)
check("unrooted graph is refused", source == SOURCE_NONE and not classes, source)

# syft: metadata.component names the scanned directory, which is not
# part of the graph.
doc = document(
    "/workspace",
    [component("demo"), component("lodash")],
    {"demo": ["lodash"], "lodash": []},
    generator="cyclonedx-py",
)
classes, source = classify_document(doc)
check("root outside the graph is refused", source == SOURCE_NONE, source)

# syft against Go: no dependencies array at all.
classes, source = classify_document(
    document("root", [component("gin")], {}, generator="cyclonedx-py")
)
check("absent graph is refused", source == SOURCE_NONE, source)

check(
    "an empty document is refused",
    classify_document({})[1] == SOURCE_NONE,
    classify_document({}),
)

print("an empty string is not an identity")
# A blank ref has no identity, so a branch routed through one cannot
# establish that what hangs off it was inherited.
doc = document(
    "root",
    [component("root"), component("package")],
    {"root": [""], "": ["package"], "package": []},
    generator="cyclonedx-py",
)
classes, source = classify_document(doc)
check(
    "a blank intermediary leaves its descendants unclassified",
    classes.get("package") != TRANSITIVE,
    classes,
)

doc = document(
    "",
    [component("package")],
    {"": ["package"], "package": []},
    generator="cyclonedx-py",
)
classes, source = classify_document(doc)
check(
    "a blank root is not an anchor",
    source == SOURCE_NONE and not classes,
    classes,
)

doc = document(
    "root",
    [component("root"), component("direct-1"), component("trans-1", purl="")],
    {"root": ["direct-1"], "direct-1": ["trans-1"], "trans-1": []},
    generator="cyclonedx-py",
)
check(
    "the fixture really carries an empty purl",
    doc["components"][2].get("purl") == "",
    doc["components"][2],
)
provenance = build(written(json.dumps(doc)), "", "sbom-graph")
check(
    "a blank purl does not join an unresolved finding",
    provenance.classify({"id": "mystery", "purl": ""}) == DIRECT,
    provenance.by_purl,
)

# A root outside the graph must not license the reactor rule either:
# promoting every unscoped component would hand the graph's lower
# reaches a transitive classification they have not earned.
doc = document(
    "/workspace",
    [
        component("demo"),
        component("lodash", scope="required"),
        component("minimist", scope="required"),
    ],
    {"demo": ["lodash"], "lodash": ["minimist"], "minimist": []},
    generator="cyclonedx-maven-plugin",
)
classes, source = classify_document(doc)
check(
    "a root outside the graph blocks the reactor rule",
    source == SOURCE_NONE and not classes,
    classes,
)

print("conflicting classifications resolve to the stricter answer")
# The same package can appear twice at different depths. The purl
# index must not let whichever is listed last decide.
doc = document(
    "root",
    [
        component("root"),
        component("a-direct", purl="pkg:npm/shared@1.0.0"),
        component("b-transitive", purl="pkg:npm/shared@1.0.0"),
    ],
    {
        "root": ["a-direct"],
        "a-direct": ["b-transitive"],
        "b-transitive": [],
    },
    generator="cyclonedx-py",
)
provenance = build(written(json.dumps(doc)), "", "sbom-graph")
check(
    "a declared purl outranks an inherited duplicate",
    provenance.classify({"id": "unknown", "purl": "pkg:npm/shared@1.0.0"}) == DIRECT,
    provenance.by_purl,
)

# A component the graph never placed cannot vouch for a purl either.
# If it shares one with a classified component, the purl no longer
# identifies which of them a finding refers to.
doc = document(
    "root",
    [
        component("root"),
        component("direct-1"),
        component("trans-1", purl="pkg:npm/ambiguous@1.0.0"),
        component("orphan", purl="pkg:npm/ambiguous@1.0.0"),
    ],
    {"root": ["direct-1"], "direct-1": ["trans-1"], "trans-1": []},
    generator="cyclonedx-py",
)
provenance = build(written(json.dumps(doc)), "", "sbom-graph")
check(
    "an unplaced component outranks an inherited namesake",
    provenance.classify({"id": "unknown", "purl": "pkg:npm/ambiguous@1.0.0"}) == DIRECT,
    provenance.by_purl,
)
check(
    "an unambiguous inherited purl still resolves",
    provenance.classify({"id": "trans-1"}) == TRANSITIVE,
    provenance.by_ref,
)

# Neither an entry without a bom-ref nor the document's own subject
# can vouch for a purl, but both still make one ambiguous.
refless = document(
    "root",
    [
        component("root"),
        component("direct-1"),
        component("trans-1", purl="pkg:npm/ambiguous@1.0.0"),
    ],
    {"root": ["direct-1"], "direct-1": ["trans-1"], "trans-1": []},
    generator="cyclonedx-py",
)
refless["components"].append({"type": "library", "purl": "pkg:npm/ambiguous@1.0.0"})
provenance = build(written(json.dumps(refless)), "", "sbom-graph")
check(
    "an entry without a bom-ref still makes a purl ambiguous",
    provenance.classify({"purl": "pkg:npm/ambiguous@1.0.0"}) == DIRECT,
    provenance.by_purl,
)

subject = document(
    "root",
    [
        component("root"),
        component("direct-1"),
        component("trans-1", purl="pkg:npm/ambiguous@1.0.0"),
    ],
    {"root": ["direct-1"], "direct-1": ["trans-1"], "trans-1": []},
    generator="cyclonedx-py",
)
subject["metadata"]["component"]["purl"] = "pkg:npm/ambiguous@1.0.0"
provenance = build(written(json.dumps(subject)), "", "sbom-graph")
check(
    "the document's own subject still makes a purl ambiguous",
    provenance.classify({"purl": "pkg:npm/ambiguous@1.0.0"}) == DIRECT,
    provenance.by_purl,
)

print("joining findings to the graph")
doc = document(
    "root",
    [
        component("root"),
        component("direct-1", purl="pkg:npm/lodash@4.17.4"),
        component("trans-1", purl="pkg:npm/minimist@1.2.0"),
    ],
    {"root": ["direct-1"], "direct-1": ["trans-1"], "trans-1": []},
    generator="cyclonedx-py",
)
classes, _ = classify_document(doc)
path = written(json.dumps(doc))
provenance = build(path, "", "auto")
check(
    "joins on bom-ref, as Grype reports it in artifact.id",
    provenance.classify({"id": "trans-1"}) == TRANSITIVE,
    provenance.by_ref,
)
check(
    "falls back to purl when the ref is unknown",
    provenance.classify({"id": "other", "purl": "pkg:npm/minimist@1.2.0"})
    == TRANSITIVE,
    provenance.by_purl,
)
check(
    "an artifact matching neither is treated as declared",
    provenance.classify({"id": "mystery", "purl": "pkg:npm/mystery@1.0.0"}) == DIRECT,
)

print("declared-dependency file")
path = written("# project dependencies\npkg:npm/lodash@4.17.4\nexpress\n\n")
provenance = build("", path, "file")
check("source is the file", provenance.source == SOURCE_FILE, provenance.source)
check(
    "a listed purl is direct",
    provenance.classify({"name": "lodash", "purl": "pkg:npm/lodash@4.17.4"}) == DIRECT,
)
check(
    "a listed bare name is direct",
    provenance.classify({"name": "express", "purl": "pkg:npm/express@4.0.0"}) == DIRECT,
)
check(
    "anything absent from the list is inherited",
    provenance.classify({"name": "minimist", "purl": "pkg:npm/minimist@1.2.0"})
    == TRANSITIVE,
)
check(
    "comments and blank lines are ignored",
    provenance.classify(
        {"name": "# project dependencies", "purl": "pkg:npm/other@1.0.0"}
    )
    == TRANSITIVE,
)
check(
    "an artifact with no usable identifier stays declared",
    provenance.classify({}) == DIRECT,
)
check(
    "an empty identifier is not an identifier",
    provenance.classify({"name": "", "purl": ""}) == DIRECT,
)

# A purl and a name are different identifiers. Absence in one form
# proves nothing about the other, so an artifact counts as inherited
# only when it can be checked against every form the list uses.
for label, text, artifact in (
    (
        "a name-only artifact against a purl-only list stays declared",
        "pkg:npm/lodash@4.17.4\n",
        {"name": "lodash"},
    ),
    (
        "a purl-only artifact against a name-only list stays declared",
        "lodash\n",
        {"purl": "pkg:npm/lodash@4.17.4"},
    ),
    (
        "a name-only artifact listed by purl in a mixed list stays declared",
        "pkg:npm/lodash@4.17.4\nexpress\n",
        {"name": "lodash"},
    ),
):
    check(label, build("", written(text), "file").classify(artifact) == DIRECT)

check(
    "absence in every form the list uses is still inherited",
    build("", written("pkg:npm/lodash@4.17.4\nexpress\n"), "file").classify(
        {"name": "minimist", "purl": "pkg:npm/minimist@1.2.0"}
    )
    == TRANSITIVE,
)
check(
    "a name-only list still judges a name-only artifact",
    build("", written("express\n"), "file").classify({"name": "minimist"})
    == TRANSITIVE,
)

print("source selection")
graph_doc = written(json.dumps(doc))
declared = written("pkg:npm/minimist@1.2.0\n")
check(
    "auto prefers the file over the graph",
    build(graph_doc, declared, "auto").source == SOURCE_FILE,
)
check(
    "auto falls back to the graph when no file is given",
    build(graph_doc, "", "auto").source == SOURCE_GRAPH,
)
check(
    "sbom-graph ignores the file",
    build(graph_doc, declared, "sbom-graph").source == SOURCE_GRAPH,
)
check(
    "file does not fall back to the graph",
    build(graph_doc, "", "file").source == SOURCE_NONE,
)
check(
    "none disables classification",
    build(graph_doc, declared, "none").source == SOURCE_NONE,
)
check(
    "a disabled classifier treats everything as declared",
    build(graph_doc, declared, "none").classify({"id": "trans-1"}) == DIRECT,
)

print("unreadable inputs never downgrade a finding")
for label, payload in (
    ("malformed JSON", "not json"),
    ("a non-object document", "[]"),
):
    check(
        f"{label} is refused",
        build(written(payload), "", "sbom-graph").source == SOURCE_NONE,
    )

missing = tempfile.mkdtemp() + "/absent.json"
check(
    "a missing SBOM is refused",
    build(missing, "", "sbom-graph").source == SOURCE_NONE,
)
check(
    "a missing declared list is refused",
    build("", missing, "file").source == SOURCE_NONE,
)

# A truncated list must not read as 'this project declares nothing',
# which would mark every package inherited and disable the gate.
for label, payload in (
    ("an empty", ""),
    ("a comments-only", "# nothing here\n\n"),
):
    check(
        f"{label} declared list is refused",
        build("", written(payload), "file").source == SOURCE_NONE,
    )

handle = tempfile.NamedTemporaryFile("wb", suffix=".json", delete=False)
handle.write(b'{"components": "\xff\xfe"}')
handle.close()
check(
    "an undecodable SBOM is refused",
    build(handle.name, "", "sbom-graph").source == SOURCE_NONE,
)

print()
if FAILURES:
    print(f"{len(FAILURES)} test(s) failed ❌")
    sys.exit(1)
print("All provenance tests passed ✅")
