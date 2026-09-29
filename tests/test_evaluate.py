#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline tests for the report evaluation logic.

These run without Grype or network access: they feed synthetic report
JSON through the evaluate script and assert on its outputs and on the
rendered step summary.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent

FAILURES: list[str] = []


def match(
    package: str,
    vuln: str,
    severity: str,
    fix: str | None = None,
    risk: float | None = None,
    epss: float | None = None,
    ref: str | None = None,
) -> dict:
    """Build a synthetic Grype match."""
    vulnerability: dict = {"id": vuln, "severity": severity}
    vulnerability["fix"] = (
        {"versions": [fix], "state": "fixed"}
        if fix
        else {"versions": [], "state": "not-fixed"}
    )
    if risk is not None:
        vulnerability["risk"] = risk
    if epss is not None:
        vulnerability["epss"] = [{"cve": vuln, "epss": epss}]
    artifact: dict = {"name": package, "version": "1.0.0", "type": "apk"}
    if ref:
        artifact["id"] = ref
    return {"vulnerability": vulnerability, "artifact": artifact}


def run(
    matches: list[dict],
    sidecar: dict | str | bytes | None = None,
    sbom: dict | str | None = None,
    **env_overrides,
) -> tuple[dict, str]:
    """Run the evaluator over one synthetic report; return outputs."""
    with tempfile.TemporaryDirectory() as tmp:
        report = pathlib.Path(tmp) / "grype-results.json"
        report.write_text(json.dumps({"matches": matches}), encoding="utf-8")
        out_file = pathlib.Path(tmp) / "out"
        summary_file = pathlib.Path(tmp) / "summary"
        out_file.touch()
        summary_file.touch()

        artefact = "sbom:test"
        if sbom is not None:
            sbom_file = pathlib.Path(tmp) / "sbom-cyclonedx.json"
            sbom_file.write_text(
                sbom if isinstance(sbom, str) else json.dumps(sbom),
                encoding="utf-8",
            )
            artefact = f"sbom:{sbom_file}"

        if sidecar is not None:
            manifest = pathlib.Path(tmp) / "dependency-change.json"
            if isinstance(sidecar, bytes):
                manifest.write_bytes(sidecar)
            else:
                manifest.write_text(
                    sidecar if isinstance(sidecar, str) else json.dumps(sidecar),
                    encoding="utf-8",
                )
            env_overrides.setdefault("INPUT_CHANGE_MANIFEST", str(manifest))

        env = dict(os.environ)
        env.update(
            {
                "MANIFEST": f"{report}|{artefact}",
                "INPUT_FAIL_ON": "high",
                "INPUT_NAME": "",
                "INPUT_SUMMARY": "true",
                "INPUT_SUMMARY_TITLE": "Grype Vulnerability Scan",
                "INPUT_SUMMARY_MAX_ROWS": "50",
                "INPUT_SUMMARY_ON_SUCCESS": "true",
                "INPUT_GATE_WHEN": "always",
                "INPUT_DEPENDENCIES_CHANGED": "",
                "INPUT_CHANGE_MANIFEST": "",
                "INPUT_DEPENDENCY_POLICY": "all",
                "INPUT_TRANSITIVE_FAIL_ON": "none",
                "INPUT_DECLARED_SOURCE": "auto",
                "INPUT_DECLARED_DEPENDENCIES": "",
                "BYPASSES": "[]",
                "BYPASS_REPO": "example/repo",
                "GITHUB_OUTPUT": str(out_file),
                "GITHUB_STEP_SUMMARY": str(summary_file),
            }
        )
        env.update({k: str(v) for k, v in env_overrides.items()})

        env["PYTHONPATH"] = str(ROOT)
        subprocess.run(
            [sys.executable, "-m", "scripts.evaluate"],
            cwd=str(ROOT),
            env=env,
            check=True,
            capture_output=True,
        )

        outputs: dict[str, str] = {}
        raw = out_file.read_text(encoding="utf-8")
        for line in raw.splitlines():
            if "=" in line and "<<" not in line:
                key, _, value = line.partition("=")
                outputs[key] = value
        return outputs, summary_file.read_text(encoding="utf-8")


def check(label: str, condition: bool, detail: object = "") -> None:
    if condition:
        print(f"  ✅ {label}")
    else:
        print(f"  ❌ {label} {detail}")
        FAILURES.append(label)


print("severity threshold")
outputs, _ = run([match("a", "CVE-1", "High"), match("b", "CVE-2", "Low")])
check("high gates, low does not", outputs["gating-matches"] == "1", outputs)
check("total counts every match", outputs["total-matches"] == "2", outputs)

outputs, _ = run([match("a", "CVE-1", "Medium")], INPUT_FAIL_ON="critical")
check("below threshold does not gate", outputs["gating"] == "false", outputs)

outputs, _ = run([match("a", "CVE-1", "Critical")], INPUT_FAIL_ON="none")
check("fail-on none never gates", outputs["gating"] == "false", outputs)

print("unknown severity")
outputs, _ = run([match("a", "CVE-1", "Unknown")])
check(
    "unknown severity does not gate",
    outputs["gating"] == "false" and outputs["total-matches"] == "1",
    outputs,
)

print("bypasses")
bypass = json.dumps(
    [{"id": "CVE-1", "issue": 7, "url": "https://example/7", "title": "BYPASS: CVE-1"}]
)
outputs, summary = run(
    [match("a", "CVE-1", "Critical"), match("b", "CVE-2", "High")],
    BYPASSES=bypass,
)
check("bypassed match does not gate", outputs["gating-matches"] == "1", outputs)
check("bypass is counted", outputs["bypassed-matches"] == "1", outputs)
check("bypassed id reported", outputs["bypassed-ids"] == "CVE-1", outputs)
check("bypass shown in summary", "Suppressed by an approved bypass" in summary)
check("bypass links the issue", "https://example/7" in summary)

outputs, _ = run(
    [match("a", "CVE-1", "Critical")],
    BYPASSES=json.dumps([{"id": "cve-1", "issue": 7, "url": "", "title": ""}]),
)
check("bypass matching is case-insensitive", outputs["gating"] == "false", outputs)

outputs, _ = run([match("a", "CVE-1", "Critical")], BYPASSES="not json")
check(
    "malformed bypass data keeps the gate closed",
    outputs["gating"] == "true",
    outputs,
)

print("rendering")
outputs, summary = run(
    [
        match("pkg-a", "CVE-9", "Critical", fix="2.0.0", risk=80.5, epss=0.95),
        match("pkg-b", "CVE-8", "High", risk=10.0, epss=0.0000001),
    ]
)
check("table header present", "| Severity | Package |" in summary)
check("fix version rendered", "2.0.0" in summary)
check("unfixed state rendered", "not-fixed" in summary)
check("epss percentage rendered", "95.0%" in summary)
check("tiny epss floors to <0.01%", "<0.01%" in summary)
check("critical sorts first", summary.index("CVE-9") < summary.index("CVE-8"))

outputs, summary = run(
    [match(f"pkg{i}", f"CVE-{i}", "High") for i in range(10)],
    INPUT_SUMMARY_MAX_ROWS="3",
)
check("row cap applied", "Showing 3 of 10 findings" in summary)

outputs, summary = run([match("a|b", "CVE-1", "High")])
check("pipes escaped in cells", "a\\|b" in summary)

outputs, summary = run([], INPUT_SUMMARY_ON_SUCCESS="false")
check("clean summary suppressed on request", summary.strip() == "")

outputs, summary = run([])
check("clean scan reports success", "No vulnerabilities reported" in summary)
check("clean scan does not gate", outputs["gating"] == "false", outputs)

print("change-scoped gating")
GATE_ON_CHANGE = {"INPUT_GATE_WHEN": "dependencies-changed"}

outputs, _ = run([match("a", "CVE-1", "Critical")])
check(
    "default gate-when still gates",
    outputs["gating"] == "true" and outputs["gate-active"] == "true",
    outputs,
)
check("nothing is advisory by default", outputs["advisory-matches"] == "0", outputs)

outputs, summary = run(
    [match("a", "CVE-1", "Critical")],
    **GATE_ON_CHANGE,
    INPUT_DEPENDENCIES_CHANGED="false",
)
check("unchanged dependencies do not gate", outputs["gating"] == "false", outputs)
check("finding becomes advisory", outputs["advisory-matches"] == "1", outputs)
check("gate reported inactive", outputs["gate-active"] == "false", outputs)
check("advisory still counted in total", outputs["total-matches"] == "1", outputs)
check("advisory rendered as a warning", "reported as warnings" in summary)
check("advisory finding still listed", "CVE-1" in summary)
check("reason explained in summary", "did not touch the dependency chain" in summary)
check(
    "advisory run explains the change signal",
    outputs["gate-reason"] == "this change did not touch the dependency chain",
    outputs,
)

outputs, _ = run(
    [match("a", "CVE-1", "Critical")],
    **GATE_ON_CHANGE,
    INPUT_DEPENDENCIES_CHANGED="true",
)
check("changed dependencies gate", outputs["gating"] == "true", outputs)
check("nothing advisory when gating", outputs["advisory-matches"] == "0", outputs)

print("change signal fails closed")
for label, kwargs in (
    ("absent signal", {}),
    ("empty signal", {"INPUT_DEPENDENCIES_CHANGED": ""}),
    ("unreadable manifest path", {"INPUT_CHANGE_MANIFEST": "/nonexistent/x.json"}),
):
    outputs, _ = run([match("a", "CVE-1", "Critical")], **GATE_ON_CHANGE, **kwargs)
    check(f"{label} gates", outputs["gating"] == "true", outputs)

for label, payload in (
    ("malformed JSON", "not json"),
    ("non-object document", "[]"),
    ("missing key", {"other": True}),
    ("string instead of boolean", {"changed": "false"}),
    ("null value", {"changed": None}),
    ("invalid UTF-8", b'{"changed": "\xff\xfe"}'),
):
    outputs, _ = run(
        [match("a", "CVE-1", "Critical")], sidecar=payload, **GATE_ON_CHANGE
    )
    check(f"sidecar with {label} gates", outputs["gating"] == "true", outputs)

print("change signal sidecar")
outputs, _ = run(
    [match("a", "CVE-1", "Critical")], sidecar={"changed": False}, **GATE_ON_CHANGE
)
check("sidecar false does not gate", outputs["advisory-matches"] == "1", outputs)

outputs, _ = run(
    [match("a", "CVE-1", "Critical")], sidecar={"changed": True}, **GATE_ON_CHANGE
)
check("sidecar true gates", outputs["gating"] == "true", outputs)

outputs, _ = run(
    [match("a", "CVE-1", "Critical")],
    sidecar={"changed": False},
    **GATE_ON_CHANGE,
    INPUT_DEPENDENCIES_CHANGED="true",
)
check("explicit input overrides the sidecar", outputs["gating"] == "true", outputs)

print("gating interactions")
outputs, _ = run(
    [match("a", "CVE-1", "Critical"), match("b", "CVE-2", "Low")],
    **GATE_ON_CHANGE,
    INPUT_DEPENDENCIES_CHANGED="false",
)
check(
    "sub-threshold findings never become advisory",
    outputs["advisory-matches"] == "1",
    outputs,
)

outputs, _ = run(
    [match("a", "CVE-1", "Critical")],
    **GATE_ON_CHANGE,
    INPUT_DEPENDENCIES_CHANGED="false",
    BYPASSES=bypass,
)
check(
    "bypass still claims the finding when not gating",
    outputs["bypassed-matches"] == "1" and outputs["advisory-matches"] == "0",
    outputs,
)

outputs, _ = run([match("a", "CVE-1", "Critical")], BYPASSES=bypass)
check(
    "gate reason reports policy, not outcome",
    outputs["gating"] == "false" and outputs["gate-reason"] == "every scan gates",
    outputs,
)

outputs, _ = run(
    [match("a", "CVE-1", "Critical")],
    **GATE_ON_CHANGE,
    INPUT_DEPENDENCIES_CHANGED="false",
    INPUT_FAIL_ON="none",
)
check(
    "fail-on none reports without advisories",
    outputs["advisory-matches"] == "0" and outputs["gating"] == "false",
    outputs,
)

outputs, _ = run([match("a", "CVE-1", "Critical")], INPUT_FAIL_ON="none")
check(
    "fail-on none reports the gate as inactive",
    outputs["gate-active"] == "false",
    outputs,
)
check(
    "fail-on none explains the threshold, not the signal",
    outputs["gate-reason"] == "no severity threshold is configured",
    outputs,
)

outputs, _ = run(
    [match("a", "CVE-1", "Critical")],
    **GATE_ON_CHANGE,
    INPUT_DEPENDENCIES_CHANGED="false",
    INPUT_FAIL_ON="none",
)
check(
    "threshold explains the outcome ahead of the signal",
    outputs["gate-reason"] == "no severity threshold is configured",
    outputs,
)

outputs, summary = run(
    [match("a", "CVE-1", "Critical")],
    **GATE_ON_CHANGE,
    INPUT_DEPENDENCIES_CHANGED="false",
    INPUT_SUMMARY_ON_SUCCESS="false",
)
check(
    "advisories are summarised even when clean runs are not",
    "CVE-1" in summary,
    summary,
)

print("dependency provenance")
# Mirrors the reactor shape cyclonedx-maven emits: 'core' is a project
# module, 'databind' is declared by it, and 'jcore' arrives only
# because databind wants it. Absence of scope is what marks the
# module, so this shape is the one worth guarding.
REACTOR = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "components": [
        {"bom-ref": "core", "type": "library", "name": "core"},
        {
            "bom-ref": "databind",
            "type": "library",
            "name": "databind",
            "scope": "required",
        },
        {
            "bom-ref": "jcore",
            "type": "library",
            "name": "jcore",
            "scope": "required",
        },
    ],
    "dependencies": [
        {"ref": "project", "dependsOn": []},
        {"ref": "core", "dependsOn": ["databind"]},
        {"ref": "databind", "dependsOn": ["jcore"]},
        {"ref": "jcore", "dependsOn": []},
    ],
    "metadata": {
        "component": {"bom-ref": "project", "name": "project"},
        "tools": {"components": [{"name": "cyclonedx-maven-plugin"}]},
    },
}
DECLARED = {"INPUT_DEPENDENCY_POLICY": "declared"}
MIXED = [
    match("databind", "CVE-D", "Critical", ref="databind"),
    match("jcore", "CVE-T", "Critical", ref="jcore"),
]

outputs, summary = run(MIXED, sbom=REACTOR, **DECLARED)
check("declared finding gates", outputs["gating-matches"] == "1", outputs)
check("inherited finding warns", outputs["advisory-matches"] == "1", outputs)
check("declared findings counted", outputs["direct-matches"] == "1", outputs)
check("inherited findings counted", outputs["transitive-matches"] == "1", outputs)
check(
    "graph named as the source",
    '"sbom-graph"' in outputs["provenance-source"],
    outputs,
)
check("inherited table rendered", "Inherited dependencies" in summary)
check("both findings listed", "CVE-D" in summary and "CVE-T" in summary)

outputs, _ = run(MIXED, sbom=REACTOR)
check(
    "default policy gates both",
    outputs["gating-matches"] == "2" and outputs["advisory-matches"] == "0",
    outputs,
)
check(
    "default policy still reports provenance accurately",
    outputs["direct-matches"] == "1"
    and outputs["transitive-matches"] == "1"
    and '"sbom-graph"' in outputs["provenance-source"],
    outputs,
)

outputs, _ = run(MIXED, sbom=REACTOR, **DECLARED, INPUT_TRANSITIVE_FAIL_ON="critical")
check(
    "transitive-fail-on gates severe inherited findings",
    outputs["gating-matches"] == "2" and outputs["advisory-matches"] == "0",
    outputs,
)

outputs, _ = run(
    [match("jcore", "CVE-T", "High", ref="jcore")],
    sbom=REACTOR,
    **DECLARED,
    INPUT_TRANSITIVE_FAIL_ON="critical",
)
check(
    "inherited findings below that threshold still warn",
    outputs["advisory-matches"] == "1",
    outputs,
)

print("the two thresholds are independent")
# fail-on sits ABOVE transitive-fail-on here, so an inherited High
# must gate even though a declared High would not. A prefilter on
# fail-on would discard it before the transitive bar was consulted.
outputs, _ = run(
    [match("jcore", "CVE-T", "High", ref="jcore")],
    sbom=REACTOR,
    **DECLARED,
    INPUT_FAIL_ON="critical",
    INPUT_TRANSITIVE_FAIL_ON="high",
)
check(
    "an inherited finding gates below the fail-on bar",
    outputs["gating-matches"] == "1",
    outputs,
)

outputs, _ = run(
    [match("databind", "CVE-D", "High", ref="databind")],
    sbom=REACTOR,
    **DECLARED,
    INPUT_FAIL_ON="critical",
    INPUT_TRANSITIVE_FAIL_ON="high",
)
check(
    "a declared finding still answers to fail-on",
    outputs["gating-matches"] == "0" and outputs["advisory-matches"] == "0",
    outputs,
)

outputs, _ = run(
    [match("jcore", "CVE-T", "Medium", ref="jcore")],
    sbom=REACTOR,
    **DECLARED,
    INPUT_FAIL_ON="critical",
    INPUT_TRANSITIVE_FAIL_ON="high",
)
check(
    "an inherited finding below both bars is neither",
    outputs["gating-matches"] == "0" and outputs["advisory-matches"] == "0",
    outputs,
)

outputs, _ = run(
    [match("jcore", "CVE-T", "Low", ref="jcore")],
    sbom=REACTOR,
    **DECLARED,
)
check(
    "transitive-fail-on none still respects fail-on for warnings",
    outputs["advisory-matches"] == "0" and outputs["total-matches"] == "1",
    outputs,
)

outputs, _ = run(
    [match("jcore", "CVE-T", "Critical", ref="jcore")],
    sbom=REACTOR,
    **DECLARED,
    INPUT_FAIL_ON="none",
    INPUT_TRANSITIVE_FAIL_ON="high",
)
check(
    "fail-on none disables gating for inherited findings too",
    outputs["gating"] == "false" and outputs["advisory-matches"] == "0",
    outputs,
)
check(
    "fail-on none is described as a single bar",
    outputs["threshold-label"] == "none",
    outputs,
)

outputs, summary = run(
    [match("jcore", "CVE-T", "High", ref="jcore")],
    sbom=REACTOR,
    **DECLARED,
    INPUT_FAIL_ON="critical",
    INPUT_TRANSITIVE_FAIL_ON="high",
)
check(
    "the summary names both bars when they differ",
    "critical declared / high inherited" in summary,
    summary,
)

outputs, summary = run([match("a", "CVE-1", "Critical")])
check(
    "a single bar is still named plainly",
    "`high`" in summary and "declared /" not in summary,
    summary,
)

print("only-fixed demotes rather than discards")
outputs, summary = run(
    [
        match("a", "CVE-FIX", "Critical", fix="2.0.0"),
        match("b", "CVE-NOFIX", "Critical"),
    ],
    INPUT_ONLY_FIXED="true",
)
check(
    "a fixable finding still gates",
    outputs["gating-matches"] == "1",
    outputs,
)
check(
    "an unfixable finding warns instead of vanishing",
    outputs["advisory-matches"] == "1",
    outputs,
)
check("both remain in the summary", "CVE-FIX" in summary and "CVE-NOFIX" in summary)
check(
    "a demoted finding is not labelled inherited",
    "Inherited dependencies" not in summary,
    summary,
)

outputs, summary = run(
    [match("jcore", "CVE-T", "Critical", ref="jcore")],
    sbom=REACTOR,
    **DECLARED,
    INPUT_TRANSITIVE_FAIL_ON="critical",
    INPUT_ONLY_FIXED="true",
)
check(
    "an inherited finding demoted by only-fixed is not labelled inherited",
    outputs["advisory-matches"] == "1" and "Inherited dependencies" not in summary,
    summary,
)

print("provenance fails closed")
outputs, _ = run(MIXED, **DECLARED)
check(
    "nothing to classify against gates everything",
    outputs["gating-matches"] == "2"
    and '"none"' in outputs["provenance-source"]
    and outputs["transitive-matches"] == "0",
    outputs,
)

outputs, _ = run(MIXED, sbom={"components": [{"bom-ref": "jcore"}]}, **DECLARED)
check(
    "an SBOM without a graph gates everything",
    outputs["gating-matches"] == "2" and '"none"' in outputs["provenance-source"],
    outputs,
)

outputs, _ = run(MIXED, sbom="not json", **DECLARED)
check(
    "an unparsable SBOM gates everything",
    outputs["gating-matches"] == "2" and '"none"' in outputs["provenance-source"],
    outputs,
)

for label, broken in (
    ("a non-object metadata", {"metadata": "bad", "dependencies": []}),
    ("a non-list dependencies", {"dependencies": 7}),
    ("a non-list components", {"components": 7, "dependencies": []}),
    (
        "a non-list dependsOn",
        {"dependencies": [{"ref": "a", "dependsOn": 7}]},
    ),
):
    outputs, _ = run(MIXED, sbom=broken, **DECLARED)
    check(
        f"{label} gates rather than aborting",
        outputs["gating-matches"] == "2",
        outputs,
    )

outputs, _ = run(
    MIXED,
    sbom=REACTOR,
    **DECLARED,
    INPUT_DECLARED_DEPENDENCIES="/nonexistent/declared.txt",
)
check(
    "an unreadable declared list does not fall back to the graph",
    outputs["gating-matches"] == "2" and '"none"' in outputs["provenance-source"],
    outputs,
)

outputs, _ = run(MIXED, sbom=REACTOR, **DECLARED, INPUT_DECLARED_SOURCE="none")
check(
    "declared-source none disables the leniency",
    outputs["gating-matches"] == "2",
    outputs,
)

outputs, _ = run(
    MIXED,
    sbom=REACTOR,
    **DECLARED,
    **GATE_ON_CHANGE,
    INPUT_DEPENDENCIES_CHANGED="false",
)
check(
    "an unarmed gate outranks provenance",
    outputs["gating"] == "false" and outputs["advisory-matches"] == "2",
    outputs,
)

print()
if FAILURES:
    print(f"{len(FAILURES)} test(s) failed ❌")
    sys.exit(1)
print("All evaluate tests passed ✅")
