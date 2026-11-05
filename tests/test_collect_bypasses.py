#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Offline tests for the bypass collector.

The collector decides whether a vulnerability stops gating a build, so
it is the security-sensitive half of this action. These tests stub the
HTTP layer, needing no network and no GitHub token.
"""

from __future__ import annotations

import datetime as dt
import io
import json
import pathlib
import sys
import urllib.error
import urllib.request
from email.message import Message

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from scripts import collect_bypasses  # noqa: E402

FAILURES: list[str] = []

# Issue events are dated relative to this instant, so a test can place
# a rename before or after the label event without touching the clock.
BASE = dt.datetime(2026, 1, 1, tzinfo=dt.UTC)


def check(label: str, condition: bool, detail: object = "") -> None:
    if condition:
        print(f"  ✅ {label}")
    else:
        print(f"  ❌ {label} {detail}")
        FAILURES.append(label)


def stamp(when: dt.datetime) -> str:
    """Format a timestamp the way the GitHub API does."""
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def issue(number: int, title: str, days_old: int = 0, pull: bool = False) -> dict:
    created = dt.datetime.now(dt.UTC) - dt.timedelta(days=days_old)
    entry = {
        "number": number,
        "title": title,
        "html_url": f"https://example/{number}",
        "created_at": stamp(created),
    }
    if pull:
        entry["pull_request"] = {"url": "https://example/pr"}
    return entry


def labelled(identifier: int, minutes: int = 0, label: str = "cve-bypass") -> dict:
    """A 'labeled' issue event, dated by minutes since the epoch base."""
    return {
        "id": identifier,
        "event": "labeled",
        "created_at": stamp(BASE + dt.timedelta(minutes=minutes)),
        "label": {"name": label},
    }


def renamed(identifier: int, before: str, after: str, minutes: int = 0) -> dict:
    """A 'renamed' issue event recording both sides of the edit."""
    return {
        "id": identifier,
        "event": "renamed",
        "created_at": stamp(BASE + dt.timedelta(minutes=minutes)),
        "rename": {"from": before, "to": after},
    }


def noise(identifier: int, minutes: int = 0) -> dict:
    """An issue event the collector does not act on."""
    return {
        "id": identifier,
        "event": "subscribed",
        "created_at": stamp(BASE + dt.timedelta(minutes=minutes)),
    }


def untitled(identifier: int, minutes: int = 0) -> dict:
    """A 'renamed' event whose rename payload is missing."""
    return {
        "id": identifier,
        "event": "renamed",
        "created_at": stamp(BASE + dt.timedelta(minutes=minutes)),
    }


class FakeHTTP:
    """Serve canned pages, recording the URLs requested.

    Issue events are served alongside the issue list, sliced into the
    same 100-item pages the real endpoint returns. Issues with no
    entry in ``events`` get a single 'labeled' event, which is what an
    issue labelled once and never renamed looks like.
    """

    def __init__(self, pages: list[list[dict]], events: dict[int, list[dict]]):
        self.pages = pages
        self.events = events
        self.urls: list[str] = []

    def __call__(self, request, timeout=None, **kwargs):  # noqa: ANN001
        url = request.full_url
        self.urls.append(url)
        # Parse '&page=' specifically: a plain 'page=' also matches
        # 'per_page=100' and would read the wrong page number.
        page = 1
        if "&page=" in url:
            page = int(url.split("&page=")[1].split("&")[0])

        if "/events" in url:
            number = int(url.split("/issues/")[1].split("/")[0])
            canned = self.events.get(number, [labelled(1)])
            if isinstance(canned, Exception):
                raise canned
            start = (page - 1) * 100
            body = canned[start : start + 100]
        else:
            body = self.pages[page - 1] if page <= len(self.pages) else []
        return io.BytesIO(json.dumps(body).encode())


def collect(pages, events=None, **env) -> list[dict]:
    """Run the collector against canned pages; return parsed bypasses."""
    import os
    import tempfile

    original = urllib.request.urlopen
    fake = FakeHTTP(pages, events or {})
    urllib.request.urlopen = fake  # type: ignore[assignment]
    try:
        with tempfile.TemporaryDirectory() as tmp:
            out = pathlib.Path(tmp) / "out"
            out.touch()
            saved = dict(os.environ)
            os.environ.update(
                {
                    "BYPASS_REPO": "example/repo",
                    "BYPASS_LABEL": "cve-bypass",
                    "BYPASS_PREFIX": "BYPASS:",
                    "BYPASS_MAX_AGE": "90",
                    "GH_TOKEN": "",
                    "API_URL": "https://api.github.com",
                    "GITHUB_OUTPUT": str(out),
                }
            )
            os.environ.update({k: str(v) for k, v in env.items()})
            try:
                collect_bypasses.main()
                text = out.read_text(encoding="utf-8")
            finally:
                os.environ.clear()
                os.environ.update(saved)
    finally:
        urllib.request.urlopen = original

    payload = text.partition("bypasses=")[2].strip()
    return json.loads(payload) if payload else []


print("identifier extraction")
extract = collect_bypasses.extract_identifiers
check("plain CVE", extract("BYPASS: CVE-2026-1234") == {"CVE-2026-1234"})
check(
    "composite distro ID kept whole",
    extract("BYPASS: ALPINE-CVE-2026-1234") == {"ALPINE-CVE-2026-1234"},
)
check(
    "GHSA without digits",
    extract("BYPASS: GHSA-abcd-efgh-ijkl") == {"GHSA-ABCD-EFGH-IJKL"},
)
check("prose without an ID", extract("BYPASS: please unblock us") == set())
check(
    "two IDs in one title",
    extract("BYPASS: CVE-2026-1 and GHSA-aaaa-bbbb-cccc")
    == {"CVE-2026-1", "GHSA-AAAA-BBBB-CCCC"},
)

print("collection")
found = collect([[issue(1, "BYPASS: CVE-2026-1234")]])
check(
    "labelled issue yields a bypass",
    [e["id"] for e in found] == ["CVE-2026-1234"],
    found,
)
check("issue number recorded", bool(found) and found[0]["issue"] == 1, found)

found = collect([[issue(2, "Something else entirely")]])
check("title without the prefix is ignored", found == [], found)

found = collect([[issue(3, "BYPASS: CVE-2026-1", days_old=200)]])
check("expired bypass ignored", found == [], found)

found = collect([[issue(4, "BYPASS: CVE-2026-1", days_old=200)]], BYPASS_MAX_AGE="0")
check("expiry disabled by zero", [e["id"] for e in found] == ["CVE-2026-1"], found)

found = collect([[issue(5, "BYPASS: CVE-2026-1", pull=True)]])
check("pull requests excluded", found == [], found)

found = collect([[issue(6, "BYPASS: no identifier here")]])
check("labelled issue without an ID ignored", found == [], found)

print("approval anchoring")
APPROVED = "BYPASS: CVE-2026-0001"
EDITED = "BYPASS: CVE-2026-9999"

found = collect(
    [[issue(10, EDITED)]],
    events={10: [labelled(1, minutes=10), renamed(2, APPROVED, EDITED, minutes=20)]},
)
check(
    "title edited after labelling keeps the approved ID",
    [e["id"] for e in found] == ["CVE-2026-0001"],
    found,
)

found = collect(
    [[issue(11, APPROVED)]],
    events={
        11: [
            renamed(1, "BYPASS: CVE-2026-000", APPROVED, minutes=10),
            labelled(2, minutes=20),
        ]
    },
)
check(
    "an edit before labelling is what was approved",
    [e["id"] for e in found] == ["CVE-2026-0001"],
    found,
)

found = collect(
    [[issue(12, EDITED)]],
    events={
        12: [
            labelled(1, minutes=10),
            renamed(2, APPROVED, EDITED, minutes=20),
            labelled(3, minutes=30),
        ]
    },
)
check(
    "re-applying the label approves the new title",
    [e["id"] for e in found] == ["CVE-2026-9999"],
    found,
)

found = collect(
    [[issue(13, EDITED)]],
    events={13: [labelled(1, minutes=10), renamed(2, APPROVED, EDITED, minutes=10)]},
)
check(
    "a rename in the same second as the label is later",
    [e["id"] for e in found] == ["CVE-2026-0001"],
    found,
)

found = collect(
    [[issue(14, "CVE-2026-0001")]],
    events={
        14: [
            labelled(1, minutes=10),
            renamed(2, APPROVED, "CVE-2026-0001", minutes=20),
        ]
    },
)
check(
    "the prefix is checked against the approved title",
    [e["id"] for e in found] == ["CVE-2026-0001"],
    found,
)

found = collect([[issue(15, APPROVED)]], events={15: [labelled(1, label="triage")]})
check("another label does not approve a bypass", found == [], found)

found = collect([[issue(16, APPROVED)]], events={16: []})
check("no label event applies no bypass", found == [], found)

found = collect(
    [[issue(17, EDITED)]],
    events={
        17: [
            labelled(1, minutes=10),
            renamed(2, APPROVED, "BYPASS: a third title", minutes=20),
        ]
    },
)
check("rename history out of step with the title ignored", found == [], found)

found = collect([[issue(18, APPROVED)]], events={18: [labelled(1, label="CVE-Bypass")]})
check(
    "label matching ignores case",
    [e["id"] for e in found] == ["CVE-2026-0001"],
    found,
)

found = collect(
    [[issue(19, APPROVED)]],
    events={19: urllib.error.HTTPError("u", 404, "nope", Message(), None)},
)
check("an unreadable history applies no bypass", found == [], found)

# The reconstruction reads two renames: the newest, and the first one
# after the label. A rename carrying no title in either position has
# to be rejected; one anywhere else decides nothing and is ignored.
found = collect(
    [[issue(22, EDITED)]],
    events={
        22: [
            labelled(1, minutes=10),
            untitled(2, minutes=20),
            renamed(3, "BYPASS: an interim title", EDITED, minutes=30),
        ]
    },
)
check("a rename with no title where it decides is rejected", found == [], found)

found = collect(
    [[issue(23, APPROVED)]],
    events={
        23: [
            untitled(1, minutes=5),
            renamed(2, "BYPASS: an earlier title", APPROVED, minutes=6),
            labelled(3, minutes=10),
        ]
    },
)
check(
    "a rename with no title elsewhere is ignored",
    [e["id"] for e in found] == ["CVE-2026-0001"],
    found,
)

print("event pagination")
# 100 events fill the first page exactly, so the rename that follows
# is only seen if the collector asks for the second one.
spanning = (
    [labelled(1, minutes=10)]
    + [noise(100 + n, minutes=10) for n in range(99)]
    + [renamed(500, APPROVED, EDITED, minutes=20)]
)
found = collect([[issue(20, EDITED)]], events={20: spanning})
check(
    "a rename on a later page is read",
    [e["id"] for e in found] == ["CVE-2026-0001"],
    found,
)

# Ten full pages exhaust the paginator. Nothing distinguishes a
# history that ends on a full page from one that continues, and a
# truncated read drops the newest events, which is where a
# post-approval rename would sit, so the bypass has to go.
busy = [labelled(1, minutes=10)] + [noise(100 + n, minutes=10) for n in range(999)]
found = collect([[issue(21, APPROVED)]], events={21: busy})
check("a history too long to read applies no bypass", found == [], found)

print("pagination")
page_one = [issue(n, f"BYPASS: CVE-2026-{n}") for n in range(100)]
page_two = [issue(500, "BYPASS: CVE-2026-999")]
found = collect([page_one, page_two])
ids = {entry["id"] for entry in found}
check("second page read", "CVE-2026-999" in ids, sorted(ids)[:3])
check("all entries collected", len(found) == 101, len(found))

print("failure handling")


def boom(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
    raise urllib.error.HTTPError("u", 403, "forbidden", Message(), None)


original = urllib.request.urlopen
urllib.request.urlopen = boom
try:
    import os
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        out = pathlib.Path(tmp) / "out"
        out.touch()
        saved = dict(os.environ)
        os.environ.update(
            {
                "BYPASS_REPO": "example/repo",
                "BYPASS_LABEL": "cve-bypass",
                "BYPASS_PREFIX": "BYPASS:",
                "BYPASS_MAX_AGE": "90",
                "GH_TOKEN": "",
                "API_URL": "https://api.github.com",
                "GITHUB_OUTPUT": str(out),
            }
        )
        try:
            rc = collect_bypasses.main()
            text = out.read_text(encoding="utf-8")
        finally:
            os.environ.clear()
            os.environ.update(saved)
    check("API failure does not fail the step", rc == 0, rc)
    check("API failure applies no bypasses", "bypasses=[]" in text, text)
finally:
    urllib.request.urlopen = original

print()
if FAILURES:
    print(f"{len(FAILURES)} test(s) failed ❌")
    sys.exit(1)
print("All collector tests passed ✅")
