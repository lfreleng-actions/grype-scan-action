#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Collect maintainer-approved vulnerability bypasses from issues.

A bypass is an open issue whose title starts with a configured prefix
and which carries a configured label, for example:

    BYPASS: CVE-2026-12345 no upstream fix yet, tracked in #42

The LABEL is the trust boundary. Opening an issue requires nothing,
but applying a label requires triage or write permission, so an
outside contributor cannot approve their own bypass.

A label alone authorises the issue, not the words it carries: an
author can edit their own issue title at any time, and could rewrite
an approved ``BYPASS: CVE-2026-0001`` into a critical, unfixed CVE
after a maintainer had agreed to the benign one. Identifiers are
therefore read from the title as it stood when the label was last
applied, reconstructed from the issue's ``renamed`` events, rather
than from the title showing now. Later edits have no effect until a
maintainer re-applies the label, which re-anchors the approval to the
revision they just read.

Issue authorship is deliberately NOT used. The ``author_association``
field reports ``CONTRIBUTOR`` rather than ``MEMBER`` when organisation
membership is private, and its value depends on the token used to read
it, so it is unreliable as an authorisation signal and would either
fail closed unpredictably or, if ``CONTRIBUTOR`` were accepted, let any
previous contributor suppress a finding.

Any failure here yields an empty bypass list, so the gate stays closed.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request

# Vulnerability identifiers are whitespace-delimited tokens containing
# a hyphen: CVE-2026-1234, GHSA-xxxx-xxxx-xxxx, ALPINE-CVE-2026-1234,
# RHSA-2026:1234. Candidates are matched as whole tokens and then
# filtered, rather than anchored to a list of known prefixes: an
# earlier prefix-anchored pattern reduced ALPINE-CVE-2026-1234 to
# CVE-2026-1234, and the exact lookup in evaluate then never matched.
CANDIDATE = re.compile(r"(?<![A-Za-z0-9._:-])([A-Za-z][A-Za-z0-9._:-]{4,})")


class ApprovalUnverifiable(Exception):
    """The title a maintainer approved could not be established."""


def looks_like_identifier(token: str) -> bool:
    """Filter candidate tokens down to plausible identifiers.

    Requires a hyphen, plus either a digit (CVE-2026-1234) or three or
    more hyphen-separated parts (GHSA-xxxx-xxxx-xxxx, which carries no
    digit at all).
    """
    if "-" not in token:
        return False
    if any(character.isdigit() for character in token):
        return True
    return len(token.split("-")) >= 3


def extract_identifiers(title: str) -> set[str]:
    """Every plausible vulnerability identifier in an issue title."""
    return {
        match.group(1).upper().rstrip(".,;:")
        for match in CANDIDATE.finditer(title)
        if looks_like_identifier(match.group(1))
    }


def emit(name: str, value: str) -> None:
    """Append a step output, using the multiline form when needed."""
    out_path = os.environ.get("GITHUB_OUTPUT")
    if not out_path:
        return
    with open(out_path, "a", encoding="utf-8") as handle:
        if "\n" in value:
            delimiter = "ghadelim_bypass_end"
            while delimiter in value:
                delimiter += "x"
            handle.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
        else:
            handle.write(f"{name}={value}\n")


def warn(message: str) -> None:
    """Surface a problem on the run page without failing the step."""
    print(f"::warning::{message}")


MAX_PAGES = 20
MAX_EVENT_PAGES = 10


def get_list(url: str, token: str) -> list[dict]:
    """GET a JSON array from the GitHub API."""
    request = urllib.request.Request(url)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    if token:
        request.add_header("Authorization", f"Bearer {token}")

    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.load(response)
    if not isinstance(payload, list):
        raise ValueError("unexpected response shape")
    return payload


def fetch_page(
    api_url: str, repo: str, label: str, token: str, page: int
) -> list[dict]:
    """Fetch one page of open issues carrying the label."""
    from urllib.parse import quote

    return get_list(
        f"{api_url}/repos/{repo}/issues?state=open"
        f"&labels={quote(label)}&per_page=100&page={page}",
        token,
    )


def fetch_issues(api_url: str, repo: str, label: str, token: str) -> list[dict]:
    """Every open issue carrying the label, following pagination.

    A shared organisation-wide bypass repository can hold more than one
    page. Reading the first page alone would silently drop approved
    bypasses and gate builds a maintainer had already unblocked.
    """
    collected: list[dict] = []
    for page in range(1, MAX_PAGES + 1):
        payload = fetch_page(api_url, repo, label, token, page)
        # Pull requests also appear in the issues endpoint; drop them.
        collected.extend(item for item in payload if "pull_request" not in item)
        if len(payload) < 100:
            return collected
    warn(f"Stopped after {MAX_PAGES} pages of bypass issues; later pages were not read")
    return collected


def fetch_events(api_url: str, repo: str, number: int, token: str) -> list[dict]:
    """Every label and rename event on one issue.

    The issue events endpoint is used in preference to the timeline,
    which repeats every comment and cross-reference and so needs far
    more pages to reach the same handful of events.

    Truncation raises rather than returning what arrived. Pages come
    oldest first, so a truncated read drops the most recent events,
    which is exactly where a post-approval rename would sit. A final
    page that comes back full is treated the same way: the history
    may end there, or may not, and the two cannot be told apart.
    """
    collected: list[dict] = []
    for page in range(1, MAX_EVENT_PAGES + 1):
        payload = get_list(
            f"{api_url}/repos/{repo}/issues/{number}/events?per_page=100&page={page}",
            token,
        )
        collected.extend(payload)
        if len(payload) < 100:
            return collected
    raise ApprovalUnverifiable(
        f"its history filled all {MAX_EVENT_PAGES} pages read, so later "
        "edits cannot be ruled out"
    )


def event_order(event: dict) -> tuple[str, int]:
    """Sort key placing events in the order they happened.

    GitHub timestamps have one-second resolution, so a rename applied
    in the same second as the label would otherwise sort arbitrarily.
    The event ID rises monotonically and breaks that tie.
    """
    identifier = event.get("id")
    return (
        str(event.get("created_at") or ""),
        identifier if isinstance(identifier, int) else 0,
    )


def rename_target(event: dict, field: str) -> str:
    """One side of a rename event, as a stripped title."""
    value = (event.get("rename") or {}).get(field)
    if not isinstance(value, str):
        raise ApprovalUnverifiable("a rename event carried no title")
    return value.strip()


def approved_title(events: list[dict], label: str, current: str) -> str:
    """The issue title as it stood when the label was last applied.

    Walking back from the current title is enough: the first rename
    after the label event records, in its ``from`` field, the title
    that the maintainer saw. Removing and re-applying the label moves
    the anchor forward, which is how an edited bypass gets re-approved.

    Raises ``ApprovalUnverifiable`` when that title cannot be
    established, so an unverifiable bypass is dropped rather than
    trusted.
    """
    ordered = sorted(events, key=event_order)
    wanted = label.strip().casefold()

    approved_at = None
    for index, event in enumerate(ordered):
        if event.get("event") != "labeled":
            continue
        name = (event.get("label") or {}).get("name")
        if isinstance(name, str) and name.strip().casefold() == wanted:
            approved_at = index
    if approved_at is None:
        raise ApprovalUnverifiable(
            f"no '{label}' label event, so the approved title is unknown"
        )

    renames = [
        index for index, event in enumerate(ordered) if event.get("event") == "renamed"
    ]
    # Two of these get dereferenced below and rename_target validates
    # both: the newest, and the first one after the label. A rename
    # carrying no title in either position raises; one anywhere else
    # cannot alter which positions those are, so it decides nothing.
    #
    # The newest rename must land on the title showing now. When it
    # does not, the event history is incomplete or out of step with
    # the issue, and reconstructing anything from it would be a guess.
    if renames and rename_target(ordered[renames[-1]], "to") != current:
        raise ApprovalUnverifiable("the rename history does not match the title")

    later = [index for index in renames if index > approved_at]
    return rename_target(ordered[later[0]], "from") if later else current


def parse_timestamp(value: object) -> dt.datetime | None:
    """Parse a GitHub ISO-8601 timestamp, or None when unusable."""
    if not isinstance(value, str):
        return None
    try:
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def expired(issue: dict, now: dt.datetime, max_age: int) -> bool:
    """Whether the issue is older than the configured limit.

    Age runs from created_at, which arrives with the issue and cannot
    be edited, so this is checked before the history lookup and an
    already-expired bypass costs no extra API call.
    """
    if max_age <= 0:
        return False
    created_at = parse_timestamp(issue.get("created_at"))
    if created_at is None:
        return False
    age_days = (now - created_at).days
    if age_days <= max_age:
        return False
    warn(
        f"Bypass issue #{issue.get('number')} is {age_days} days old "
        f"(limit {max_age}); ignoring"
    )
    return True


def verified_title(
    api_url: str, repo: str, issue: dict, label: str, token: str
) -> str | None:
    """The approved title of one bypass issue, or None to ignore it."""
    number = issue.get("number")
    current = (issue.get("title") or "").strip()
    if not isinstance(number, int):
        warn("A labelled issue arrived without a number; ignoring")
        return None

    try:
        title = approved_title(
            fetch_events(api_url, repo, number, token), label, current
        )
    except ApprovalUnverifiable as exc:
        warn(f"Bypass issue #{number} could not be verified: {exc}; ignoring")
        return None
    except Exception as exc:  # noqa: BLE001 - never fail the scan
        warn(f"Could not read the history of bypass issue #{number} ({exc}); ignoring")
        return None

    if title != current:
        warn(
            f"Bypass issue #{number} was renamed after it was labelled; "
            f"honouring the approved title '{title}'. Re-apply the label "
            "to approve the new one."
        )
    return title


def main() -> int:
    repo = os.environ.get("BYPASS_REPO", "")
    label = os.environ.get("BYPASS_LABEL", "")
    prefix = os.environ.get("BYPASS_PREFIX", "")
    token = os.environ.get("GH_TOKEN", "")
    api_url = os.environ.get("API_URL", "https://api.github.com")
    try:
        max_age = int(os.environ.get("BYPASS_MAX_AGE", "0") or 0)
    except ValueError:
        max_age = 0

    if not repo or not label:
        emit("bypasses", "[]")
        return 0

    try:
        issues = fetch_issues(api_url, repo, label, token)
    except urllib.error.HTTPError as exc:
        warn(
            f"Could not read bypass issues from {repo} (HTTP {exc.code}); "
            "continuing with no bypasses applied"
        )
        emit("bypasses", "[]")
        return 0
    except Exception as exc:  # noqa: BLE001 - never fail the scan
        warn(
            f"Could not read bypass issues from {repo} ({exc}); "
            "continuing with no bypasses applied"
        )
        emit("bypasses", "[]")
        return 0

    now = dt.datetime.now(dt.timezone.utc)
    collected: list[dict] = []
    for issue in issues:
        if expired(issue, now, max_age):
            continue

        title = verified_title(api_url, repo, issue, label, token)
        if title is None:
            continue

        if prefix and not title.upper().startswith(prefix.upper()):
            continue

        ids = extract_identifiers(title)
        if not ids:
            warn(
                f"Bypass issue #{issue.get('number')} has the label but "
                "no recognisable vulnerability ID in its title; ignoring"
            )
            continue

        for vuln_id in sorted(ids):
            collected.append(
                {
                    "id": vuln_id,
                    "issue": issue.get("number"),
                    "url": issue.get("html_url", ""),
                    "title": title,
                }
            )

    emit("bypasses", json.dumps(collected))

    if collected:
        listed = ", ".join(sorted({entry["id"] for entry in collected}))
        print(f"Approved bypasses in {repo}: {listed}")
    else:
        print(f"No approved bypasses found in {repo}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
