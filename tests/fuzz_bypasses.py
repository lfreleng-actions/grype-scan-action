# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Fuzz bypass titles and the approval history behind them.

An input is an issue title, a newline, then the body the issue events
endpoint returns; the HTTP read is replaced so that body is what
``scripts.collect_bypasses`` parses. Contracts checked, in the
module's own words:

* "Any failure here yields an empty bypass list, so the gate stays
  closed." Verifying one issue through ``verified_title``, the level
  where ``main`` catches failures by design, returns a title or a
  refusal (None) and never raises, its warnings included: output goes
  to a strict UTF-8 stream, as on the runner.
* Identifiers are read "from the title as it stood when the label was
  last applied, reconstructed from the issue's ``renamed`` events". A
  title it returns needs a ``labeled`` event for the label in the
  history, and is the ``from`` side of the first rename after the last
  such event, or the current title when no rename follows it. A
  history whose newest rename does not land on the current title, or
  that fills a page and so may continue, cannot be approved. The
  expected title is derived here from the raw events, by the order
  ``fetch_events`` documents (timestamp, then event ID), not taken
  from ``approved_title``. A refusal is always allowed: it keeps the
  gate closed.
* ``extract_identifiers`` returns for any string. A slow regular
  expression shows up as a libFuzzer timeout, so run with
  ``-timeout``; each identifier it returns occurs in the upper-cased
  title and carries a hyphen.

``check`` needs no Atheris; tests/test_fuzz_replay.py runs every seed
through it. To fuzz, on Linux with Atheris installed (see README):

    python3 tests/fuzz_bypasses.py -max_total_time=60 -timeout=10
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from scripts import collect_bypasses  # noqa: E402

LABEL = "cve-bypass"
# fetch_events treats a full page as a history that may continue.
PAGE = 100


class ContractBroken(AssertionError):
    """The code under test broke a contract its docstring promises."""


def require(condition: bool, message: str) -> None:
    """Raise ContractBroken unless the condition holds."""
    if not condition:
        raise ContractBroken(message)


def split(data: bytes) -> tuple[str, bytes]:
    """The title and the events body an input carries."""
    head, _, body = data.partition(b"\n")
    return head.decode("utf-8", "replace"), body


def expected(body: bytes, current: str) -> str | None:
    """The title the raw history says was approved; None if it cannot say.

    Both exceptions are the decoder's documented failures, on this
    harness's own parse.
    """
    try:
        events = json.loads(body)
    except (RecursionError, ValueError):
        return None
    if not isinstance(events, list) or len(events) >= PAGE:
        return None
    if not all(isinstance(event, dict) for event in events):
        return None

    def when(event: dict) -> tuple[str, int]:
        number = event.get("id")
        return str(event.get("created_at") or ""), (
            number if isinstance(number, int) else 0
        )

    ordered = sorted(events, key=when)
    labels = [
        index
        for index, event in enumerate(ordered)
        if event.get("event") == "labeled"
        and isinstance(event.get("label"), dict)
        and isinstance(event["label"].get("name"), str)
        and event["label"]["name"].strip().casefold() == LABEL
    ]
    if not labels:
        return None
    renames = [
        event.get("rename") for event in ordered if event.get("event") == "renamed"
    ]
    if renames:
        newest = renames[-1]
        if not isinstance(newest, dict) or not isinstance(newest.get("to"), str):
            return None
        if newest["to"].strip() != current:
            return None
    after = [
        event.get("rename")
        for event in ordered[labels[-1] + 1 :]
        if event.get("event") == "renamed"
    ]
    if not after:
        return current
    first = after[0]
    if not isinstance(first, dict) or not isinstance(first.get("from"), str):
        return None
    return first["from"].strip()


def verify(title: str, body: bytes) -> str | None:
    """Run verified_title with every events page answered by ``body``."""

    def answer(*_args: object, **_kwargs: object) -> io.BytesIO:
        return io.BytesIO(body)

    # The action's stdout is strict UTF-8. A StringIO accepts text no
    # codec can encode, such as a lone surrogate, and so would hide a
    # print that raises on the runner.
    output = io.TextIOWrapper(
        io.BytesIO(), encoding="utf-8", errors="strict", write_through=True
    )
    original = urllib.request.urlopen
    urllib.request.urlopen = answer
    try:
        with contextlib.redirect_stdout(output):
            return collect_bypasses.verified_title(
                "https://api.invalid", "o/r", {"number": 1, "title": title}, LABEL, ""
            )
    finally:
        urllib.request.urlopen = original


def check(data: bytes) -> None:
    """Hold title parsing and approval verification to their contracts."""
    title, body = split(data)

    upper = title.upper()
    for found in collect_bypasses.extract_identifiers(title):
        require("-" in found, f"{found!r} has no hyphen")
        require(found in upper, f"{found!r} is not in the title {title!r}")

    result = verify(title, body)
    if result is None:
        return
    require(isinstance(result, str), f"verified_title returned {result!r}")
    approved = expected(body, title.strip())
    require(approved is not None, f"{result!r} approved without verifiable history")
    require(
        result == approved,
        f"{result!r} approved, but the title at the label was {approved!r}",
    )


def main() -> None:
    """Fuzz ``check`` under Atheris, seeded from tests/fuzz_seeds.py."""
    # Atheris is installed only where fuzzing runs; the checker sees
    # its typeshed stubs alone.
    import atheris  # pyright: ignore[reportMissingModuleSource]
    from atheris.instrument_bytecode import (  # pyright: ignore[reportMissingModuleSource]
        instrument_all,
    )
    from fuzz_seeds import BYPASS_SEEDS, write_corpus

    args = sys.argv
    # libFuzzer runs file arguments one by one instead of fuzzing, so
    # add the seed corpus only when no input was named.
    if not any(not arg.startswith("-") for arg in args[1:]):
        import tempfile

        corpus = tempfile.mkdtemp(prefix="fuzz-bypasses-corpus-")
        write_corpus(corpus, BYPASS_SEEDS)
        args = [*args, corpus]
    instrument_all()
    atheris.Setup(args, check)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
