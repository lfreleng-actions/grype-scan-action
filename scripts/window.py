#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""The remediation window: how long a fixable finding may only warn.

In a run whose change left the dependency chain alone, the gate is
unarmed and every finding is a warning. The window bounds that leniency
in time: once a fix has been available for the configured number of
days, the finding gates as it would in an armed run. It can only add
gating to a run, never remove it.
"""

from __future__ import annotations

import datetime as dt
import os
import re
import sys

DAYS_PATTERN = re.compile(r"^[0-9]+$")
DATE_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


def utc_today() -> dt.date:
    """The current date in UTC, the clock every deadline is read against."""
    return dt.datetime.now(dt.timezone.utc).date()


def annotation(text: object) -> str:
    """Escape a value for a workflow command, so it cannot end it early."""
    return str(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def parse_days(value: str | None) -> int | None:
    """Parse remediation-window-days; None when the window is off."""
    text = (value or "").strip()
    if not text:
        return None
    if not DAYS_PATTERN.fullmatch(text):
        raise ValueError(
            f"remediation-window-days must be a whole number of days; got '{value}'"
        )
    return int(text)


def parse_start(value: str | None, today: dt.date) -> dt.date | None:
    """Parse remediation-window-start; None when unset.

    A start in the future would hold every finding back for longer
    than the window promises, so it is rejected rather than honoured.
    """
    text = (value or "").strip()
    if not text:
        return None
    try:
        if not DATE_PATTERN.fullmatch(text):
            raise ValueError(text)
        start = dt.date.fromisoformat(text)
    except ValueError:
        raise ValueError(
            f"remediation-window-start must be a YYYY-MM-DD date; got '{value}'"
        ) from None
    if start > today:
        raise ValueError(
            f"remediation-window-start must not be in the future; got '{value}'"
        )
    return start


def fix_date(vulnerability: dict) -> dt.date | None:
    """The earliest date Grype reports a fix as available, of any kind.

    Entries whose date cannot be read are skipped rather than trusted:
    the caller treats a fix with no usable date as fail-closed.
    """
    fix = vulnerability.get("fix") or {}
    available = fix.get("available") if isinstance(fix, dict) else None
    if not isinstance(available, list):
        return None
    dates = []
    for entry in available:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("date")
        if not isinstance(raw, str) or len(raw) < 10:
            continue
        try:
            dates.append(dt.date.fromisoformat(raw[:10]))
        except ValueError:
            continue
    return min(dates) if dates else None


def deadline(
    fixable: bool,
    fixed_on: dt.date | None,
    days: int,
    start: dt.date | None,
) -> dt.date | None:
    """The date from which a finding gates; None when no clock runs.

    The clock starts at the later of the fix date and the configured
    start. A finding with no fix never starts one. A fixed finding with
    no date and no configured start returns ``date.min``, which has
    already passed, so it gates at once rather than waiting forever.
    """
    if not fixable:
        return None
    known = [value for value in (fixed_on, start) if value is not None]
    if not known:
        return dt.date.min
    try:
        return max(known) + dt.timedelta(days=days)
    except OverflowError:
        return dt.date.max


def main() -> int:
    """Validate the window inputs, failing the step on a bad value."""
    today = utc_today()
    try:
        parse_days(os.environ.get("INPUT_REMEDIATION_WINDOW_DAYS"))
        parse_start(os.environ.get("INPUT_REMEDIATION_WINDOW_START"), today)
    except ValueError as error:
        print(f"::error::{annotation(error)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
