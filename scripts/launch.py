#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 The Linux Foundation

"""Run one of the action's helper modules without trusting the cwd.

The action's steps run in ``$GITHUB_WORKSPACE``, which can hold a
checkout the caller does not trust. ``python3 -m`` puts that directory
first on ``sys.path``, so a planted ``scripts/`` package or a module
named like a standard one (``json.py``) would run in place of the
action's own code.

The steps therefore start this file with ``python3 -I``, which keeps
the working directory and this file's directory off ``sys.path`` and
ignores the ``PYTHON*`` variables that steer imports (``PYTHONPATH``,
``PYTHONHOME``, ``PYTHONSTARTUP`` and the like). This launcher then
binds the ``scripts`` package to the directory it lives in, by path,
and runs the requested helper as ``__main__``.

It adds nothing to ``sys.path``. Prepending the action's root would
let any file there shadow the standard library. Appending it instead
would let an installed package named ``scripts`` win the lookup.

Usage: ``python3 -I scripts/launch.py <helper>``, where ``<helper>``
is a module name such as ``evaluate``.
"""

from __future__ import annotations

import importlib.util
import pathlib
import runpy
import sys

PACKAGE = "scripts"
HELPERS = ("collect_bypasses", "evaluate", "window")


def bind_package() -> None:
    """Register this directory as the ``scripts`` package."""
    here = pathlib.Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location(
        PACKAGE,
        here / "__init__.py",
        submodule_search_locations=[str(here)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load the {PACKAGE} package from {here}")
    package = importlib.util.module_from_spec(spec)
    sys.modules[PACKAGE] = package
    spec.loader.exec_module(package)


def main(argv: list[str]) -> int:
    """Run the named helper; its own ``sys.exit`` sets the status."""
    if len(argv) != 2 or argv[1] not in HELPERS:
        print(
            f"usage: python3 -I {argv[0]} <{'|'.join(HELPERS)}>",
            file=sys.stderr,
        )
        return 2
    helper = f"{PACKAGE}.{argv[1]}"
    bind_package()
    # The helpers see the argv that 'python3 -m' gave them.
    del sys.argv[1:]
    runpy.run_module(helper, run_name="__main__", alter_sys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
