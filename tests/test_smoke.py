"""pytest wrappers around the standalone smoke suites.

Each suite is integration-style: it spins up real servers on ephemeral localhost
ports and exercises real HTTP paths, then exits 0 (all checks passed) or non-zero.
They need no Raspberry Pi, no external network, and no root.

We run each suite in its OWN subprocess (a fresh interpreter), which is exactly
how they are designed to run (`python -m logicward.tests.smoke_<name>`). That
isolation keeps background threads, Modbus ports, and watchdog FIM timers from one
suite from bleeding into the next. The original entrypoints keep working unchanged.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]

SUITES = [
    "bus", "l5x", "plant", "drift", "agent",
    "dashboard", "attacker", "grfics", "multisite", "classify",
]


@pytest.mark.parametrize("name", SUITES)
def test_smoke_suite(name: str) -> None:
    env = dict(os.environ)
    # If a coverage run set COVERAGE_PROCESS_START, make sure the subprocess can
    # import the repo-root sitecustomize that calls coverage.process_startup().
    if env.get("COVERAGE_PROCESS_START"):
        env["PYTHONPATH"] = str(_REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, "-m", f"logicward.tests.smoke_{name}"],
        capture_output=True, text=True, timeout=300, env=env,
    )
    if proc.returncode != 0:
        pytest.fail(f"smoke_{name} failed:\n{proc.stdout[-3000:]}\n{proc.stderr[-2000:]}")
