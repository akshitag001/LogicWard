"""Scoped command runner for the in-console terminals.

Both the red-team console (:9090) and the SOC 'Insider' tab expose a terminal so
operators can run the ATTACK commands live (judges see real commands, not a
button). To keep that safe it is deliberately **not** an open shell: only the
project's two attack entrypoints may run, arguments are shlex-parsed, shell
metacharacters are rejected, and there is a hard timeout. `subprocess` is invoked
with an explicit argv (never `shell=True`).
"""
from __future__ import annotations

import shlex
import subprocess
import sys

ALLOWED_MODULES = ("logicward.attacker.attacks", "logicward.sites.grfics.attacks")
_BAD_CHARS = set(";|&`$><\n\r")

HELP = ("Scoped terminal — only the Vigilo attack CLI runs here:\n"
        "  python -m logicward.attacker.attacks --host <H> --modbus-port <P> <command>\n"
        "  python -m logicward.sites.grfics.attacks --host <H> --port <P> <command>\n"
        "Type  help  for this message.")


def run_scoped(cmd: str, timeout: float = 30.0) -> tuple[bool, str]:
    """Run one allow-listed attack command. Returns (ok, combined_output)."""
    cmd = (cmd or "").strip()
    if not cmd:
        return False, "empty command"
    if cmd.lower() in ("help", "?"):
        return True, HELP
    if any(ch in cmd for ch in _BAD_CHARS):
        return False, "rejected: shell metacharacters (; | & ` $ > <) are not allowed"
    try:
        parts = shlex.split(cmd)
    except ValueError as exc:
        return False, f"parse error: {exc}"
    if parts and parts[0] in ("python", "python3", "py"):
        parts = parts[1:]
    if parts[:1] != ["-m"] or len(parts) < 2:
        return False, "only 'python -m <vigilo attack module> ...' is allowed (type: help)"
    module, args = parts[1], parts[2:]
    if module not in ALLOWED_MODULES:
        return False, f"module '{module}' not allowed. Allowed: {', '.join(ALLOWED_MODULES)}"
    argv = [sys.executable, "-m", module, *args]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        return True, out or "(no output)"
    except subprocess.TimeoutExpired:
        return False, f"command timed out after {timeout:.0f}s"
    except Exception as exc:  # noqa: BLE001
        return False, f"error: {exc}"
