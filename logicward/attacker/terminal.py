"""Scoped command runner for the in-console terminals.

The red-team console (:9090, including its Insider tab) exposes a terminal so
operators can run the ATTACK commands live (judges see real commands, not a
button). To keep that safe it is deliberately **not** an open shell: only the
project's two attack entrypoints may run, arguments are shlex-parsed, shell
metacharacters are rejected, and there is a hard timeout. `subprocess` is invoked
with an explicit argv (never `shell=True`).
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys

from logicward import config

ALLOWED_MODULES = ("logicward.attacker.attacks", "logicward.sites.grfics.attacks")
_BAD_CHARS = set(";|&`$><\n\r")

HELP = ("Scoped terminal — only the Vigilo attack CLI runs here:\n"
        "  python -m logicward.attacker.attacks --host <H> --modbus-port <P> <command>\n"
        "  python -m logicward.sites.grfics.attacks --host <H> --port <P> <command>\n"
        "Type  help  for this message.")


def allowed_hosts() -> set[str]:
    """Targets the console may attack (Prompt 2.5): the lab PLC hosts only, plus
    anything explicitly listed in LOGICWARD_ATTACK_TARGETS (comma-separated)."""
    hosts = {"127.0.0.1", "localhost", config.PI_HOST, config.GRFICS_MODBUS_HOST}
    extra = os.environ.get("LOGICWARD_ATTACK_TARGETS", "")
    hosts |= {h.strip() for h in extra.split(",") if h.strip()}
    return hosts


def allowed_ports() -> set[int]:
    return {config.MODBUS_PORT, config.GRFICS_MODBUS_PORT, 502, 5020, 5021}


def _flag_values(args: list[str], *names: str) -> list[str]:
    """All values given for any of `names` (supports `--x v` and `--x=v`)."""
    vals: list[str] = []
    for i, a in enumerate(args):
        for n in names:
            if a == n and i + 1 < len(args):
                vals.append(args[i + 1])
            elif a.startswith(n + "="):
                vals.append(a.split("=", 1)[1])
    return vals


def check_targets(args: list[str]) -> str | None:
    """Return an error message if the command targets a host/port off the allow-list."""
    hosts = allowed_hosts()
    for h in _flag_values(args, "--host"):
        if h not in hosts:
            return (f"rejected: --host {h} is not an allowed lab target "
                    f"(allowed: {', '.join(sorted(hosts))}; extend via LOGICWARD_ATTACK_TARGETS)")
    ports = allowed_ports()
    for v in _flag_values(args, "--modbus-port", "--port"):
        try:
            port = int(v)
        except ValueError:
            return f"rejected: port {v!r} is not a number"
        if port not in ports:
            return f"rejected: port {port} is not a known lab port (allowed: {', '.join(map(str, sorted(ports)))})"
    return None


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
    err = check_targets(args)
    if err:
        return False, err
    argv = [sys.executable, "-m", module, *args]
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        out = ((r.stdout or "") + (r.stderr or "")).strip()
        return True, out or "(no output)"
    except subprocess.TimeoutExpired:
        return False, f"command timed out after {timeout:.0f}s"
    except Exception as exc:  # noqa: BLE001
        return False, f"error: {exc}"
