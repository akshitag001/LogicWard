"""`python -m logicward` / the `logicward` console script.

Subcommands:
    (none) | dashboard   run the single-machine SOC dashboard (embedded plant)
    demo                 dashboard + red-team console + browser, Ctrl+C stops both
    attack <name> ...    thin alias for `python -m logicward.attacker.attacks`
"""
from __future__ import annotations

import os
import subprocess
import sys
import time
import webbrowser

from logicward import config


def _run_dashboard() -> None:
    from logicward.dashboard.app import main as run
    run()


def _run_attack(argv: list[str]) -> None:
    from logicward.attacker import attacks
    sys.argv = ["logicward.attacker.attacks", *argv]
    attacks.main()


def _run_demo() -> None:
    """Bring up the dashboard + red-team console, open the browser, and stop both
    cleanly on Ctrl+C."""
    dash_port = config.INGEST_PORT
    console_port = 9090
    console_bind = os.environ.get("LOGICWARD_CONSOLE_BIND", "127.0.0.1")
    env = dict(os.environ)
    env.setdefault("LOGICWARD_MULTISITE", "1")       # thermal + chemical sites
    env.setdefault("LOGICWARD_EMBED_PLANT", "1")

    procs: list[subprocess.Popen] = []
    try:
        procs.append(subprocess.Popen([sys.executable, "-m", "logicward.dashboard.app"], env=env))
        procs.append(subprocess.Popen(
            [sys.executable, "-m", "logicward.attacker.dashboard",
             "--host", "127.0.0.1", "--bind", console_bind, "--port", str(console_port)], env=env))
        time.sleep(2.0)
        url = f"http://127.0.0.1:{dash_port}/login"
        print("\n" + "=" * 60)
        print("  LogicWard demo is up")
        print(f"  SOC dashboard   : {url}")
        print(f"  Red-team console: http://127.0.0.1:{console_port}/")
        print("  Logins          : soc/soc123 · engineer/engineer123 · operator/operator123")
        print("                    netsec/netsec123 · vendor/vendor123 · ciso/ciso123")
        print("  Ctrl+C to stop both.")
        print("=" * 60 + "\n")
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
        while all(p.poll() is None for p in procs):
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nstopping…")
    finally:
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(timeout=5)
            except Exception:  # noqa: BLE001
                p.kill()


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "dashboard"
    if cmd in ("dashboard", "serve", ""):
        _run_dashboard()
    elif cmd == "demo":
        _run_demo()
    elif cmd == "attack":
        _run_attack(argv[1:])
    else:
        print("usage: python -m logicward [dashboard|demo|attack <name> ...]")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
