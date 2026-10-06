"""`python -m logicward` / the `logicward` console script.

Subcommands are expanded in Prompt 4.4 (demo, attack). For now this runs the
single-machine dashboard, matching `python -m logicward.dashboard.app`.
"""
from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    cmd = argv[0] if argv else "dashboard"
    if cmd in ("dashboard", "serve", ""):
        from logicward.dashboard.app import main as run
        run()
    else:
        print(f"unknown command: {cmd}\nusage: python -m logicward [dashboard]")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
