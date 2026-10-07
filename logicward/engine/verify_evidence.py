"""CLI: verify the tamper-evident evidence chain (Prompt 3.1).

    python -m logicward.engine.verify_evidence logicward/data/evidence.jsonl
"""
from __future__ import annotations

import sys

from logicward import config
from logicward.engine.events import verify_chain


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    path = argv[0] if argv else str(config.EVIDENCE_PATH)
    ok, bad = verify_chain(path)
    if ok:
        print(f"Evidence chain: VERIFIED  ({path})")
        return 0
    print(f"Evidence chain: BROKEN at line {bad}  ({path})")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
