"""CLI: verify a signed PDF forensic report (Prompt 3.2).

    python -m logicward.dashboard.verify_report report.pdf report.sig [pubkey.pem]
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

from logicward.dashboard.report_sign import verify_report


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if len(argv) < 2:
        print("usage: python -m logicward.dashboard.verify_report report.pdf report.sig [pubkey.pem]")
        return 2
    pdf = Path(argv[0]).read_bytes()
    manifest = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    pub = Path(argv[2]).read_bytes() if len(argv) > 2 else None
    ok = verify_report(pdf, manifest, pub)
    print(f"Report signature: {'VALID' if ok else 'INVALID'}  "
          f"(key {manifest.get('fingerprint', '?')})")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
