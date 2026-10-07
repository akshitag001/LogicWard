"""Verify the hash-chained, tamper-evident evidence log (Prompt 3.1).

Run:  python -m logicward.tests.smoke_evidence
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from logicward.engine.events import EvidenceLog, new_event, verify_chain

_checks: list[tuple[bool, str]] = []


def check(cond: bool, label: str) -> None:
    _checks.append((bool(cond), label))
    print(f"  [{'PASS' if cond else 'FAIL'}] {label}")


def main() -> int:
    tmp = Path(tempfile.mkdtemp(prefix="lw_ev_")) / "evidence.jsonl"
    log = EvidenceLog(tmp)
    for i in range(10):
        log.append(new_event("cyber.setpoint_drift", "test", {"n": i}))

    lines = [ln for ln in tmp.read_text(encoding="utf-8").splitlines() if ln.strip()]
    check(len(lines) == 10, f"10 events written ({len(lines)})")
    first = json.loads(lines[0])
    check(first.get("prev_hash") == "GENESIS", "first line links to GENESIS")
    check(all(json.loads(lines[i])["prev_hash"] == json.loads(lines[i - 1])["entry_hash"]
              for i in range(1, 10)), "every line chains to the previous entry_hash")

    ok, bad = verify_chain(tmp)
    check(ok and bad is None, "intact chain verifies OK")

    # tamper line 4 by hand (change a detail, leave the hashes)
    rec = json.loads(lines[3])
    rec["details"]["n"] = 999
    lines[3] = json.dumps(rec)
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    ok, bad = verify_chain(tmp)
    check((not ok) and bad == 4, f"editing line 4 is detected at line {bad}")

    # a resumed log continues the chain and verifies after reopen
    tmp2 = Path(tempfile.mkdtemp(prefix="lw_ev2_")) / "evidence.jsonl"
    EvidenceLog(tmp2).append(new_event("resource.cpu_spike", "test", {}))
    log2 = EvidenceLog(tmp2)                 # resume
    log2.append(new_event("resource.cpu_spike", "test", {}))
    log2.checkpoint()
    ok, bad = verify_chain(tmp2)
    check(ok, "resumed chain + signed checkpoint verifies")
    tail = json.loads([ln for ln in tmp2.read_text(encoding="utf-8").splitlines() if ln.strip()][-1])
    check(tail.get("checkpoint") and tail.get("hmac", "").startswith("hmac-sha256:"),
          "checkpoint line is HMAC-signed")

    # CLI
    import subprocess
    import sys
    r = subprocess.run([sys.executable, "-m", "logicward.engine.verify_evidence", str(tmp2)],
                       capture_output=True, text=True)
    check(r.returncode == 0 and "VERIFIED" in r.stdout, "verify_evidence CLI reports VERIFIED on a good chain")
    r = subprocess.run([sys.executable, "-m", "logicward.engine.verify_evidence", str(tmp)],
                       capture_output=True, text=True)
    check(r.returncode == 1 and "BROKEN at line 4" in r.stdout, "verify_evidence CLI reports BROKEN at line 4")

    passed = sum(1 for ok, _ in _checks if ok)
    total = len(_checks)
    print(f"\n{'='*52}\n  RESULT: {passed}/{total} checks passed\n{'='*52}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    raise SystemExit(main())
