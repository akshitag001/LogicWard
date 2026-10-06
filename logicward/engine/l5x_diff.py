"""GitHub-style side-by-side diff of two L5X programs (baseline vs live).

Produces aligned rows with per-row status (equal / added / removed / changed) and,
for changed rows, word-level inline segments so the dashboard can highlight the
exact operand/operator that flipped — red on the baseline side, green on the live
side, like a pull-request diff. Operates on the canonical neutral-text lines, so
volatile noise never shows up as a change.
"""
from __future__ import annotations

import difflib
import re

from logicward.engine import l5x


def _tokens(s: str) -> list[str]:
    return re.findall(r"\w+|\W", s or "")


def _inline(a: str, b: str) -> tuple[list[dict], list[dict]]:
    """Word-level diff -> (left_segments, right_segments), each seg {text, hl}."""
    at, bt = _tokens(a), _tokens(b)
    sm = difflib.SequenceMatcher(a=at, b=bt, autojunk=False)
    left: list[dict] = []
    right: list[dict] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        la = "".join(at[i1:i2])
        rb = "".join(bt[j1:j2])
        if tag == "equal":
            if la:
                left.append({"text": la, "hl": False})
            if rb:
                right.append({"text": rb, "hl": False})
        else:
            if la:
                left.append({"text": la, "hl": True})
            if rb:
                right.append({"text": rb, "hl": True})
    return left, right


def side_by_side(baseline_lines: list[str], live_lines: list[str]) -> list[dict]:
    sm = difflib.SequenceMatcher(a=baseline_lines, b=live_lines, autojunk=False)
    rows: list[dict] = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                line = baseline_lines[i1 + k]
                rows.append({"type": "equal", "left": line, "right": live_lines[j1 + k],
                             "left_seg": [{"text": line, "hl": False}],
                             "right_seg": [{"text": live_lines[j1 + k], "hl": False}]})
        elif tag == "replace":
            left = baseline_lines[i1:i2]
            right = live_lines[j1:j2]
            for k in range(max(len(left), len(right))):
                l = left[k] if k < len(left) else None
                r = right[k] if k < len(right) else None
                ls, rs = _inline(l or "", r or "")
                rows.append({"type": "changed", "left": l, "right": r,
                             "left_seg": ls, "right_seg": rs})
        elif tag == "delete":
            for k in range(i1, i2):
                rows.append({"type": "removed", "left": baseline_lines[k], "right": None,
                             "left_seg": [{"text": baseline_lines[k], "hl": True}], "right_seg": []})
        elif tag == "insert":
            for k in range(j1, j2):
                rows.append({"type": "added", "left": None, "right": live_lines[k],
                             "left_seg": [], "right_seg": [{"text": live_lines[k], "hl": True}]})
    return rows


def diff_programs(baseline_prog: l5x.L5XProgram, live_prog: l5x.L5XProgram) -> dict:
    base_lines = l5x.neutral_text_lines(baseline_prog)
    live_lines = l5x.neutral_text_lines(live_prog)
    rows = side_by_side(base_lines, live_lines)
    summary = {"equal": 0, "added": 0, "removed": 0, "changed": 0}
    for r in rows:
        summary[r["type"]] += 1
    return {
        "rows": rows,
        "summary": summary,
        "changed": summary["added"] + summary["removed"] + summary["changed"],
        "baseline_hash": l5x.structural_hash(baseline_prog),
        "live_hash": l5x.structural_hash(live_prog),
    }
