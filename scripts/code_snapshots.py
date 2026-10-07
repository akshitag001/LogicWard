"""Render the most important code excerpts as clean images (Prompt 5.2).

Excerpts are located BY NAME with the `ast` module (not hardcoded line numbers),
so the images stay correct after edits. Each is trimmed to its essentials
(docstrings dropped) and rendered with Pygments + a rounded card via Pillow into
docs/screenshots/code/.

Usage:  python scripts/code_snapshots.py
"""
from __future__ import annotations

import ast
from pathlib import Path

from PIL import Image, ImageDraw
from pygments import highlight
from pygments.formatters import ImageFormatter
from pygments.lexers import PythonLexer

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots" / "code"
OUT.mkdir(parents=True, exist_ok=True)

# image basename -> (module path, [top-level names to include])
EXCERPTS = {
    "canonicalize.png": ("logicward/engine/l5x.py", ["canonical", "structural_hash"]),
    "branch-tree.png":  ("logicward/engine/l5x.py", ["_parse_series", "build_logic_tree"]),
    "inversion.png":    ("logicward/engine/drift.py", ["_diff_rung"]),
    "severity.png":     ("logicward/engine/events.py", ["BASE_WEIGHTS", "compute_severity"]),
    "hash-chain.png":   ("logicward/engine/events.py", ["_entry_hash", "verify_chain"]),
    "hmac-baseline.png": ("logicward/engine/baseline.py", ["capture", "verify"]),
}


def _strip_docstring(node: ast.AST) -> None:
    body = getattr(node, "body", None)
    if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant) \
            and isinstance(body[0].value.value, str):
        del body[0]


def extract(module_path: str, names: list[str]) -> str:
    src = (ROOT / module_path).read_text(encoding="utf-8")
    tree = ast.parse(src)
    chunks: list[str] = []
    for name in names:
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
                _strip_docstring(node)
                chunks.append(ast.unparse(node))
                break
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == name for t in node.targets):
                chunks.append(ast.unparse(node))
                break
    text = "\n\n\n".join(chunks)
    # keep each excerpt compact
    lines = text.splitlines()
    if len(lines) > 30:
        lines = lines[:29] + ["    # …"]
    return "\n".join(lines) + "\n"


def round_corners(img: Image.Image, radius: int = 16, pad: int = 18,
                  bg=(13, 17, 23)) -> Image.Image:
    canvas = Image.new("RGBA", (img.width + 2 * pad, img.height + 2 * pad), (0, 0, 0, 0))
    card = Image.new("RGBA", (img.width + 2 * pad, img.height + 2 * pad), bg + (255,))
    mask = Image.new("L", card.size, 0)
    ImageDraw.Draw(mask).rounded_rectangle([0, 0, card.width - 1, card.height - 1],
                                           radius=radius, fill=255)
    canvas.paste(card, (0, 0), mask)
    canvas.paste(img, (pad, pad))
    return canvas


def main() -> int:
    for fname, (mod, names) in EXCERPTS.items():
        code = extract(mod, names)
        png = highlight(code, PythonLexer(), ImageFormatter(
            style="monokai", font_size=28, line_numbers=True, line_number_bg="#1b2028",
            line_number_fg="#5b6b80", image_pad=22))
        tmp = OUT / ("_" + fname)
        tmp.write_bytes(png)
        img = Image.open(tmp).convert("RGBA")
        round_corners(img).save(OUT / fname)
        tmp.unlink()
        print("saved", fname)
    print("\ncode snapshots:", sorted(x.name for x in OUT.glob("*.png")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
