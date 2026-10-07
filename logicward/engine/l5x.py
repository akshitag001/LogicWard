"""L5X (Rockwell Studio 5000) program parser + canonicalizer.

The PLC "program" is a real `.L5X` XML export. This module turns it into a
canonical, logic-only representation the drift engine can diff and hash —
deliberately *excluding* volatile noise (export/edit timestamps, revisions,
CRCs, and free-text comments) so a re-export with no logic change produces an
identical structural hash (no false positives).

Neutral-text ladder (e.g. ``XIC(Plant_Running)[LES(Drum_Level,Drum_Level_LL_SP)]
OTE(Feedwater_Trip);``) is tokenized into instruction/operand structs so the
drift engine can name the six mutation classes rather than just "something changed".

The program is DATA — it is parsed and compared, never executed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from lxml import etree

# ── Ladder instruction taxonomy (Rockwell mnemonics) ──────────────────────────
CONTACTS = {"XIC", "XIO"}                       # examine-if-closed / -open
COMPARES = {"GRT", "LES", "GEQ", "LEQ", "EQU", "NEQ", "LIM"}
OUTPUTS = {"OTE", "OTL", "OTU"}                 # energize / latch / unlatch

#: Attributes that change between exports without changing logic — stripped from
#: any XML-level canonical form so they never trigger a false drift alert.
VOLATILE_ATTRS = {
    "ExportDate", "EditedDate", "ProjectCreationDate", "LastModifiedDate",
    "ExportOptions", "SoftwareRevision", "ProjectSN", "CreatedDate", "CreatedBy",
    "EditedBy", "Owner", "CRC", "MajorRev", "MinorRev", "TimeSlice",
}

_TOKEN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)")
#: Same shape as _TOKEN_RE but anchored, for scanning a rung left-to-right so we
#: can see the branch delimiters [ ] , *between* instructions (Prompt 1.1).
_INSTR_AT = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\s*\(([^()]*)\)")


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class Instruction:
    op: str
    args: list[str]

    def as_tuple(self) -> list:
        return [self.op, list(self.args)]

    def render(self) -> str:
        return f"{self.op}({','.join(self.args)})"


@dataclass
class Rung:
    number: int
    text: str                       # normalized neutral text (whitespace-collapsed)
    comment: str                    # tracked for display; NOT part of the logic hash
    instructions: list[Instruction]
    output_op: str | None
    output_coil: str | None
    safety_critical: bool
    logic_tree: list = field(default_factory=list)   # serialized AND/OR input structure

    @property
    def inputs(self) -> list[Instruction]:
        return [i for i in self.instructions if i.op in CONTACTS]

    @property
    def compares(self) -> list[Instruction]:
        return [i for i in self.instructions if i.op in COMPARES]

    def rung_id(self, routine: str) -> str:
        return f"{routine}/Rung{self.number}"


@dataclass
class L5XProgram:
    controller: str
    setpoints: dict[str, float]                 # *_SP tag name -> value
    tags: dict[str, dict] = field(default_factory=dict)
    routines: dict[str, list[Rung]] = field(default_factory=dict)
    source_xml: bytes = b""
    tag_values: dict[str, str] = field(default_factory=dict)      # ALL scalar tags -> value (Prompt 1.2)
    non_rll_routines: dict[str, dict] = field(default_factory=dict)  # name -> {type, sig}
    aois: dict[str, str] = field(default_factory=dict)            # AOI name -> body signature
    tasks: dict[str, dict] = field(default_factory=dict)          # task name -> {type, rate, priority, scheduled}


# ── Neutral-text parsing ──────────────────────────────────────────────────────

def parse_neutral_text(text: str) -> list[Instruction]:
    """Tokenize ladder neutral text into ordered instructions.

    Branch delimiters ``[`` ``]`` and the trailing ``;`` are ignored — only the
    instructions and their operands are structurally significant.
    """
    out: list[Instruction] = []
    for op, raw_args in _TOKEN_RE.findall(text or ""):
        args = [a.strip() for a in raw_args.split(",") if a.strip()]
        out.append(Instruction(op.upper(), args))
    return out


def _tokenize_rung(text: str) -> list[tuple]:
    """Scan a rung into tokens: ('I', Instruction) | ('[',) | (']',) | (',',).

    Commas INSIDE an instruction's parens (e.g. ``LES(A,B)``) are consumed as
    part of that instruction token, so the only bare ``,`` tokens are branch
    separators — which is exactly what distinguishes series (AND) from a
    parallel ``[ … , … ]`` branch (OR).
    """
    toks: list[tuple] = []
    s = text or ""
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch in "[],":
            toks.append((ch,))
            i += 1
        elif ch == ";" or ch.isspace():
            i += 1
        else:
            m = _INSTR_AT.match(s, i)
            if m:
                args = [a.strip() for a in m.group(2).split(",") if a.strip()]
                toks.append(("I", Instruction(m.group(1).upper(), args)))
                i = m.end()
            else:
                i += 1
    return toks


def _parse_series(toks: list[tuple], pos: int) -> tuple[tuple, int]:
    """Parse a series (AND) of nodes until a ``]`` or ``,`` (or end). A ``[`` opens
    a parallel branch (OR) of comma-separated legs, each itself a series."""
    children: list[tuple] = []
    while pos < len(toks):
        tag = toks[pos][0]
        if tag in ("]", ","):
            break
        if tag == "[":
            pos += 1
            legs = []
            leg, pos = _parse_series(toks, pos)
            legs.append(leg)
            while pos < len(toks) and toks[pos][0] == ",":
                pos += 1
                leg, pos = _parse_series(toks, pos)
                legs.append(leg)
            if pos < len(toks) and toks[pos][0] == "]":
                pos += 1
            children.append(("OR", legs))
        else:  # ('I', Instruction)
            children.append(("I", toks[pos][1]))
            pos += 1
    return ("AND", children), pos


def _serialize_tree(node: tuple) -> list:
    """Deterministic nested-list serialization of a logic tree node."""
    if node[0] == "I":
        instr: Instruction = node[1]
        return ["I", instr.op, list(instr.args)]
    return [node[0], [_serialize_tree(c) for c in node[1]]]


def build_logic_tree(text: str) -> tuple[list, list[Instruction]]:
    """Return (serialized input logic tree, [output Instructions]) for a rung.

    Series = AND, ``[a,b]`` = OR(a,b); legs can nest. Outputs (OTE/OTL/OTU) at the
    top level are split out so the structure of the *inputs* is what the tree
    captures — flipping ``A·B`` to ``A+B`` changes the tree (and the hash) even
    though the instruction set is identical.
    """
    tree, _ = _parse_series(_tokenize_rung(text), 0)
    inputs: list[tuple] = []
    outputs: list[Instruction] = []
    for node in tree[1]:
        if node[0] == "I" and node[1].op in OUTPUTS:
            outputs.append(node[1])
        else:
            inputs.append(node)
    return _serialize_tree(("AND", inputs)), outputs


def _classify_output(instrs: list[Instruction]) -> tuple[str | None, str | None]:
    outs = [i for i in instrs if i.op in OUTPUTS]
    if not outs:
        return None, None
    last = outs[-1]
    return last.op, (last.args[0] if last.args else None)


def _routine_body_sig(element) -> str:
    """Stable signature of a non-RLL routine (ST/FBD/SFC) or AOI body.

    For Structured Text we hash the concatenated line text; for any other body we
    hash its C14N XML with volatile attributes and comments stripped — so a
    cosmetic re-export is invariant but a real logic edit changes the signature.
    """
    st_lines = [ln.text or "" for ln in element.findall(".//STContent/Line")]
    if st_lines:
        payload = "\n".join(" ".join((t or "").split()) for t in st_lines).encode("utf-8")
    else:
        clone = etree.fromstring(etree.tostring(element))
        for el in clone.iter():
            for attr in list(el.attrib):
                if attr in VOLATILE_ATTRS:
                    del el.attrib[attr]
        for c in clone.xpath("//comment()"):
            c.getparent().remove(c)
        payload = etree.tostring(clone, method="c14n")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


SAFETY_TAGS_PATH = Path(__file__).resolve().parents[1] / "plant" / "program" / "safety_tags.json"
_log = logging.getLogger("logicward.l5x")
_warned_fallback: set[str] = set()


def load_safety_tags(path: str | Path | None = None) -> list[str]:
    """The explicit safety-critical tag allow-list (Prompt 1.5)."""
    p = Path(path or SAFETY_TAGS_PATH)
    try:
        return sorted(json.loads(p.read_text(encoding="utf-8")).get("safety_tags", []))
    except (OSError, ValueError):
        return []


def _is_safety_critical(output_coil: str | None, safety_tags=None) -> bool:
    """Safety classification = membership in the explicit allow-list.

    The old name-keyword heuristic ("trip"/"fuel"/"feedwater") is kept ONLY as a
    fallback for tags not in the list, and logs a warning when used — renaming a
    coil can no longer silently drop its severity for listed tags.
    """
    if not output_coil:
        return False
    tags = set(load_safety_tags() if safety_tags is None else safety_tags)
    if output_coil in tags:
        return True
    hit = any(key in output_coil.lower() for key in ("trip", "fuel", "feedwater"))
    if hit and output_coil not in _warned_fallback:
        _warned_fallback.add(output_coil)
        _log.warning("safety classification for %r used the keyword fallback "
                     "(tag not in safety_tags.json)", output_coil)
    return hit


# ── Parsing ───────────────────────────────────────────────────────────────────

def parse(xml: bytes | str, safety_tags: list[str] | None = None) -> L5XProgram:
    """Parse an L5X document into an `L5XProgram`.

    `safety_tags` overrides the shipped allow-list (the drift engine passes the
    list stored in the signed baseline manifest).
    """
    if safety_tags is None:
        safety_tags = load_safety_tags()
    if isinstance(xml, str):
        xml = xml.encode("utf-8")
    root = etree.fromstring(xml)
    controller = root.find("Controller")
    if controller is None:
        raise ValueError("not a valid L5X: no <Controller> element")

    # -- tags + setpoints (controller- AND program-scoped) --
    tags: dict[str, dict] = {}
    setpoints: dict[str, float] = {}
    tag_values: dict[str, str] = {}

    def _read_tags(container, prefix: str) -> None:
        for tag in container.findall("Tags/Tag"):
            name = tag.get("Name")
            if not name:
                continue
            key = prefix + name
            dtype = tag.get("DataType")
            dv = tag.find(".//DataValue")
            value = dv.get("Value") if dv is not None else None
            tags[key] = {"type": dtype, "value": value}
            if value is not None:
                tag_values[key] = value          # ALL scalar tag values (Prompt 1.2)
            if name.endswith("_SP") and value is not None:
                try:
                    setpoints[name] = float(value)
                except ValueError:
                    pass

    _read_tags(controller, "")

    # -- routines / rungs (RLL) + non-RLL routine signatures --
    routines: dict[str, list[Rung]] = {}
    non_rll: dict[str, dict] = {}
    for program in controller.findall("Programs/Program"):
        pname = program.get("Name", "?")
        _read_tags(program, f"{pname}/")
        for routine in program.findall("Routines/Routine"):
            rname = routine.get("Name", "?")
            rtype = routine.get("Type")
            if rtype == "RLL":
                rungs: list[Rung] = []
                for rung_el in routine.findall("RLLContent/Rung"):
                    number = int(rung_el.get("Number", "0"))
                    text = " ".join((rung_el.findtext("Text") or "").split())
                    comment = " ".join((rung_el.findtext("Comment") or "").split())
                    instrs = parse_neutral_text(text)
                    out_op, out_coil = _classify_output(instrs)
                    tree, _outs = build_logic_tree(text)
                    rungs.append(Rung(
                        number=number, text=text, comment=comment,
                        instructions=instrs, output_op=out_op, output_coil=out_coil,
                        safety_critical=_is_safety_critical(out_coil, safety_tags),
                        logic_tree=tree,
                    ))
                routines[rname] = sorted(rungs, key=lambda r: r.number)
            else:
                non_rll[f"{pname}/{rname}"] = {"type": rtype, "sig": _routine_body_sig(routine)}

    # -- Add-On Instruction definitions + Tasks (scan scheduling) --
    aois: dict[str, str] = {}
    for aoi in controller.findall("AddOnInstructionDefinitions/AddOnInstructionDefinition"):
        aois[aoi.get("Name", "?")] = _routine_body_sig(aoi)

    tasks: dict[str, dict] = {}
    for task in controller.findall("Tasks/Task"):
        tasks[task.get("Name", "?")] = {
            "type": task.get("Type"),
            "rate": task.get("Rate"),
            "priority": task.get("Priority"),
            "scheduled": sorted(sp.get("Name", "")
                                for sp in task.findall("ScheduledPrograms/ScheduledProgram")),
        }

    return L5XProgram(controller=controller.get("Name", "?"),
                      setpoints=setpoints, tags=tags, routines=routines,
                      source_xml=xml, tag_values=tag_values, non_rll_routines=non_rll,
                      aois=aois, tasks=tasks)


def load(path: str | Path) -> L5XProgram:
    return parse(Path(path).read_bytes())


# ── Canonical forms ───────────────────────────────────────────────────────────

def canonical(program: L5XProgram) -> dict:
    """Deterministic, logic-only view used for diffing + hashing.

    Excludes timestamps, revisions, and comments — only instructions, operands,
    output coils, and setpoint values are structurally significant.
    """
    return {
        "controller": program.controller,
        "setpoints": {k: program.setpoints[k] for k in sorted(program.setpoints)},
        # ALL scalar tag values (not just *_SP) — timer presets, constants, flags (Prompt 1.2)
        "tag_values": {k: program.tag_values[k] for k in sorted(program.tag_values)},
        "routines": {
            rname: [
                {
                    "number": r.number,
                    "logic": [i.as_tuple() for i in r.instructions],
                    "logic_tree": r.logic_tree,          # AND/OR structure (Prompt 1.1)
                    "output_coil": r.output_coil,
                    "safety_critical": r.safety_critical,
                }
                for r in rungs
            ]
            for rname, rungs in sorted(program.routines.items())
        },
        # non-ladder routines (ST/FBD/SFC), AOIs, and task scheduling (Prompt 1.2)
        "non_rll_routines": {k: program.non_rll_routines[k] for k in sorted(program.non_rll_routines)},
        "aois": {k: program.aois[k] for k in sorted(program.aois)},
        "tasks": {k: program.tasks[k] for k in sorted(program.tasks)},
    }


def structural_hash(program: L5XProgram) -> str:
    """SHA-256 of the canonical logic view (`sha256:...`)."""
    blob = json.dumps(canonical(program), sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(blob.encode("utf-8")).hexdigest()


def neutral_text_lines(program: L5XProgram) -> list[str]:
    """One human-readable, normalized line per rung — the input to the dashboard's
    GitHub-style side-by-side diff. Stable ordering; excludes volatile noise."""
    lines: list[str] = []
    for rname in sorted(program.routines):
        for r in program.routines[rname]:
            sp = ""
            # inline any setpoint referenced by a compare, so a setpoint drift is
            # visible in the diff text itself
            refs = [a for i in r.compares for a in i.args if a in program.setpoints]
            if refs:
                sp = "   ; " + ", ".join(f"{n}={program.setpoints[n]:g}" for n in refs)
            lines.append(f"{r.rung_id(rname)}: {r.text}{sp}")
    return lines


def strip_volatile_xml(xml: bytes | str) -> bytes:
    """Return C14N-canonical XML with volatile attributes removed.

    Useful for a raw-tree integrity hash; the semantic `canonical()` above is the
    primary drift surface.
    """
    if isinstance(xml, str):
        xml = xml.encode("utf-8")
    root = etree.fromstring(xml)
    for el in root.iter():
        for attr in list(el.attrib):
            if attr in VOLATILE_ATTRS:
                del el.attrib[attr]
    return etree.tostring(root, method="c14n")
