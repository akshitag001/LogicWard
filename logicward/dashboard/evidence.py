"""Evidence log query + PDF forensic report (reportlab).

Every event on the bus is already persisted as JSONL (SIEM-ready) by the
EvidenceLog. This module reads it back for the dashboard and renders the signed
incident report a SOC hands to an investigator: who / when / what changed / the
ICS technique.
"""
from __future__ import annotations

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer, Table,
                                TableStyle)

NAVY = colors.HexColor("#14304F")
SEV_COLOR = {
    "critical": colors.HexColor("#C02626"), "high": colors.HexColor("#C05621"),
    "medium": colors.HexColor("#A16207"), "low": colors.HexColor("#0E7A0E"),
    "info": colors.HexColor("#5B6B80"),
}


def query(events: list[dict], severity: str | None = None, etype: str | None = None,
          site: str | None = None, limit: int = 500) -> list[dict]:
    rows = events
    if severity:
        rows = [e for e in rows if e.get("severity") == severity]
    if etype:
        rows = [e for e in rows if e.get("type", "").startswith(etype)]
    if site:
        # thermal events omit details.site → default to the thermal site id
        rows = [e for e in rows if (e.get("details") or {}).get("site", "thermal-pi") == site]
    rows = sorted(rows, key=lambda e: e.get("seq", 0), reverse=True)
    return rows[:limit]


def summary(events: list[dict]) -> dict:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for e in events:
        counts[e.get("severity", "info")] = counts.get(e.get("severity", "info"), 0) + 1
    return counts


def build_pdf(events: list[dict], meta: dict | None = None) -> bytes:
    meta = meta or {}
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=18 * mm, bottomMargin=16 * mm,
                            leftMargin=16 * mm, rightMargin=16 * mm,
                            title="Vigilo Forensic Report")
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], textColor=NAVY, fontSize=20, spaceAfter=2)
    sub = ParagraphStyle("sub", parent=styles["Normal"], textColor=colors.HexColor("#5B6B80"), fontSize=9)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], textColor=NAVY, fontSize=12, spaceBefore=10)
    cell = ParagraphStyle("cell", parent=styles["Normal"], fontSize=7.5, leading=9)

    story = [Paragraph("Vigilo — OT Drift Forensic Report", h1),
             Paragraph(f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M:%S} UTC · "
                       f"Controller: {meta.get('controller', '?')} · "
                       f"Baseline: {meta.get('baseline_hash', '?')[:23]}… · "
                       f"Baseline integrity: {meta.get('baseline_integrity', '?')}", sub),
             Spacer(1, 8)]

    counts = summary(events)
    sev_tbl = Table([["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                     [counts["critical"], counts["high"], counts["medium"], counts["low"], counts["info"]]],
                    colWidths=[35 * mm] * 5)
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, 0), SEV_COLOR["critical"]),
        ("BACKGROUND", (1, 0), (1, 0), SEV_COLOR["high"]),
        ("BACKGROUND", (2, 0), (2, 0), SEV_COLOR["medium"]),
        ("BACKGROUND", (3, 0), (3, 0), SEV_COLOR["low"]),
        ("BACKGROUND", (4, 0), (4, 0), SEV_COLOR["info"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9), ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.white), ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story += [Paragraph("Severity summary", h2), sev_tbl, Spacer(1, 6),
              Paragraph(f"Total events: {len(events)}", sub),
              Paragraph("Event timeline (most recent first)", h2)]

    def _xesc(s: str) -> str:
        return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    header = ["Time (UTC)", "Sev", "Type", "By whom", "MITRE", "Origin", "Detail"]
    data = [header]
    for e in query(events, limit=120):
        m = e.get("mitre", {})
        det = e.get("details", {})
        detail = _xesc(str(det.get("reason", ""))[:90])
        if det.get("command"):
            detail += f"<br/><font face='Courier' size='6'>{_xesc(det['command'])}</font>"
        data.append([
            Paragraph(e.get("timestamp", "")[:19].replace("T", " "), cell),
            Paragraph(e.get("severity", ""), cell),
            Paragraph(e.get("type", ""), cell),
            Paragraph((lambda w: w if w and w != "unknown" else e.get("source", ""))(
                (e.get("identity") or {}).get("who")), cell),
            Paragraph(f"{m.get('technique_id', '')}", cell),
            Paragraph((e.get("category") or "").upper(), cell),
            Paragraph(detail, cell),
        ])
    tbl = Table(data, colWidths=[24 * mm, 12 * mm, 31 * mm, 20 * mm, 13 * mm, 16 * mm, 52 * mm], repeatRows=1)
    style = [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
             ("FONTSIZE", (0, 0), (-1, 0), 8), ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#DBE0E8")),
             ("VALIGN", (0, 0), (-1, -1), "TOP"), ("ROWBACKGROUNDS", (0, 1), (-1, -1),
              [colors.white, colors.HexColor("#F6F8FB")])]
    for i, e in enumerate(query(events, limit=120), start=1):
        style.append(("TEXTCOLOR", (1, i), (1, i), SEV_COLOR.get(e.get("severity", "info"), NAVY)))
    tbl.setStyle(TableStyle(style))
    story.append(tbl)
    story += [Spacer(1, 10),
              Paragraph("MITRE ATT&CK for ICS technique IDs are rule-based mappings verified against "
                        "the live matrix (attack.mitre.org/matrices/ics). This report is generated "
                        "evidence from the Vigilo event bus.", sub)]

    doc.build(story)
    return buf.getvalue()
