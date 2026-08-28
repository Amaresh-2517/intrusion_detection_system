"""
Generates a PDF alert report using reportlab. Kept separate from
routes.py so the Flask route stays thin and this can be unit-tested
(or reused from a CLI script) independently of the web layer.
"""

import io
from datetime import datetime

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
)

_SEVERITY_COLORS = {
    "Critical": colors.HexColor("#f87171"),
    "High": colors.HexColor("#fb923c"),
    "Medium": colors.HexColor("#d97706"),
    "Low": colors.HexColor("#6b7280"),
}


def build_alert_report_pdf(alert_rows, filters=None):
    """
    alert_rows: list of dicts (as returned by get_recent_alerts)
    filters: optional dict of the filters that were applied, shown in
             the report header so the reader knows what they're looking at
    Returns: BytesIO buffer positioned at 0, ready for send_file()
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        topMargin=0.6 * inch, bottomMargin=0.6 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], fontSize=18, spaceAfter=4,
    )
    meta_style = ParagraphStyle(
        "Meta", parent=styles["Normal"], fontSize=9, textColor=colors.grey,
    )

    story = []
    story.append(Paragraph("NIDS Alert Report", title_style))
    story.append(Paragraph(
        f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &middot; "
        f"{len(alert_rows)} alert(s)", meta_style
    ))

    if filters and any(filters.values()):
        active = ", ".join(f"{k}={v}" for k, v in filters.items() if v)
        story.append(Paragraph(f"Filters applied: {active}", meta_style))

    story.append(Spacer(1, 16))

    if not alert_rows:
        story.append(Paragraph("No alerts match the selected filters.", styles["Normal"]))
    else:
        header = ["Time", "Severity", "Type", "Source IP", "Description"]
        data = [header]
        for r in alert_rows:
            data.append([
                r["timestamp"],
                r["severity"],
                r["alert_type"],
                r["source_ip"] or "",
                Paragraph(r["description"] or "", styles["Normal"]),
            ])

        table = Table(data, colWidths=[1.3*inch, 0.65*inch, 1.1*inch, 0.95*inch, 2.5*inch], repeatRows=1)
        style_commands = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#12161c")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f9fafb")]),
            ("TOPPADDING", (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ]
        # Color the severity cell text per row based on its value
        for i, r in enumerate(alert_rows, start=1):
            sev_color = _SEVERITY_COLORS.get(r["severity"], colors.black)
            style_commands.append(("TEXTCOLOR", (1, i), (1, i), sev_color))
            style_commands.append(("FONTNAME", (1, i), (1, i), "Helvetica-Bold"))

        table.setStyle(TableStyle(style_commands))
        story.append(table)

    doc.build(story)
    buf.seek(0)
    return buf
