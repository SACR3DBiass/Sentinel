"""
SENTINEL Monthly Security Report Generator
Produces a professional PDF summary of phishing threats and trends.
Enhanced with XAI feedback metrics and executive cost analysis.
"""

import os
import io
from datetime import datetime
from typing import Optional


def generate_monthly_report_pdf(
    report_data: dict,
    org_name: str = "Default Organization",
    cost_per_incident: float = 4500.00,
    output_path: Optional[str] = None,
) -> bytes:
    """
    Generate a Monthly Security Summary PDF.

    Args:
        report_data: Dict with keys: total, malicious, suspicious, safe,
                     top_targets, top_senders, period_start, period_end,
                     threats_blocked, estimated_cost_prevented, feedback_count,
                     false_positives, false_negatives, unique_targets
        org_name: Organization name for the header
        cost_per_incident: Configurable cost per phishing incident prevented
        output_path: If provided, also save to this file path

    Returns:
        PDF file as bytes
    """
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT

    # Colors
    RED = HexColor("#DC2626")
    DARK_RED = HexColor("#991B1B")
    GREEN = HexColor("#22C55E")
    YELLOW = HexColor("#EAB308")
    BLACK = HexColor("#111111")
    GRAY = HexColor("#666666")
    LIGHT_GRAY = HexColor("#F5F5F5")
    WHITE = HexColor("#FFFFFF")
    BLUE = HexColor("#3B82F6")

    # Build the PDF
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="ReportTitle", fontSize=24, fontName="Helvetica-Bold",
        textColor=RED, spaceAfter=6, alignment=TA_CENTER, leading=30,
    ))
    styles.add(ParagraphStyle(
        name="ReportSubtitle", fontSize=11, fontName="Helvetica",
        textColor=GRAY, spaceAfter=20, alignment=TA_CENTER, leading=15,
    ))
    styles.add(ParagraphStyle(
        name="SectionHeader", fontSize=14, fontName="Helvetica-Bold",
        textColor=BLACK, spaceBefore=24, spaceAfter=12, leading=18,
    ))
    styles.add(ParagraphStyle(
        name="BodyText2", fontSize=10, fontName="Helvetica",
        textColor=BLACK, spaceAfter=8, leading=14,
    ))
    styles.add(ParagraphStyle(
        name="BodyTextWrap", fontSize=10, fontName="Helvetica",
        textColor=BLACK, spaceAfter=8, leading=14, wordWrap="CJK",
    ))
    styles.add(ParagraphStyle(
        name="StatValue", fontSize=32, fontName="Helvetica-Bold",
        textColor=RED, alignment=TA_CENTER, leading=38, spaceAfter=2,
    ))
    styles.add(ParagraphStyle(
        name="StatLabel", fontSize=9, fontName="Helvetica",
        textColor=GRAY, alignment=TA_CENTER, leading=12, spaceAfter=4,
    ))
    styles.add(ParagraphStyle(
        name="SmallGray", fontSize=8, fontName="Helvetica",
        textColor=GRAY, spaceAfter=4, leading=11,
    ))

    story = []

    # --- Header ---
    story.append(Paragraph("SENTINEL", styles["ReportTitle"]))
    story.append(Paragraph("Monthly Security Intelligence Report", styles["ReportSubtitle"]))

    # Period
    period_start = report_data.get("period_start", "")
    period_end = report_data.get("period_end", "")
    if period_start:
        try:
            ps = datetime.fromisoformat(period_start.replace("Z", "+00:00")).strftime("%B %d, %Y")
            pe = datetime.fromisoformat(period_end.replace("Z", "+00:00")).strftime("%B %d, %Y")
        except Exception:
            ps, pe = period_start[:10], period_end[:10]
        story.append(Paragraph(f"Organization: {org_name}  |  Period: {ps} - {pe}", styles["SmallGray"]))

    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#1a1a1a"), spaceAfter=16))

    # --- Executive Summary Stats ---
    story.append(Paragraph("Executive Summary", styles["SectionHeader"]))

    total = report_data.get("total", 0)
    malicious = report_data.get("malicious", 0)
    suspicious = report_data.get("suspicious", 0)
    safe = report_data.get("safe", 0)
    threats_blocked = report_data.get("threats_blocked", malicious + suspicious)
    estimated_cost = report_data.get("estimated_cost_prevented", malicious * cost_per_incident)

    stat_data = [
        [
            Paragraph(str(total), styles["StatValue"]),
            Paragraph(str(threats_blocked), ParagraphStyle("mv", parent=styles["StatValue"], textColor=RED)),
            Paragraph(str(suspicious), ParagraphStyle("sv", parent=styles["StatValue"], textColor=YELLOW)),
            Paragraph(str(safe), ParagraphStyle("sv2", parent=styles["StatValue"], textColor=GREEN)),
        ],
        [
            Paragraph("Total Analyzed", styles["StatLabel"]),
            Paragraph("Threats Blocked", styles["StatLabel"]),
            Paragraph("Suspicious", styles["StatLabel"]),
            Paragraph("Safe", styles["StatLabel"]),
        ],
    ]
    stat_table = Table(stat_data, colWidths=[1.75 * inch] * 4, rowHeights=[48, 20])
    stat_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, 0), 10),
        ("BOTTOMPADDING", (0, 0), (-1, 0), 4),
        ("TOPPADDING", (0, 1), (-1, 1), 2),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 8),
        ("BACKGROUND", (0, 0), (-1, -1), LIGHT_GRAY),
        ("BOX", (0, 0), (-1, -1), 1, HexColor("#e0e0e0")),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 16))

    # --- Cost Analysis ---
    story.append(Paragraph("Cost Analysis", styles["SectionHeader"]))
    cost_data = [
        [Paragraph("<b>Metric</b>", styles["BodyTextWrap"]),
         Paragraph("<b>Value</b>", styles["BodyTextWrap"])],
        [Paragraph("Threats Blocked (Malicious + Suspicious)", styles["BodyTextWrap"]),
         Paragraph(str(threats_blocked), styles["BodyTextWrap"])],
        [Paragraph("Cost Per Incident (Industry Avg)", styles["BodyTextWrap"]),
         Paragraph(f"${cost_per_incident:,.2f}", styles["BodyTextWrap"])],
        [Paragraph("<b>Estimated Cost Prevented</b>", styles["BodyTextWrap"]),
         Paragraph(f"<b>${estimated_cost:,.2f}</b>", ParagraphStyle("cost", parent=styles["BodyTextWrap"], textColor=GREEN))],
    ]
    cost_table = Table(cost_data, colWidths=[4 * inch, 3 * inch])
    cost_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a1a1a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
        ("BACKGROUND", (0, 1), (-1, -1), LIGHT_GRAY),
        ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e0e0e0")),
        ("TOPPADDING", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ("LEFTPADDING", (0, 0), (-1, -1), 12),
        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    story.append(cost_table)
    story.append(Spacer(1, 16))

    # --- AI Feedback Accuracy ---
    feedback_count = report_data.get("feedback_count", 0)
    false_positives = report_data.get("false_positives", 0)
    false_negatives = report_data.get("false_negatives", 0)
    if feedback_count > 0:
        story.append(Paragraph("AI Feedback & Accuracy", styles["SectionHeader"]))
        accuracy = 100 - ((false_positives + false_negatives) / max(feedback_count, 1) * 100)
        fb_data = [
            [Paragraph("<b>Metric</b>", styles["BodyTextWrap"]),
             Paragraph("<b>Value</b>", styles["BodyTextWrap"])],
            [Paragraph("Total User Corrections", styles["BodyTextWrap"]),
             Paragraph(str(feedback_count), styles["BodyTextWrap"])],
            [Paragraph("False Positives (flagged safe incorrectly)", styles["BodyTextWrap"]),
             Paragraph(str(false_positives), ParagraphStyle("fp", parent=styles["BodyTextWrap"], textColor=YELLOW))],
            [Paragraph("False Negatives (missed threats)", styles["BodyTextWrap"]),
             Paragraph(str(false_negatives), ParagraphStyle("fn", parent=styles["BodyTextWrap"], textColor=RED))],
            [Paragraph("<b>AI Accuracy Rate</b>", styles["BodyTextWrap"]),
             Paragraph(f"<b>{accuracy:.1f}%</b>", ParagraphStyle("acc", parent=styles["BodyTextWrap"], textColor=GREEN))],
        ]
        fb_table = Table(fb_data, colWidths=[4 * inch, 3 * inch])
        fb_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a1a1a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("BACKGROUND", (0, 1), (-1, -1), LIGHT_GRAY),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e0e0e0")),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ("LEFTPADDING", (0, 0), (-1, -1), 12),
            ("RIGHTPADDING", (0, 0), (-1, -1), 12),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(fb_table)
        story.append(Spacer(1, 16))

    # --- Top Targeted Users ---
    top_targets = report_data.get("top_targets", [])
    if top_targets:
        story.append(Paragraph("Top Targeted Users", styles["SectionHeader"]))
        target_data = [[
            Paragraph("<b>Rank</b>", styles["BodyTextWrap"]),
            Paragraph("<b>User ID</b>", styles["BodyTextWrap"]),
            Paragraph("<b>Reports</b>", styles["BodyTextWrap"]),
        ]]
        for i, (uid, count) in enumerate(top_targets[:10], 1):
            target_data.append([
                Paragraph(str(i), styles["BodyTextWrap"]),
                Paragraph(str(uid)[:30], styles["BodyTextWrap"]),
                Paragraph(str(count), styles["BodyTextWrap"]),
            ])
        target_table = Table(target_data, colWidths=[0.8 * inch, 3.5 * inch, 1.5 * inch])
        target_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a1a1a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("BACKGROUND", (0, 1), (-1, -1), LIGHT_GRAY),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e0e0e0")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(target_table)
        story.append(Spacer(1, 16))

    # --- Top Malicious Sender Domains ---
    top_senders = report_data.get("top_senders", [])
    if top_senders:
        story.append(Paragraph("Top Malicious Sender Domains", styles["SectionHeader"]))
        sender_data = [[
            Paragraph("<b>Rank</b>", styles["BodyTextWrap"]),
            Paragraph("<b>Domain</b>", styles["BodyTextWrap"]),
            Paragraph("<b>Count</b>", styles["BodyTextWrap"]),
        ]]
        for i, (domain, count) in enumerate(top_senders[:10], 1):
            sender_data.append([
                Paragraph(str(i), styles["BodyTextWrap"]),
                Paragraph(str(domain), styles["BodyTextWrap"]),
                Paragraph(str(count), styles["BodyTextWrap"]),
            ])
        sender_table = Table(sender_data, colWidths=[0.8 * inch, 3.5 * inch, 1.5 * inch])
        sender_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HexColor("#1a1a1a")),
            ("TEXTCOLOR", (0, 0), (-1, 0), WHITE),
            ("BACKGROUND", (0, 1), (-1, -1), LIGHT_GRAY),
            ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#e0e0e0")),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        story.append(sender_table)
        story.append(Spacer(1, 24))

    # --- Recommendations ---
    story.append(Paragraph("Recommendations", styles["SectionHeader"]))
    recs = []
    if malicious > 0:
        recs.append(f"Investigate the {malicious} blocked threat(s) and verify no payloads were delivered before filtering.")
    if suspicious > 0:
        recs.append(f"Review the {suspicious} suspicious report(s) for potential false negatives.")
    if false_negatives > 0:
        recs.append(f"{false_negatives} false negative(s) detected — the AI missed threats that users corrected. Consider additional training data.")
    if false_positives > 0:
        recs.append(f"{false_positives} false positive(s) detected — the AI flagged legitimate emails. Add safe senders to whitelist.")
    if top_targets:
        top_user = top_targets[0][0]
        recs.append(f"User '{top_user}' is the most targeted — consider additional security awareness training.")
    if top_senders:
        top_domain = top_senders[0][0]
        recs.append(f"Consider blocking inbound mail from domain '{top_domain}' at the mail gateway.")
    if not recs:
        recs.append("No immediate action required. Continue monitoring.")

    for rec in recs:
        story.append(Paragraph(f"  \u2022  {rec}", styles["BodyTextWrap"]))

    story.append(Spacer(1, 32))
    story.append(HRFlowable(width="100%", thickness=0.5, color=HexColor("#cccccc"), spaceAfter=8))
    story.append(Paragraph(
        f"Generated by SENTINEL v4.0  |  {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  |  Confidential",
        styles["SmallGray"]
    ))

    # Build
    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(pdf_bytes)

    return pdf_bytes
