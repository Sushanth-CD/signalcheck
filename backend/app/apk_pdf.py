"""PDF report generation for APK static analysis results.

Produces a clean, compact one-page technical report containing:
- Header and metadata (package name, version, SHA-256 fingerprint, analysis timestamp).
- Primary indicator level and summary.
- Findings table with category, severity, evidence, and rationale.
- Grouped declared permissions.
- Cryptographic signature information.
- Permanent static limitations notice.
"""

from __future__ import annotations

import io
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def generate_apk_pdf_report(data: dict[str, Any]) -> bytes:
    """Render a structured one-page PDF document in-memory."""
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=0.5 * inch,
        leftMargin=0.5 * inch,
        topMargin=0.5 * inch,
        bottomMargin=0.5 * inch,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "DocTitle",
        parent=styles["Heading1"],
        fontSize=18,
        leading=22,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=4,
    )
    subtitle_style = ParagraphStyle(
        "DocSubtitle",
        parent=styles["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#64748b"),
        spaceAfter=10,
    )
    section_heading = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#0f766e"),
        spaceBefore=8,
        spaceAfter=4,
    )
    body_style = ParagraphStyle(
        "BodySmall",
        parent=styles["Normal"],
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#1e293b"),
    )
    bold_label = ParagraphStyle(
        "BoldLabel",
        parent=body_style,
        fontName="Helvetica-Bold",
    )
    limitations_style = ParagraphStyle(
        "Limitations",
        parent=styles["Normal"],
        fontSize=7,
        leading=9,
        textColor=colors.HexColor("#475569"),
    )

    app_info = data.get("app", {})
    package_name = app_info.get("package_name") or "Unknown"
    version_str = f"{app_info.get('version_name', 'N/A')} (code {app_info.get('version_code', 'N/A')})"
    sha256 = data.get("sha256", "N/A")
    file_size_mb = f"{(data.get('file_size', 0) / (1024 * 1024)):.2f} MB"
    
    indicator_summary = data.get("indicator_summary")
    if not indicator_summary:
        from app.apk_scoring import score_findings
        indicator_summary = score_findings(data.get("findings", []))

    summary_level = indicator_summary.get("level", "Low")
    total_points = indicator_summary.get("total_points", 0)
    scoring_ver = indicator_summary.get("scoring_version", "apk-rules-v1")
    level_display = f"{summary_level} ({total_points} pts, {scoring_ver})"
    
    findings = data.get("findings", [])
    perms = data.get("permissions", {})
    signing = data.get("signing", {})
    limitations = data.get("limitations", [])

    elements = []

    # Title & Header
    elements.append(Paragraph("SignalCheck — APK Static Analysis Technical Report", title_style))
    elements.append(Paragraph(f"Analysis Version: {data.get('analysis_version', 'apk-static-v1')} | Purely Static Inspection | Zero Code Execution", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#cbd5e1"), spaceAfter=8))

    # Metadata Grid
    meta_table_data = [
        [
            Paragraph("<b>Package Name:</b>", bold_label),
            Paragraph(package_name, body_style),
            Paragraph("<b>Indicator Level:</b>", bold_label),
            Paragraph(f"<b>{level_display}</b>", body_style),
        ],
        [
            Paragraph("<b>Version:</b>", bold_label),
            Paragraph(version_str, body_style),
            Paragraph("<b>SDK Target:</b>", bold_label),
            Paragraph(f"Min: {app_info.get('min_sdk', 'N/A')} | Target: {app_info.get('target_sdk', 'N/A')}", body_style),
        ],
        [
            Paragraph("<b>SHA-256:</b>", bold_label),
            Paragraph(f"<font size='6'>{sha256}</font>", body_style),
            Paragraph("<b>File Size:</b>", bold_label),
            Paragraph(file_size_mb, body_style),
        ],
    ]
    meta_table = Table(meta_table_data, colWidths=[1.1 * inch, 2.5 * inch, 1.1 * inch, 2.8 * inch])
    meta_table.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 2),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#f1f5f9")),
        ])
    )
    elements.append(meta_table)
    elements.append(Spacer(1, 4))
    elements.append(Paragraph(f"<font size='7' color='#64748b'><b>Note:</b> {indicator_summary.get('disclaimer', '')}</font>", body_style))
    elements.append(Spacer(1, 4))

    # Findings Section
    elements.append(Paragraph(f"Static Security Findings ({len(findings)})", section_heading))
    if not findings:
        elements.append(Paragraph("No high or medium severity heuristic indicators were flagged for this archive.", body_style))
    else:
        findings_table_data = [
            [
                Paragraph("<b>Sev</b>", bold_label),
                Paragraph("<b>Finding Title</b>", bold_label),
                Paragraph("<b>Evidence & Reason</b>", bold_label),
            ]
        ]
        for f in findings[:6]:  # Limit to 6 on one-page summary
            sev = f.get("severity", "info").upper()
            detail_text = f"{f.get('evidence', '')} — {f.get('why_it_matters', '')}"
            explanation = f.get("explanation")
            if isinstance(explanation, dict) and explanation.get("what_it_means"):
                detail_text += f"<br/><b>What this means:</b> {explanation['what_it_means']}"
            findings_table_data.append([
                Paragraph(f"<b>{sev}</b>", body_style),
                Paragraph(f.get("title", ""), body_style),
                Paragraph(detail_text, body_style),
            ])
        findings_table = Table(findings_table_data, colWidths=[0.8 * inch, 2.4 * inch, 4.3 * inch])
        findings_table.setStyle(
            TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
                ("PADDING", (0, 0), (-1, -1), 3),
                ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ])
        )
        elements.append(findings_table)

    # Permissions and Signing Snapshot
    elements.append(Paragraph("Permissions & Cryptographic Signing", section_heading))
    perm_groups = [f"{k.upper()}: {len(v)}" for k, v in perms.items() if k != "all_declared" and len(v) > 0]
    perm_summary = ", ".join(perm_groups) if perm_groups else "No sensitive permission groups flagged."
    
    signing_schemes = ", ".join(signing.get("signature_schemes", [])) or "None"
    signing_text = (
        f"Signed: {'Yes' if signing.get('is_signed') else 'No'} ({signing_schemes}) | "
        f"Debug Cert: {'Yes (Flagged)' if signing.get('is_debug_signed') else 'No'} | "
        f"Self-Signed: {'Yes' if signing.get('is_self_signed') else 'No'}"
    )

    perm_sign_data = [
        [Paragraph("<b>Declared Permission Groups:</b>", bold_label), Paragraph(perm_summary, body_style)],
        [Paragraph("<b>Signature Status:</b>", bold_label), Paragraph(signing_text, body_style)],
    ]
    perm_sign_table = Table(perm_sign_data, colWidths=[2.2 * inch, 5.3 * inch])
    perm_sign_table.setStyle(
        TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("PADDING", (0, 0), (-1, -1), 2),
            ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ])
    )
    elements.append(perm_sign_table)

    # Scientific Limitations Notice
    elements.append(Paragraph("Scientific Scope & Static Limitations", section_heading))
    lim_bullets = "<br/>".join([f"• {lim}" for lim in limitations])
    elements.append(Paragraph(lim_bullets, limitations_style))

    doc.build(elements)
    buf.seek(0)
    return buf.getvalue()
