import os
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

class SecurityReportGenerator:
    @staticmethod
    def generate(scan_data: dict, output_path: str):
        doc = SimpleDocTemplate(output_path, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        elements = []

        title_style = ParagraphStyle('ReportTitle', parent=styles['Heading1'], fontSize=18, leading=22, textColor=colors.HexColor("#1e293b"))
        h2_style = ParagraphStyle('ReportH2', parent=styles['Heading2'], fontSize=13, leading=16, textColor=colors.HexColor("#0f172a"))
        body_style = styles['BodyText']

        elements.append(Paragraph("VulnGuard - Security Assessment Report", title_style))
        elements.append(Paragraph(f"Target: {scan_data['target_name']} ({scan_data['target_url']})", body_style))
        elements.append(Paragraph(f"Execution Date: {scan_data['date']} | Score: {scan_data['score']}/100", body_style))
        elements.append(Spacer(1, 15))

        elements.append(Paragraph("Executive Summary", h2_style))
        summary_text = (
            f"This automated assessment evaluated {scan_data['target_url']} within an authorized laboratory scope. "
            f"A total of {len(scan_data['findings'])} findings were identified across headers, cookies, "
            f"ports, and baseline configurations."
        )
        elements.append(Paragraph(summary_text, body_style))
        elements.append(Spacer(1, 15))

        elements.append(Paragraph("Vulnerability Register", h2_style))
        table_data = [["ID", "Severity", "Finding Title", "Category"]]
        for f in scan_data["findings"]:
            table_data.append([
                f.get("finding_id", "N/A"),
                f.get("severity", "Info"),
                Paragraph(f.get("title", ""), body_style),
                f.get("category", "General")
            ])

        t = Table(table_data, colWidths=[80, 60, 240, 140])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#f1f5f9")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor("#0f172a")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 20))

        elements.append(Paragraph("Remediation Details", h2_style))
        for f in scan_data["findings"]:
            elements.append(Paragraph(f"<b>{f.get('title')}</b> [{f.get('severity')}]", styles['Heading3']))
            elements.append(Paragraph(f"<b>Evidence:</b> {f.get('evidence')}", body_style))
            elements.append(Paragraph(f"<b>Impact:</b> {f.get('impact')}", body_style))
            elements.append(Paragraph(f"<b>Remediation:</b> {f.get('recommendation')}", body_style))
            elements.append(Spacer(1, 10))

        doc.build(elements)
