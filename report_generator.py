"""
report_generator.py
--------------------
Turns the timeline (timeline_engine.generate_timeline) into two
investigation-ready deliverables:

  - an HTML report (jinja2 template, self-contained, no external assets)
  - a PDF report (reportlab Platypus, paginated tables, color-coded
    severity)

Both cover the same content: a case summary, the anomaly findings
(with severity), recovered deleted files, and the full chronological
timeline.
"""

import html
from datetime import datetime

from jinja2 import Template
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
)

SEVERITY_COLORS_HEX = {"HIGH": "#d62728", "MEDIUM": "#ff7f0e", "LOW": "#1f77b4"}
SEVERITY_COLORS_RL = {
    "HIGH": colors.HexColor("#d62728"),
    "MEDIUM": colors.HexColor("#ff7f0e"),
    "LOW": colors.HexColor("#1f77b4"),
}


def _summary_stats(events):
    unique_files = {e.path for e in events}
    deleted_files = {e.path for e in events if e.deleted}
    anomaly_paths = {e.path for e in events if e.severity}
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for path in anomaly_paths:
        sev = next(e.severity for e in events if e.path == path and e.severity)
        severity_counts[sev] += 1
    return {
        "total_events": len(events),
        "unique_files": len(unique_files),
        "deleted_files": len(deleted_files),
        "anomaly_files": len(anomaly_paths),
        "severity_counts": severity_counts,
    }


# =======================================================================
# HTML report
# =======================================================================

HTML_TEMPLATE = Template("""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Forensic Timeline Report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 40px; color: #1a1a1a; }
  h1 { border-bottom: 3px solid #1a1a1a; padding-bottom: 8px; }
  h2 { margin-top: 36px; border-bottom: 1px solid #ccc; padding-bottom: 4px; }
  .meta { color: #555; font-size: 0.9em; }
  .stats { display: flex; gap: 24px; margin: 20px 0; }
  .stat-box { border: 1px solid #ddd; border-radius: 8px; padding: 12px 20px; text-align: center; }
  .stat-box .num { font-size: 1.8em; font-weight: bold; }
  .stat-box .label { font-size: 0.85em; color: #666; }
  table { border-collapse: collapse; width: 100%; margin-top: 12px; font-size: 0.88em; }
  th, td { border: 1px solid #ddd; padding: 6px 10px; text-align: left; }
  th { background: #f2f2f2; }
  tr.deleted { background: #fdecea; }
  .sev-HIGH { color: #d62728; font-weight: bold; }
  .sev-MEDIUM { color: #ff7f0e; font-weight: bold; }
  .sev-LOW { color: #1f77b4; font-weight: bold; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 10px;
           color: white; font-size: 0.8em; font-weight: bold; }
</style>
</head>
<body>
  <h1>Forensic File System Timeline Report</h1>
  <p class="meta">Generated {{ generated_at }} &middot; Image: {{ image_path }}</p>

  <div class="stats">
    <div class="stat-box"><div class="num">{{ stats.total_events }}</div><div class="label">Timeline events</div></div>
    <div class="stat-box"><div class="num">{{ stats.unique_files }}</div><div class="label">Files</div></div>
    <div class="stat-box"><div class="num">{{ stats.deleted_files }}</div><div class="label">Deleted files recovered</div></div>
    <div class="stat-box"><div class="num">{{ stats.anomaly_files }}</div><div class="label">Files with anomalies</div></div>
  </div>

  <h2>Anomaly Findings</h2>
  {% if anomalies %}
  <table>
    <tr><th>Severity</th><th>File</th><th>Rule</th><th>Detail</th></tr>
    {% for a in anomalies %}
    <tr>
      <td><span class="badge" style="background:{{ sev_colors[a.severity.value] }}">{{ a.severity.value }}</span></td>
      <td>{{ a.path }}</td>
      <td>{{ a.rule }}</td>
      <td>{{ a.detail }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>No anomalies detected.</p>
  {% endif %}

  <h2>Recovered Deleted Files</h2>
  {% if deleted_files %}
  <table>
    <tr><th>Path</th><th>Size</th><th>Created</th><th>Modified</th><th>Content recovered</th></tr>
    {% for rf in deleted_files %}
    <tr>
      <td>{{ rf.path }}</td>
      <td>{{ rf.size }}</td>
      <td>{{ rf.created }}</td>
      <td>{{ rf.modified }}</td>
      <td>{{ "Yes" if rf.content_recovered else "No" }}</td>
    </tr>
    {% endfor %}
  </table>
  {% else %}
  <p>No deleted files recovered.</p>
  {% endif %}

  <h2>Full Timeline ({{ events|length }} events)</h2>
  <table>
    <tr><th>Timestamp</th><th>Event</th><th>Path</th><th>Size</th><th>Deleted</th><th>Severity</th></tr>
    {% for e in events %}
    <tr class="{{ 'deleted' if e.deleted else '' }}">
      <td>{{ e.timestamp }}</td>
      <td>{{ e.event_type }}</td>
      <td>{{ e.path }}</td>
      <td>{{ e.size }}</td>
      <td>{{ "Yes" if e.deleted else "" }}</td>
      <td class="{{ 'sev-' + e.severity if e.severity else '' }}">{{ e.severity or "" }}</td>
    </tr>
    {% endfor %}
  </table>
</body>
</html>
""")


def generate_html_report(events, anomalies, deleted_files, image_path, out_path):
    stats = _summary_stats(events)
    html_out = HTML_TEMPLATE.render(
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        image_path=html.escape(image_path),
        stats=stats,
        anomalies=anomalies,
        deleted_files=deleted_files,
        events=events,
        sev_colors=SEVERITY_COLORS_HEX,
    )
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html_out)
    return out_path


# =======================================================================
# PDF report
# =======================================================================

def generate_pdf_report(events, anomalies, deleted_files, image_path, out_path):
    stats = _summary_stats(events)
    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    heading_style = styles["Heading2"]
    normal_style = styles["Normal"]
    meta_style = ParagraphStyle("meta", parent=normal_style, textColor=colors.grey, fontSize=9)

    doc = SimpleDocTemplate(out_path, pagesize=letter,
                             topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    story = []

    story.append(Paragraph("Forensic File System Timeline Report", title_style))
    story.append(Paragraph(
        f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &middot; "
        f"Image: {html.escape(image_path)}", meta_style))
    story.append(Spacer(1, 14))

    summary_data = [
        ["Timeline events", "Files", "Deleted files recovered", "Files with anomalies"],
        [str(stats["total_events"]), str(stats["unique_files"]),
         str(stats["deleted_files"]), str(stats["anomaly_files"])],
    ]
    summary_table = Table(summary_data, hAlign="LEFT")
    summary_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f2f2")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 20))

    # Anomaly findings
    story.append(Paragraph("Anomaly Findings", heading_style))
    if anomalies:
        rows = [["Severity", "File", "Rule", "Detail"]]
        for a in anomalies:
            rows.append([a.severity.value, a.path, a.rule,
                         Paragraph(a.detail, normal_style)])
        t = Table(rows, colWidths=[0.7 * inch, 1.3 * inch, 1.6 * inch, 2.6 * inch], hAlign="LEFT")
        style_cmds = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f2f2")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]
        for i, a in enumerate(anomalies, start=1):
            style_cmds.append(("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLORS_RL[a.severity.value]))
            style_cmds.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
        t.setStyle(TableStyle(style_cmds))
        story.append(t)
    else:
        story.append(Paragraph("No anomalies detected.", normal_style))
    story.append(Spacer(1, 16))

    # Recovered deleted files
    story.append(Paragraph("Recovered Deleted Files", heading_style))
    if deleted_files:
        rows = [["Path", "Size", "Created", "Modified", "Content"]]
        for rf in deleted_files:
            rows.append([rf.path, str(rf.size), str(rf.created), str(rf.modified),
                         "Recovered" if rf.content_recovered else "Lost"])
        t = Table(rows, colWidths=[1.6 * inch, 0.6 * inch, 1.5 * inch, 1.5 * inch, 1.0 * inch], hAlign="LEFT")
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f2f2")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(t)
    else:
        story.append(Paragraph("No deleted files recovered.", normal_style))

    story.append(PageBreak())

    # Full timeline
    story.append(Paragraph(f"Full Timeline ({len(events)} events)", heading_style))
    rows = [["Timestamp", "Event", "Path", "Size", "Del.", "Sev."]]
    for e in events:
        rows.append([str(e.timestamp), e.event_type, e.path, str(e.size),
                     "Y" if e.deleted else "", e.severity or ""])
    t = Table(rows, colWidths=[1.3 * inch, 0.7 * inch, 1.8 * inch, 0.6 * inch, 0.4 * inch, 0.6 * inch],
               hAlign="LEFT", repeatRows=1)
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#f2f2f2")),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]
    for i, e in enumerate(events, start=1):
        if e.deleted:
            style_cmds.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#fdecea")))
        if e.severity:
            style_cmds.append(("TEXTCOLOR", (5, i), (5, i), SEVERITY_COLORS_RL[e.severity]))
            style_cmds.append(("FONTNAME", (5, i), (5, i), "Helvetica-Bold"))
    t.setStyle(TableStyle(style_cmds))
    story.append(t)

    doc.build(story)
    return out_path


def main():
    import sys
    from fat16_parser import Fat16Parser
    from deleted_file_recovery import DeletedFileRecovery
    from anomaly_detector import AnomalyDetector
    from timeline_engine import generate_timeline

    image_path = sys.argv[1] if len(sys.argv) > 1 else "test_disk.dd"
    acquisition_time = datetime(2026, 8, 25, 12, 0, 0)

    parser = Fat16Parser(image_path)
    live_records = [r for r in parser.walk() if not r.name.startswith("$")]

    anomalies = AnomalyDetector(acquisition_time=acquisition_time).scan(live_records)
    deleted_records = DeletedFileRecovery(image_path).scan()
    events = generate_timeline(live_records, deleted_records, anomalies)

    generate_html_report(events, anomalies, deleted_records, image_path, "report.html")
    generate_pdf_report(events, anomalies, deleted_records, image_path, "report.pdf")
    print("Wrote report.html and report.pdf")


if __name__ == "__main__":
    main()
