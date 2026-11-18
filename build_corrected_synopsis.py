from docx import Document
from docx.shared import Cm, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from pathlib import Path

OUT = Path('output/Network_Intrusion_Detection_System_Synopsis.docx')
OUT.parent.mkdir(exist_ok=True)

def font(run, size=12, bold=False, italic=False):
    run.font.name = 'Times New Roman'
    run._element.rPr.rFonts.set(qn('w:eastAsia'), 'Times New Roman')
    run.font.size = Pt(size)
    run.bold, run.italic = bold, italic

def shade(cell, fill):
    el = OxmlElement('w:shd'); el.set(qn('w:fill'), fill)
    cell._tc.get_or_add_tcPr().append(el)

def cell_format(cell, bold=False, center=False):
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
    for p in cell.paragraphs:
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER if center else WD_ALIGN_PARAGRAPH.LEFT
        p.paragraph_format.space_after = Pt(0); p.paragraph_format.line_spacing = 1.0
        for r in p.runs: font(r, 11, bold)

def heading(doc, text):
    p = doc.add_paragraph(); p.paragraph_format.space_before = Pt(7); p.paragraph_format.space_after = Pt(3)
    font(p.add_run(text), 12, True)
    return p

def body(doc, text, first=False):
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.paragraph_format.line_spacing = 1.5; p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.first_line_indent = Cm(0 if first else 0.6)
    font(p.add_run(text))
    return p

doc = Document()
s = doc.sections[0]
s.page_width, s.page_height = Cm(21), Cm(29.7)
s.left_margin, s.right_margin, s.top_margin, s.bottom_margin = Cm(2), Cm(1), Cm(1), Cm(1)
doc.styles['Normal'].font.name = 'Times New Roman'; doc.styles['Normal'].font.size = Pt(12)

p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER; p.paragraph_format.space_after = Pt(8)
r = p.add_run('PRELIMINARY REPORT (SEMINAR / PROJECT / DISSERTATION)'); font(r, 14, True); r.underline = True

info = [
    ('Submitted By', 'Amaresh Sahoo', 'Roll No.', '23BTICS02'),
    ('Discipline', 'Cyber Security', 'Semester', '7th'),
    ('Academic Session', '2023 - 2027', '', ''),
    ('Guide Full Name', 'Ms. Swetangi Somyadarshi Pati', 'Designation', 'Assistant Professor'),
    ('Guide Address', 'sspati@suiit.ac.in, 7978494612', '', ''),
]
t = doc.add_table(rows=len(info), cols=4); t.alignment = WD_TABLE_ALIGNMENT.CENTER; t.autofit = False
for row, values in zip(t.rows, info):
    for i, (cell, value) in enumerate(zip(row.cells, values)):
        cell.text = value; cell_format(cell, bold=i in (0, 2))

p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER; p.paragraph_format.space_before = Pt(5); p.paragraph_format.space_after = Pt(5)
font(p.add_run('NETWORK INTRUSION DETECTION SYSTEM'), 12, True)
heading(doc, 'ABSTRACT / SHORT DESCRIPTION OF PROJECT:')
paras = [
    'This project presents a rule-based Network Intrusion Detection System (NIDS) developed to monitor network traffic, identify suspicious activities, and provide timely security alerts. The system captures live packets using Scapy and extracts traffic attributes such as source and destination IP addresses, ports, protocols, packet size, and timestamps. These records are stored in an SQLite database for analysis, alert tracking, and reporting.',
    'The detection engine applies predefined rules to identify port scans, ICMP flooding, repeated connection attempts, blacklisted IP addresses, and malicious payload signatures. Payload inspection identifies patterns associated with SQL injection, cross-site scripting, directory traversal, and the EICAR test string. Each detected event is assigned a Low, Medium, High, or Critical severity level. An alert cooldown mechanism reduces repeated alerts during sustained attacks, while high-severity events can trigger console or email notifications.',
    'A Flask-based dashboard provides authenticated access to live traffic, alert history, filtering, statistical summaries, and CSV/PDF report export. Packet capture and the dashboard run as separate processes while sharing the same database. The project provides a foundation for network monitoring; planned future work includes machine-learning-based anomaly detection, automated prevention, and advanced threat analysis.'
]
for i, item in enumerate(paras): body(doc, item, i == 0)
p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY; p.paragraph_format.space_after = Pt(6)
font(p.add_run('Keywords: '), 12, True, True)
font(p.add_run('Network Intrusion Detection System, NIDS, Packet Sniffing, Scapy, Flask, SQLite, Rule-Based Detection, Network Security, Cybersecurity, Threat Detection'))

heading(doc, 'REFERENCE(S):')
refs = [
    '[1] S. Axelsson, “The Base-Rate Fallacy and the Difficulty of Intrusion Detection,” ACM Transactions on Information and System Security, vol. 3, no. 3, pp. 186–205, 2000.',
    '[2] C. Kruegel, D. Mutz, W. Robertson, and G. Vigna, “Bayesian Event Classification for Intrusion Detection,” in Proceedings of the 19th Annual Computer Security Applications Conference, 2003, pp. 14–23.'
]
for text in refs:
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY; p.paragraph_format.line_spacing = 1.5; p.paragraph_format.space_after = Pt(3); p.paragraph_format.left_indent = Cm(.6); p.paragraph_format.first_line_indent = Cm(-.6); font(p.add_run(text))

heading(doc, 'TIME LINE / GANTT CHART:')
p = doc.add_paragraph(); p.paragraph_format.space_after = Pt(4); font(p.add_run('Will you extend the same project to next semester? Yes'))
g = doc.add_table(rows=7, cols=3); g.alignment = WD_TABLE_ALIGNMENT.CENTER; g.style = 'Table Grid'; g.autofit = False
headers = ('Activity', '7th Semester', '8th Semester')
for c, v in zip(g.rows[0].cells, headers): c.text = v; shade(c, 'BFBFBF'); cell_format(c, True, True)
plan = [
    ('Requirement analysis and system design', '✓', ''),
    ('Packet capture, database, and rule-based detection', '✓', ''),
    ('Dashboard development and testing', '✓', ''),
    ('Dataset preparation and feature extraction', '', '✓'),
    ('ML-based anomaly detection', '', '✓'),
    ('Prevention module and final evaluation', '', '✓'),
]
for row, values in zip(g.rows[1:], plan):
    for i, (c, v) in enumerate(zip(row.cells, values)):
        c.text = v; cell_format(c, center=i > 0)

doc.save(OUT)
print(OUT)
