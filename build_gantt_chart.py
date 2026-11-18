from docx import Document
from docx.shared import Cm, Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from pathlib import Path

out = Path('output/NIDS_Gantt_Chart.docx')
out.parent.mkdir(exist_ok=True)

def shade(cell, colour):
    item = OxmlElement('w:shd')
    item.set(qn('w:fill'), colour)
    cell._tc.get_or_add_tcPr().append(item)

def set_font(run, size=12, bold=False):
    run.font.name = 'Times New Roman'
    run._element.rPr.rFonts.set(qn('w:eastAsia'), 'Times New Roman')
    run.font.size = Pt(size)
    run.bold = bold

def format_cell(cell, centre=False, bold=False):
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER
    p = cell.paragraphs[0]
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER if centre else WD_ALIGN_PARAGRAPH.LEFT
    p.paragraph_format.space_before = Pt(2)
    p.paragraph_format.space_after = Pt(2)
    for r in p.runs: set_font(r, 11, bold)

doc = Document()
sec = doc.sections[0]
sec.left_margin = Cm(2); sec.right_margin = Cm(2); sec.top_margin = Cm(1.5); sec.bottom_margin = Cm(1.5)

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.paragraph_format.space_after = Pt(4)
set_font(p.add_run('TIME LINE / GANTT CHART'), 14, True)

p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.paragraph_format.space_after = Pt(10)
set_font(p.add_run('Network Intrusion Detection System'), 12, True)

table = doc.add_table(rows=7, cols=3)
table.style = 'Table Grid'
table.alignment = WD_TABLE_ALIGNMENT.CENTER
table.autofit = False
for c, w in zip(table.rows[0].cells, [Cm(9.5), Cm(3.5), Cm(3.5)]): c.width = w
headers = ('Project Activity', '7th Semester', '8th Semester')
for cell, text in zip(table.rows[0].cells, headers):
    cell.text = text; shade(cell, '808080'); format_cell(cell, True, True)
    for r in cell.paragraphs[0].runs: r.font.color.rgb = __import__('docx').shared.RGBColor(255, 255, 255)

rows = [
    ('Requirement analysis and system design', True, False),
    ('Packet capture and traffic logging', True, False),
    ('Rule-based intrusion detection engine', True, False),
    ('Flask dashboard, testing, and documentation', True, False),
    ('Dataset preparation and feature extraction', False, True),
    ('ML-based anomaly detection and prevention', False, True),
]
for tr, (activity, sem7, sem8) in zip(table.rows[1:], rows):
    tr.cells[0].text = activity
    tr.cells[1].text = ' '
    tr.cells[2].text = ' '
    format_cell(tr.cells[0])
    format_cell(tr.cells[1], True)
    format_cell(tr.cells[2], True)
    if sem7: shade(tr.cells[1], 'A9D18E')
    if sem8: shade(tr.cells[2], 'A9D18E')

p = doc.add_paragraph()
p.paragraph_format.space_before = Pt(8)
p.alignment = WD_ALIGN_PARAGRAPH.LEFT
set_font(p.add_run('Legend: '), 11, True)
set_font(p.add_run('Green cells indicate the planned period of work.'), 11)

doc.save(out)
print(out)
