from datetime import date
from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_CELL_VERTICAL_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

OUT = "deliverables/NIDS_Software_Requirements_Specification.docx"

NAVY = "17365D"
BLUE = "D9EAF7"
PALE = "F5F8FB"
GRAY = "D9D9D9"


def shade(cell, fill):
    props = cell._tc.get_or_add_tcPr()
    item = OxmlElement("w:shd")
    item.set(qn("w:fill"), fill)
    props.append(item)


def borders(table):
    tbl_pr = table._tbl.tblPr
    b = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        e = OxmlElement(f"w:{edge}")
        e.set(qn("w:val"), "single")
        e.set(qn("w:sz"), "6")
        e.set(qn("w:color"), GRAY)
        b.append(e)
    tbl_pr.append(b)


def set_cell(cell, text, header=False):
    cell.text = ""
    p = cell.paragraphs[0]
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.space_before = Pt(2)
    r = p.add_run(str(text))
    r.font.name = "Aptos"
    r.font.size = Pt(9)
    r.bold = header
    if header:
        r.font.color.rgb = RGBColor(255, 255, 255)
        shade(cell, NAVY)
    cell.vertical_alignment = WD_CELL_VERTICAL_ALIGNMENT.CENTER


def table(doc, headers, rows, widths=None):
    t = doc.add_table(rows=1, cols=len(headers))
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.style = "Table Grid"
    borders(t)
    for i, h in enumerate(headers):
        set_cell(t.rows[0].cells[i], h, True)
    for row_i, row in enumerate(rows):
        cells = t.add_row().cells
        for i, value in enumerate(row):
            set_cell(cells[i], value)
            if row_i % 2 == 1:
                shade(cells[i], PALE)
    if widths:
        for row in t.rows:
            for i, width in enumerate(widths):
                row.cells[i].width = Inches(width)
    doc.add_paragraph()
    return t


def heading(doc, text, level=1):
    p = doc.add_heading(text, level=level)
    for r in p.runs:
        r.font.color.rgb = RGBColor(0, 0, 0)
        r.font.name = "Aptos Display" if level == 1 else "Aptos"
    return p


def bullet(doc, text, level=0):
    p = doc.add_paragraph(style="List Bullet" if level == 0 else "List Bullet 2")
    p.add_run(text)
    return p


def add_page_number(section):
    footer = section.footer.paragraphs[0]
    footer.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = footer.add_run("Page ")
    fld = OxmlElement("w:fldSimple")
    fld.set(qn("w:instr"), "PAGE")
    footer._p.append(fld)


def main():
    doc = Document()
    sec = doc.sections[0]
    sec.top_margin = Inches(0.8)
    sec.bottom_margin = Inches(0.7)
    sec.left_margin = Inches(0.8)
    sec.right_margin = Inches(0.8)
    add_page_number(sec)

    styles = doc.styles
    styles["Normal"].font.name = "Aptos"
    styles["Normal"].font.size = Pt(10.5)
    styles["Normal"].paragraph_format.space_after = Pt(6)
    styles["Normal"].paragraph_format.line_spacing = 1.12

    title = doc.add_paragraph(style="Title")
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    title.add_run("Software Requirements Specification")
    subtitle = doc.add_paragraph()
    subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = subtitle.add_run("Network Intrusion Detection System")
    r.bold = True; r.font.size = Pt(18); r.font.color.rgb = RGBColor(0, 0, 0)
    doc.add_paragraph()
    p = doc.add_paragraph(); p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.add_run("Minor Project Documentation\n").bold = True
    p.add_run("Version 1.0\n4 November 2026")
    doc.add_paragraph()
    table(doc, ["Document information", "Value"], [
        ("System", "Network Intrusion Detection System NIDS"),
        ("Document type", "Software Requirements Specification"),
        ("Version", "1.0"),
        ("Prepared for", "Academic minor project submission"),
        ("Status", "Baseline requirements for the current rule based implementation"),
    ], [2.0, 4.5])
    doc.add_page_break()

    heading(doc, "1 Introduction")
    heading(doc, "1.1 Purpose", 2)
    doc.add_paragraph("This document specifies the requirements for a Network Intrusion Detection System that captures network packets, records traffic metadata, evaluates rule based indicators of suspicious activity, and presents results through a protected web dashboard. It defines the agreed scope of the current minor project implementation and provides a basis for development, testing, demonstration, and later extension.")
    heading(doc, "1.2 Scope", 2)
    doc.add_paragraph("The system is a host based monitoring application. A Scapy capture process reads live IPv4 traffic from a selected interface. It stores packet metadata in SQLite, evaluates behavioral and signature rules, records deduplicated alerts, and exposes traffic, alert, statistics, and export views through a Flask dashboard. The system is designed for a controlled academic or local monitoring environment.")
    bullet(doc, "In scope: packet capture, metadata logging, rule based detection, alerting, dashboard authentication, filtering, statistics, CSV export, and PDF export.")
    bullet(doc, "Out of scope: automatic blocking, enterprise identity management, distributed capture, guaranteed detection of encrypted payload attacks, and machine learning classification.")
    heading(doc, "1.3 Definitions", 2)
    table(doc, ["Term", "Meaning"], [
        ("NIDS", "Network Intrusion Detection System."),
        ("Alert", "A recorded event indicating that a configured detection rule matched."),
        ("Traffic log", "Stored metadata for an observed packet, excluding raw payload content."),
        ("Payload signature", "A known byte pattern searched in a packet payload while the packet is processed."),
        ("Cooldown", "A period during which duplicate alerts of the same type and source are suppressed."),
        ("BPF", "Berkeley Packet Filter syntax used to limit captured traffic when configured."),
    ], [1.7, 4.8])
    heading(doc, "1.4 Intended users", 2)
    doc.add_paragraph("The primary user is a student demonstrator or local security operator who starts the capture process, signs in to the dashboard, observes traffic and alerts, and exports evidence for review. A project evaluator may inspect the dashboard and supporting reports during a demonstration.")

    heading(doc, "2 Overall Description")
    heading(doc, "2.1 Product perspective", 2)
    doc.add_paragraph("The application has two independent processes that share an SQLite database. Separating capture from the dashboard keeps privileged packet access outside the web process and allows the dashboard to remain read focused.")
    table(doc, ["Component", "Responsibility", "Primary interfaces"], [
        ("Packet sniffer", "Captures packets and extracts IPv4 metadata and raw payload bytes.", "Scapy, configured network interface"),
        ("Detection engine", "Runs configured rules and reports matched conditions.", "Packet fields, rule functions"),
        ("Database", "Stores traffic metadata and alerts.", "SQLite with WAL mode"),
        ("Notifier", "Displays high severity alerts and optionally sends email.", "Console, SMTP"),
        ("Dashboard", "Shows data, statistics, exports, authentication, and health status.", "Flask routes, browser"),
    ], [1.25, 2.8, 2.45])
    heading(doc, "2.2 Operating environment", 2)
    table(doc, ["Area", "Requirement"], [
        ("Operating system", "macOS, Linux, or Windows with Python support. Live capture requires platform specific capture permissions."),
        ("Runtime", "Python 3 with the dependencies listed in requirements.txt."),
        ("Network capture", "Scapy. The capture process normally requires administrator privileges; on macOS it must access /dev/bpf devices."),
        ("Database", "SQLite local database stored under the project data directory."),
        ("Web access", "A modern browser connecting to the locally configured Flask host and port."),
    ], [1.55, 4.95])
    heading(doc, "2.3 Constraints", 2)
    bullet(doc, "The capture process needs elevated privileges, while the dashboard must run without them.")
    bullet(doc, "SQLite is suitable for the current single host demonstration but is not a high throughput event store.")
    bullet(doc, "Encrypted traffic cannot be inspected by the payload signature rule unless plaintext is available at capture time.")
    bullet(doc, "Rules use fixed, configurable thresholds and may require tuning for the monitored network.")

    heading(doc, "3 Functional Requirements")
    table(doc, ["ID", "Requirement", "Priority"], [
        ("FR 01", "The system shall capture live packets from the configured interface and may apply a configured BPF filter.", "Must"),
        ("FR 02", "The system shall ignore packets that do not contain an IPv4 layer.", "Must"),
        ("FR 03", "The system shall record timestamp, source and destination IP address, protocol, ports when available, and packet size for each captured IPv4 packet.", "Must"),
        ("FR 04", "The system shall not persist raw packet payloads in the traffic log.", "Must"),
        ("FR 05", "The system shall evaluate each captured packet against blacklist, port scan, ICMP flood, repeated connection, and payload signature rules.", "Must"),
        ("FR 06", "The system shall skip all detection rules for traffic from configured whitelisted source IP addresses.", "Must"),
        ("FR 07", "The system shall record alert type, source IP, description, timestamp, and severity for each accepted alert.", "Must"),
        ("FR 08", "The system shall suppress a duplicate alert with the same alert type and source IP during the configured cooldown period.", "Must"),
        ("FR 09", "The system shall display a console notification for alerts meeting the configured severity threshold.", "Must"),
        ("FR 10", "The system shall send email alerts only when email notification is explicitly enabled and complete SMTP settings are provided.", "Should"),
        ("FR 11", "The dashboard shall require a user to authenticate before viewing traffic, alerts, statistics, APIs, or exports.", "Must"),
        ("FR 12", "The dashboard shall show recent traffic and support protocol and source IP filtering.", "Must"),
        ("FR 13", "The dashboard shall show recent alerts and support severity, alert type, and source IP filtering.", "Must"),
        ("FR 14", "The dashboard shall provide aggregate statistics for packets, alerts, source IPs, protocols, alert types, and severity levels.", "Must"),
        ("FR 15", "The dashboard shall export the currently filtered alert set as CSV and PDF files.", "Should"),
        ("FR 16", "The dashboard shall report whether capture activity is active, waiting for packets, or stale based on recent traffic records.", "Should"),
    ], [0.65, 5.1, 0.65])

    doc.add_page_break()
    heading(doc, "4 Detection Requirements")
    doc.add_paragraph("The following rules are evaluated independently. Their thresholds and severities are configured centrally so they can be tuned without modifying the rule functions.")
    table(doc, ["Rule", "Condition", "Default response"], [
        ("Blacklisted IP", "A source or destination IP matches the configured blacklist.", "Critical alert"),
        ("Port scan", "One source contacts at least 15 distinct destination ports in 10 seconds.", "Medium alert"),
        ("ICMP flood", "One source sends at least 50 ICMP packets in 10 seconds.", "Medium alert"),
        ("Repeated connections", "One source makes at least 20 attempts to the same destination IP and port in 15 seconds.", "Low alert"),
        ("Payload signature", "Packet raw payload contains a configured case insensitive signature such as SQL injection, XSS, traversal, command injection, or EICAR test content.", "Configured severity"),
    ], [1.45, 3.85, 1.1])
    heading(doc, "4.1 Rule behavior", 2)
    bullet(doc, "Behavioral rules query recent traffic records using a rolling time window.")
    bullet(doc, "Payload inspection occurs in memory. The matching payload itself is not written to the database.")
    bullet(doc, "A rule match may be reported to the engine even if the alert insert is suppressed by the cooldown. The persisted alert count remains the source of record for the dashboard.")

    heading(doc, "5 External Interface Requirements")
    heading(doc, "5.1 User interface", 2)
    table(doc, ["View", "Required behavior"], [
        ("Login", "Accept username, password, and a session CSRF token. Reject invalid credentials and throttle repeated failed attempts."),
        ("Live traffic", "Poll the traffic API and render timestamp, protocol, endpoints, ports, and packet size."),
        ("Alert history", "Poll the alert API, render severity and description, apply filters, and maintain filter aware export links."),
        ("Statistics", "Display total counts and horizontal bars for aggregate data."),
        ("Navigation", "Show a capture health indicator and allow a protected sign out action."),
    ], [1.3, 5.1])
    heading(doc, "5.2 Software interfaces", 2)
    table(doc, ["Interface", "Use"], [
        ("Scapy", "Packet capture and protocol layer inspection."),
        ("SQLite", "Persistent traffic and alert storage with WAL mode for concurrent reads and writes."),
        ("Flask", "Dashboard pages, JSON APIs, session handling, and file downloads."),
        ("ReportLab", "Generation of PDF alert reports."),
        ("SMTP", "Optional email delivery for qualifying alerts."),
    ], [1.25, 5.15])
    heading(doc, "5.3 Database requirements", 2)
    table(doc, ["Table", "Required fields", "Purpose"], [
        ("TrafficLog", "id, timestamp, src_ip, dst_ip, protocol, src_port, dst_port, packet_size", "Packet metadata used for dashboard views and rolling detection windows."),
        ("Alerts", "id, timestamp, alert_type, source_ip, description, severity", "Recorded detection events for review, statistics, and export."),
    ], [1.1, 3.25, 2.05])

    heading(doc, "6 Nonfunctional Requirements")
    table(doc, ["ID", "Requirement"], [
        ("NFR 01", "The capture loop shall remain available when an individual detection rule raises an exception; it shall log the rule failure and continue processing later packets."),
        ("NFR 02", "The database layer shall use parameterized SQL statements for values supplied to queries."),
        ("NFR 03", "The dashboard shall bind to localhost by default and shall run with Flask debug mode disabled by default."),
        ("NFR 04", "Dashboard credentials and the Flask session secret shall be supplied through environment variables rather than committed source code."),
        ("NFR 05", "Dashboard sessions shall use HttpOnly and SameSite cookie settings. Secure cookies shall be enabled when the application is served over HTTPS."),
        ("NFR 06", "The application shall reject external post login redirect targets and shall protect login and logout state changes with CSRF tokens."),
        ("NFR 07", "The system shall store no raw packet payloads in SQLite to reduce storage of sensitive application content."),
        ("NFR 08", "For a local demonstration workload, the dashboard shall refresh traffic and alert data at the configured interval without requiring a page reload."),
        ("NFR 09", "The system shall maintain unit tests for detection thresholds, cooldown behavior, whitelisting, dashboard redirect safety, and logout protection."),
        ("NFR 10", "The database connection shall use WAL mode and a busy timeout to reduce reader writer contention in the two process design."),
    ], [0.7, 5.85])

    heading(doc, "7 Security and Privacy Requirements")
    doc.add_paragraph("This system is intended for authorized monitoring only. The operator must obtain permission before monitoring a network or collecting network metadata. The current implementation is a teaching project and is not a substitute for a production security operations platform.")
    table(doc, ["Area", "Requirement"], [
        ("Credentials", "Use a username, a Werkzeug compatible password hash, and a high entropy Flask secret supplied as environment variables."),
        ("Authorization", "Require an authenticated session for all dashboard pages, APIs, exports, health information, and logout."),
        ("Request safety", "Use CSRF tokens for login and logout forms. Limit login failures per process and source address."),
        ("Data minimization", "Persist packet metadata only. Do not store raw payloads or credentials observed in network traffic."),
        ("Network exposure", "Use loopback binding by default. If exposed through a reverse proxy, use HTTPS and enable secure cookies."),
        ("Auditability", "Keep alert timestamps, severity, and descriptions so operators can review why a detection was reported."),
    ], [1.55, 4.95])

    heading(doc, "8 Acceptance Criteria")
    table(doc, ["ID", "Acceptance test", "Expected result"], [
        ("AC 01", "Start the sniffer with the permissions required by the operating system and generate ordinary IPv4 traffic.", "Traffic records appear in the database and live dashboard."),
        ("AC 02", "Send traffic to at least 15 distinct ports from one source within 10 seconds.", "A Port Scan alert is recorded at Medium severity, subject to cooldown."),
        ("AC 03", "Send at least 50 ICMP packets from one source in 10 seconds.", "An ICMP Flood alert is recorded at Medium severity, subject to cooldown."),
        ("AC 04", "Configure a blacklist address and observe traffic involving that address.", "A Critical Blacklisted IP alert is recorded."),
        ("AC 05", "Process a test payload containing a configured signature.", "A Signature Match alert is recorded and the payload is absent from TrafficLog."),
        ("AC 06", "Add a source IP to the whitelist and generate matching suspicious traffic.", "No rule based alert is recorded for that source."),
        ("AC 07", "Attempt dashboard access before login.", "The user is redirected to the login page."),
        ("AC 08", "Log in with an external next URL parameter.", "The user is redirected only to the local dashboard landing page."),
        ("AC 09", "Attempt logout using GET or a POST without a CSRF token.", "GET is rejected and the invalid POST is rejected."),
        ("AC 10", "Filter Alert History and export CSV and PDF.", "Each export contains the same filtered alert set shown to the user."),
    ], [0.65, 3.65, 2.2])

    doc.add_page_break()
    heading(doc, "9 Future Enhancements")
    doc.add_paragraph("The following items are planned extensions and are not requirements for the current minor project baseline.")
    bullet(doc, "In memory sliding windows or stream processing to reduce per packet database queries at higher capture rates.")
    bullet(doc, "Flow level feature extraction and an offline trained anomaly detection model using an appropriate labeled intrusion dataset.")
    bullet(doc, "IPv6 support, TCP flag analysis, fragmented packet handling, and more comprehensive signature rules.")
    bullet(doc, "Database retention, pagination, backups, structured application logs, and health metrics for production scale monitoring.")
    bullet(doc, "A separately controlled prevention module that can block an IP only after explicit policy approval and with a safe default of disabled.")

    heading(doc, "10 Traceability Summary")
    table(doc, ["Requirement group", "Implementation area", "Verification"], [
        ("Capture and logging", "app capture and database modules", "AC 01, unit tests, dashboard observation"),
        ("Detection and alerting", "app detection, models, and notifications modules", "AC 02 through AC 06 and rule tests"),
        ("Dashboard and export", "app dashboard routes, templates, reports, and static assets", "AC 07 through AC 10"),
        ("Security", "configuration, authentication, routes, and session settings", "Dashboard security regression tests"),
        ("Reliability", "database connection settings and detection exception isolation", "Unit tests and controlled runtime testing"),
    ], [1.55, 3.2, 1.75])

    doc.save(OUT)


if __name__ == "__main__":
    main()
