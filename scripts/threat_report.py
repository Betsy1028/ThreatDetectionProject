import csv
import re
import os
from fpdf import FPDF
from collections import Counter
import matplotlib.pyplot as plt

LOGS_FOLDER = os.path.join(os.path.dirname(__file__), "..", "logs")
REPORTS_FOLDER = os.path.join(os.path.dirname(__file__), "..", "reports")
os.makedirs(LOGS_FOLDER, exist_ok=True)
os.makedirs(REPORTS_FOLDER, exist_ok=True)

LOG_FILE = os.path.join(LOGS_FOLDER, "sample_event_logs.csv")
REPORT_FILE = os.path.join(REPORTS_FOLDER, "threat_report.pdf")

SUSPICIOUS_USERS = ["admin1", "testuser", "unknown"]
SUSPICIOUS_COMMANDS = ["powershell.exe -nop", "wmic", "schtasks /create"]
SUSPICIOUS_IPS = ["192.168.100.100", "10.10.10.200"]

def detect_suspicious_activity(log_file):
    alerts = []
    user_counts = Counter()
    command_counts = Counter()
    ip_counts = Counter()
    with open(log_file, newline="", encoding="utf-8") as csvfile:
        reader = csv.DictReader(csvfile)
        for row in reader:
            username = row.get("Username", "").lower()
            command = row.get("CommandLine", "").lower()
            ip_address = row.get("SourceIP", "")
            if username in [u.lower() for u in SUSPICIOUS_USERS]:
                alerts.append(f"Suspicious User: {username} in EventID {row.get('EventID')}")
                user_counts[username] += 1
            for cmd in SUSPICIOUS_COMMANDS:
                if re.search(cmd, command):
                    alerts.append(f"Suspicious Command: '{command}' by {username} in EventID {row.get('EventID')}")
                    command_counts[cmd] += 1
            if ip_address in SUSPICIOUS_IPS:
                alerts.append(f"Suspicious IP: {ip_address} in EventID {row.get('EventID')}")
                ip_counts[ip_address] += 1
    return alerts, user_counts, command_counts, ip_counts

def generate_report(alerts, user_counts, command_counts, ip_counts, report_file):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, "Threat Detection Report", ln=True, align="C")
    pdf.set_font("Arial", "", 12)
    pdf.ln(10)
    pdf.multi_cell(0, 10, f"Total Alerts Detected: {len(alerts)}")
    pdf.ln(5)
    pdf.cell(0, 10, "Alerts Summary:", ln=True)
    for alert in alerts:
        pdf.multi_cell(0, 8, f"- {alert}")
    def save_chart(counter, title, filename):
        if counter:
            plt.figure(figsize=(5,3))
            plt.bar(counter.keys(), counter.values(), color='red')
            plt.title(title)
            plt.xticks(rotation=45)
            plt.tight_layout()
            chart_path = os.path.join(REPORTS_FOLDER, filename)
            plt.savefig(chart_path)
            plt.close()
            pdf.image(chart_path, w=170)
    save_chart(user_counts, "Suspicious Users", "user_chart.png")
    save_chart(command_counts, "Suspicious Commands", "command_chart.png")
    save_chart(ip_counts, "Suspicious IPs", "ip_chart.png")
    pdf.output(report_file)
    print(f"Report generated: {report_file}")

if __name__ == "__main__":
    alerts, user_counts, command_counts, ip_counts = detect_suspicious_activity(LOG_FILE)
    generate_report(alerts, user_counts, command_counts, ip_counts, REPORT_FILE)
