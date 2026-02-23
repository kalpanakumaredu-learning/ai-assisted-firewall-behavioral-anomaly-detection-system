import sys
import os

# Ensure project root is in Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from src.parser import parse_log_file
from src.anomaly_detector import detect_suspicious_activity


def generate_markdown_report(events, outfile="report.md"):
    with open(outfile, "w") as f:
        f.write("# AI-Assisted Firewall Behavioral Anomaly Detection Report\n\n")

        if not events:
            f.write("No suspicious activity detected.\n")
            return

        for i, event in enumerate(events, 1):
            f.write(f"## Incident {i}\n\n")
            f.write(f"**Detection Type:** {event['detection_type']}  \n")
            f.write(f"**Source IP:** {event['SRC']}  \n")
            f.write(f"**Target:** {event['DST']}  \n")
            f.write(f"**Port(s):** {event['DPT']}  \n\n")

            f.write(f"**Severity:** {event['severity']}  \n")
            f.write(f"**Risk Score:** {event['risk_score']}  \n")
            f.write(f"**Confidence:** {event['confidence']}  \n")
            f.write(f"**MITRE Technique:** {event['mitre_technique']}  \n\n")

            f.write("---\n\n")


def main(log_file_path):
    parsed_logs = parse_log_file(log_file_path)

    suspicious = detect_suspicious_activity(
        parsed_logs,
        threshold=5,
        window_seconds=60
    )

    if not suspicious:
        print("No suspicious activity detected.")
        generate_markdown_report([])
        return

    print("\n=== Suspicious Activity Detected ===\n")

    for event in suspicious:
        print(f"Detection Type: {event['detection_type']}")
        print(f"Source: {event['SRC']}")
        print(f"Severity: {event['severity']}")
        print("---")

    generate_markdown_report(suspicious)
    print("Report saved to report.md")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run.py data/firewall_sample.log")
    else:
        main(sys.argv[1])
        