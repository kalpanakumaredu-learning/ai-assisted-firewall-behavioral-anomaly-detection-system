from parser import parse_log_file
from anomaly_detector import detect_suspicious_activity
from rag_assistant import explain_threat

import sys


def generate_markdown_report(explanations, outfile="report.md"):
    with open(outfile, "w") as f:
        f.write("# AI-Powered Firewall Threat Analysis Report\n\n")
        for exp in explanations:
            f.write(f"## Suspicious Activity\n\n{exp}\n\n---\n\n")


def main(log_file_path):
    parsed_logs = parse_log_file(log_file_path)
    suspicious = detect_suspicious_activity(parsed_logs, threshold=5)

    print("\n=== Suspicious Activity Detected ===\n")
    explanations = []

    for entry in suspicious:
        explanation = explain_threat(entry)
        explanations.append(explanation)
        print(explanation)
        print("\n---\n")

    generate_markdown_report(explanations)
    print("\nReport saved to report.md")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python run.py E:\Project\AI\Firewall\data\firewall_sample.log")
    else:
        main(sys.argv[1])
