from collections import defaultdict
from typing import List, Dict
from datetime import timedelta
import math


PRIVILEGED_PORTS = {"22", "3389", "445", "21", "23"}


# -----------------------------
# Risk Scoring Engine
# -----------------------------
def calculate_risk_score(event: Dict) -> Dict:
    score = 0

    if event.get("count", 0) >= 5:
        score += 3

    if event.get("DPT") in PRIVILEGED_PORTS:
        score += 2

    if event.get("detection_type") == "Multi-Port Scanning":
        score += 3

    if event.get("detection_type") == "Statistical Activity Spike":
        score += 2

    if event.get("count", 0) >= 10:
        score += 2

    if score >= 6:
        severity = "HIGH"
    elif score >= 4:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    confidence = min(0.4 + (score * 0.08), 0.9)

    event["risk_score"] = score
    event["severity"] = severity
    event["confidence"] = round(confidence, 2)

    return event


# -----------------------------
# MITRE Mapping
# -----------------------------
def map_to_mitre(event: Dict) -> Dict:

    if event.get("detection_type") == "Multi-Port Scanning":
        event["mitre_technique"] = "T1595 - Active Scanning"
        return event

    if event.get("detection_type") == "Statistical Activity Spike":
        event["mitre_technique"] = "T1498 - Network Denial of Service (Potential)"
        return event

    port = event.get("DPT")

    if port == "22":
        event["mitre_technique"] = "T1110 - Brute Force"
    elif port == "3389":
        event["mitre_technique"] = "T1110 - Brute Force (RDP)"
    elif port == "445":
        event["mitre_technique"] = "T1021 - Remote Services"
    else:
        event["mitre_technique"] = "T1595 - Active Scanning"

    return event


# -----------------------------
# Burst Detection
# -----------------------------
def detect_burst_activity(parsed_logs: List[Dict], threshold: int, window_seconds: int):
    grouped_attempts = defaultdict(list)

    for entry in parsed_logs:
        if all(key in entry for key in ("SRC", "DST", "DPT", "timestamp")):
            key = (entry["SRC"], entry["DST"], entry["DPT"])
            grouped_attempts[key].append(entry)

    suspicious_events = []

    for (src, dst, dpt), events in grouped_attempts.items():

        events = sorted(events, key=lambda x: x["timestamp"])

        for i in range(len(events)):
            start_time = events[i]["timestamp"]
            burst_count = 1

            for j in range(i + 1, len(events)):
                if events[j]["timestamp"] - start_time <= timedelta(seconds=window_seconds):
                    burst_count += 1
                else:
                    break

            if burst_count >= threshold:
                event = {
                    "SRC": src,
                    "DST": dst,
                    "DPT": dpt,
                    "count": burst_count,
                    "window_seconds": window_seconds,
                    "detection_type": "Time-Window Burst Activity"
                }

                event = calculate_risk_score(event)
                event = map_to_mitre(event)

                suspicious_events.append(event)
                break

    return suspicious_events


# -----------------------------
# Multi-Port Scan Detection
# -----------------------------
def detect_multi_port_scan(parsed_logs: List[Dict], window_seconds: int):
    src_groups = defaultdict(list)

    for entry in parsed_logs:
        if entry.get("timestamp") and entry.get("SRC") and entry.get("DPT"):
            src_groups[entry["SRC"]].append(entry)

    scan_events = []

    for src, events in src_groups.items():
        events = sorted(events, key=lambda x: x["timestamp"])

        for i in range(len(events)):
            start_time = events[i]["timestamp"]
            ports = {events[i]["DPT"]}

            for j in range(i + 1, len(events)):
                if events[j]["timestamp"] - start_time <= timedelta(seconds=window_seconds):
                    ports.add(events[j]["DPT"])
                else:
                    break

            if len(ports) >= 3:
                event = {
                    "SRC": src,
                    "DST": "Multiple",
                    "DPT": "Multiple",
                    "count": len(ports),
                    "window_seconds": window_seconds,
                    "detection_type": "Multi-Port Scanning"
                }

                event = calculate_risk_score(event)
                event = map_to_mitre(event)

                scan_events.append(event)
                break

    return scan_events


# -----------------------------
# Statistical Anomaly Detection
# -----------------------------
def detect_statistical_anomalies(parsed_logs: List[Dict]):
    source_counts = defaultdict(int)

    for entry in parsed_logs:
        if entry.get("SRC"):
            source_counts[entry["SRC"]] += 1

    if not source_counts:
        return []

    counts = list(source_counts.values())
    mean = sum(counts) / len(counts)

    variance = sum((x - mean) ** 2 for x in counts) / len(counts)
    std_dev = math.sqrt(variance)

    anomalies = []

    for src, count in source_counts.items():

        if std_dev == 0:
            if count >= 8:
                z_score = 3
            else:
                continue
        else:
            z_score = (count - mean) / std_dev

        if z_score >= 1.5 and count >= 8:
            event = {
                "SRC": src,
                "DST": "Multiple",
                "DPT": "Multiple",
                "count": count,
                "detection_type": "Statistical Activity Spike",
                "z_score": round(z_score, 2)
            }

            event = calculate_risk_score(event)
            event = map_to_mitre(event)

            anomalies.append(event)

    return anomalies


# -----------------------------
# Master Detection Function
# -----------------------------
def detect_suspicious_activity(
    parsed_logs: List[Dict],
    threshold: int = 5,
    window_seconds: int = 60
) -> List[Dict]:

    burst_events = detect_burst_activity(parsed_logs, threshold, window_seconds)
    scan_events = detect_multi_port_scan(parsed_logs, window_seconds)
    statistical_events = detect_statistical_anomalies(parsed_logs)

    return burst_events + scan_events + statistical_events