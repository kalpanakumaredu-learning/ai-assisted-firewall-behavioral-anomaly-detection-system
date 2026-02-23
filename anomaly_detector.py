from collections import defaultdict
from typing import List, Dict

# Detect suspicious repeated access attempts based on source IP and destination port.


def detect_suspicious_activity(parsed_logs: List[Dict], threshold: int = 5) -> List[Dict]:
    attempts = defaultdict(int)

    for entry in parsed_logs:
        if all(key in entry for key in ("SRC", "DST", "DPT")):
            key = (entry["SRC"], entry["DST"], entry["DPT"])
            attempts[key] += 1

    suspicious_events = []
    for (src, dst, dpt), count in attempts.items():
        if count >= threshold:
            suspicious_events.append({
                "SRC": src,
                "DST": dst,
                "DPT": dpt,
                "count": count,
                "description": f"Possible brute force or port scanning detected: {src} -> {dst} on port {dpt} ({count} attempts)"
            })

    return suspicious_events


if __name__ == "__main__":
    # Example will be filled in later once full pipeline is ready.
    pass
