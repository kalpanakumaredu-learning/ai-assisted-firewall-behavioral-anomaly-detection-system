import re
from typing import List, Dict
from datetime import datetime


def parse_firewall_log_line(line: str) -> Dict:
    """
    Parse UFW firewall log line and extract:
    - timestamp
    - SRC
    - DST
    - PROTO
    - SPT
    - DPT
    """

    # Extract timestamp (e.g., "Mar 10 17:00:01")
    timestamp_match = re.search(r"^(\w+\s+\d+\s+\d+:\d+:\d+)", line)
    timestamp = None

    if timestamp_match:
        time_str = timestamp_match.group(1)
        try:
            timestamp = datetime.strptime(time_str, "%b %d %H:%M:%S")
            timestamp = timestamp.replace(year=datetime.now().year)
        except ValueError:
            timestamp = None

    # Extract firewall fields
    pattern = r"SRC=(?P<SRC>\S+) DST=(?P<DST>\S+).*?PROTO=(?P<PROTO>\S+) SPT=(?P<SPT>\S+) DPT=(?P<DPT>\S+)"
    match = re.search(pattern, line)

    if match:
        event = match.groupdict()
        event["timestamp"] = timestamp
        return event

    return {"raw": line.strip(), "timestamp": timestamp}


def parse_log_file(filepath: str) -> List[Dict]:
    parsed = []
    with open(filepath, 'r') as f:
        for line in f:
            parsed.append(parse_firewall_log_line(line))
    return parsed


if __name__ == "__main__":
    logs = parse_log_file("../data/firewall_sample.log")
    print(logs[:5])