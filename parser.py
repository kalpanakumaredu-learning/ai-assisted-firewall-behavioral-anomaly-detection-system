import re
from typing import List, Dict

# This file will parse firewall logs into structured Python objects.
# We will update this together.

# Parsing logic for UFW firewall logs implemented below.

def parse_firewall_log_line(line: str) -> Dict:
    """
    Parse UFW firewall log line and extract key fields.
    Example UFW log:
    Dec 14 17:28:14 host kernel: [UFW BLOCK] IN=enp0s3 OUT= MAC=... SRC=185.122.58.13 DST=192.168.0.20 LEN=60 TOS=0x00 PROTO=TCP SPT=53422 DPT=22
    """
    pattern = r"SRC=(?P<SRC>\S+) DST=(?P<DST>\S+).*?PROTO=(?P<PROTO>\S+) SPT=(?P<SPT>\S+) DPT=(?P<DPT>\S+)"
    match = re.search(pattern, line)
    if match:
        return match.groupdict()
    return {"raw": line.strip()}


def parse_log_file(filepath: str) -> List[Dict]:
    parsed = []
    with open(filepath, 'r') as f:
        for line in f:
            parsed.append(parse_firewall_log_line(line))
    return parsed


if __name__ == "__main__":
    # Example usage (we'll adapt this later):
    logs = parse_log_file("../data/firewall_sample.log")
    print(logs[:5])
