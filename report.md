## Suspicious Activity — 185.122.58.13 → 192.168.0.20

**Observed behavior:** Multiple repeated connection attempts observed from external IP **185.122.58.13** targeting internal host **192.168.0.20**. Attempts all target the same destination host and port range, indicative of automated probing.

**Likely attack type:** Automated scanning / credential-guessing (brute-force) against services on the destination host.

**Possible attacker intent:** Discover open services and weak credentials to gain unauthorized access or to identify attack surface for later exploitation.

**Potential impact if not addressed:** Successful compromise of the host (remote code execution, persistence), data exfiltration, or lateral movement to other network assets.

**Recommended actions:**

* Block `185.122.58.13` at the perimeter firewall.
* Apply rate limiting and fail2ban-style auto-banning.
* Check authentication logs on `192.168.0.20` for successful logins.
* Enforce SSH key-only authentication.
* Add event to SIEM with monitoring alerts.
