# Auto-Submit Credentials to C2

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Documents how phishing pages automatically forward captured credentials to attacker-
controlled C2 infrastructure via multiple channels (HTTPS, DNS, email).

## Exfiltration Channels
- **HTTPS POST**: Direct POST to attacker server
- **DNS exfiltration**: Base64-encoded data in subdomain queries
- **Email forwarding**: Send via victim's SMTP if accessible

## MITRE ATT&CK
- **T1041** — Exfiltration Over C2 Channel (Exfiltration)
- **T1048** — Exfiltration Over Alternative Protocol (Exfiltration)

## Detection
- Analyze form submission destinations on phishing pages
- DNS query analysis for base64-like subdomain patterns
- Unusual SMTP sending from credential capture pages

## Mitigation
- DNS filtering to block data exfiltration via DNS
- Web proxy with DLP capabilities
- Network traffic analysis for credential patterns

## References
- [MITRE T1041](https://attack.mitre.org/techniques/T1041/)
- [MITRE T1048](https://attack.mitre.org/techniques/T1048/)
