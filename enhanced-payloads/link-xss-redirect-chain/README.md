# XSS + Open Redirect Chain

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Uses open redirect vulnerabilities on trusted domains to redirect to malicious content, bypassing URL-based reputation checks.

## MITRE ATT&CK
- **T1189** — Drive-by Compromise

## Detection
Follow all redirects in URL scanning, analyze final destination

## Mitigation
- Implement URL reputation services at email gateway and web proxy
- Deploy DNS filtering
- User training on URL verification before clicking
- Use password manager (auto-fill only on exact domain match)

## References
- [MITRE T1189](https://attack.mitre.org/techniques/T1189/)
