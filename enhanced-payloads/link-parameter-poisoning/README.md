# Query Parameter Poisoning

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Manipulates URL query parameters to alter application behavior or bypass security controls.

## MITRE ATT&CK
- **T1190** — Exploit Public-Facing Application

## Detection
WAF rules, input validation monitoring

## Mitigation
- Implement URL reputation services at email gateway and web proxy
- Deploy DNS filtering
- User training on URL verification before clicking
- Use password manager (auto-fill only on exact domain match)

## References
- [MITRE T1190](https://attack.mitre.org/techniques/T1190/)
