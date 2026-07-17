# Homograph Domain Attack

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Uses Unicode characters that are visually identical to ASCII letters to create look-alike domains.

## MITRE ATT&CK
- **T1036** — Masquerading

## Detection
Domain analysis, Unicode inspection, Certificate Transparency monitoring

## Mitigation
- Implement URL reputation services at email gateway and web proxy
- Deploy DNS filtering
- User training on URL verification before clicking
- Use password manager (auto-fill only on exact domain match)

## References
- [MITRE T1036](https://attack.mitre.org/techniques/T1036/)
