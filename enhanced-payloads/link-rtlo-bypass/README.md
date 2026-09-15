# Right-to-Left Override (RTLO)

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Uses Unicode U+202E to reverse display order of filename characters, making .exe files appear as .pdf or other safe formats.

## MITRE ATT&CK
- **T1036.002** — Masquerading: Right-to-Left Override

## Detection
Alert on filenames containing U+202E, file extension verification

## Mitigation
- Implement URL reputation services at email gateway and web proxy
- Deploy DNS filtering
- User training on URL verification before clicking
- Use password manager (auto-fill only on exact domain match)

## References
- [MITRE T1036.002](https://attack.mitre.org/techniques/T1036/002/)
