# Staged DDE Payload

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization. PoC uses calc.exe.

## Overview
Two-stage DDE payload: Stage 1 is a minimal downloader DDE formula; Stage 2 is the full payload retrieved remotely.

## MITRE ATT&CK
- **Technique**: T1105 — Ingress Tool Transfer
- **Tactic**: Command and Control

## Detection
- Deep content inspection of Office files (not signature-based)
- Behavioral monitoring: Office application spawning cmd.exe or powershell.exe
- Disable DDE via Group Policy to prevent all DDE variants

## Mitigation
- Disable DDE in Microsoft Office via Group Policy
- Enable Protected View for files from internet/email
- Deploy Attack Surface Reduction (ASR) rules

## Files
See payload template files in this directory.

## References
- [MITRE ATT&CK T1105](https://attack.mitre.org/techniques/T1105/)
- [Microsoft DDE Advisory](https://docs.microsoft.com/en-us/security-updates/)
