# XOR-Obfuscated DDE Payload

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization. PoC uses calc.exe.

## Overview
DDE payload where the command string is XOR-encoded and decoded at runtime using Excel formula chaining.

## MITRE ATT&CK
- **Technique**: T1027 — Obfuscated Files or Information
- **Tactic**: Defense Evasion

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
- [MITRE ATT&CK T1027](https://attack.mitre.org/techniques/T1027/)
- [Microsoft DDE Advisory](https://docs.microsoft.com/en-us/security-updates/)
