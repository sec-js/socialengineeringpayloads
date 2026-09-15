# P-code Encrypted VBA Macros

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
VBA in Office documents compiles to p-code (pseudo-code) stored separately from the
VBA source text. Some AV products only scan the source code, not the compiled p-code.
This technique removes or corrupts the source code while preserving functional p-code.

## Technical Detail
```
Normal Office document:
  VBA source code (readable text) → compiled to → p-code (binary)
  
Technique:
  VBA source code (corrupted/removed) + p-code (functional, intact)
  → AV scans source: nothing found
  → Office executes p-code: macro runs
```

## MITRE ATT&CK
- **T1059.005** — Command and Scripting Interpreter: Visual Basic (Execution)
- **T1027** — Obfuscated Files or Information (Defense Evasion)

## Detection
- Tools that analyze p-code directly: pcodedmp, oledump with p-code plugin
- Behavioral detection: Office spawning child processes
- AMSI (Antimalware Scan Interface) may still catch some variants

## Mitigation
- Disable macros in Office via Group Policy
- Use endpoint protection that analyzes p-code, not just source
- Deploy AMSI for Office macro scanning (modern Office versions)

## References
- [MITRE T1059.005](https://attack.mitre.org/techniques/T1059/005/)
- [pcodedmp tool](https://github.com/bontchev/pcodedmp)
