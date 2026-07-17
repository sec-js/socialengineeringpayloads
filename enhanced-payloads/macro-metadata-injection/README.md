# Macros in Document Metadata

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Stores payload code in document metadata fields (Author, Title, Comments, Custom Properties),
then constructs and executes the payload by reading these fields at runtime via VBA.

## How It Works
1. Attacker stores command fragments in document properties
2. Minimal VBA macro reads properties and assembles command
3. Command executed via Shell() or similar
4. Static analysis of VBA code reveals nothing suspicious — payload is in metadata

## MITRE ATT&CK
- **T1027** — Obfuscated Files or Information (Defense Evasion)
- **T1059.005** — Visual Basic (Execution)

## Detection
- Inspect document metadata for unusual content
- Document properties analysis tools (OLE analysis)
- Behavioral detection of macro reading own document properties

## Mitigation
- Strip metadata from documents before sending externally
- Behavioral monitoring of document property access via macros
- AMSI for VBA scanning

## References
- [MITRE T1027](https://attack.mitre.org/techniques/T1027/)
