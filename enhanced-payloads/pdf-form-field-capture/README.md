# PDF: form-field-capture Technique

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Advanced PDF exploitation technique targeting PDF readers and JavaScript execution.

## MITRE ATT&CK
- **T1204.002** — User Execution: Malicious File (Execution)
- **T1566.001** — Phishing: Spearphishing Attachment (Initial Access)

## Detection
- PDF content analysis tools: peepdf, pdf-parser, PDFiD
- Disable JavaScript in PDF readers
- Sandbox detonation of PDFs before delivery

## Mitigation
- Disable JavaScript in Adobe Reader and other PDF viewers
- Use PDF sandboxing (Adobe Protected Mode)
- Update PDF readers to latest version

## References
- [MITRE T1204.002](https://attack.mitre.org/techniques/T1204/002/)
- [PDFiD Tool](https://blog.didierstevens.com/programs/pdf-tools/)
