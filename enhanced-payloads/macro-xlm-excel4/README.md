# Excel 4.0 (XLM) Macros

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Excel 4.0 (XLM) macros predate VBA (1992) and use a different macro engine. Many
modern AV products and sandboxes have weaker detection for XLM macros compared to VBA.

## Technical Detail
XLM macros are stored as spreadsheet cells rather than VBA modules:
- Name the macro sheet "Auto_Open" for auto-execution on file open
- Cells contain formula-like commands: `=EXEC()`, `=CALL()`, `=HALT()`

## Example XLM Structure (for detection reference)
```
Cell A1: =EXEC("calc.exe")
Cell A2: =HALT()
Sheet Name: Auto_Open
```

## MITRE ATT&CK
- **T1137.001** — Office Application Startup: Office Template Macros (Persistence)
- **T1059.005** — Command and Scripting Interpreter: Visual Basic (Execution)

## Detection
- Excel sheets named "Auto_Open" with formula-based content
- XLSB files (binary format) often used to hide XLM macros
- Enable "Block macros in Office files from the internet" policy
- Microsoft Defender has XLM macro detection capabilities

## Mitigation
- Block Excel 4.0 macro execution via Group Policy
- Policy: "Prevent Excel from running macro from internet"
- Deploy ASR rules for Office applications

## Files
- `xlm-template.txt` — Example XLM macro structure (for detection rule creation)

## References
- [MITRE T1137.001](https://attack.mitre.org/techniques/T1137/001/)
