# DDE-Based Social Engineering – XLS Payload

## Overview

Microsoft Excel spreadsheets (`.xls`) support DDE formulas via their native formula engine. An XLS file can contain cells with DDE formulas that execute arbitrary commands when opened and the update prompt is accepted by the victim.

## How it Works

DDE formulas in XLS cells follow the format:

```
=application|'topic'!item
```

When Excel opens the file it evaluates the formula and prompts the user to allow the external data connection. If accepted, the referenced application (`cmd.exe`) is launched with the supplied arguments.

## PoC

The file `new-osha300form1-1-04.xls` contains a DDE formula that launches `calc.exe`.

**To create your own PoC XLS:**

1. Open Excel and create a new workbook.
2. In cell `A1`, enter:

   ```
   =cmd|' /C calc'!A0
   ```

3. Save as `.xls` (Excel 97-2003 format).
4. Close and reopen the file — Excel will prompt to update external links.

## Social Engineering Context

The filename mimics an OSHA safety compliance form, a common lure targeting employees in regulated industries who routinely handle government forms.

## MITRE ATT&CK

| Field | Value |
|---|---|
| Technique | T1559.002 – Inter-Process Communication: Dynamic Data Exchange |
| Tactic | Execution |
| Platform | Windows |

## Detection

- Monitor `EXCEL.EXE` spawning `cmd.exe` or `powershell.exe`.
- Alert on XLS files with cell formulas matching the pattern `=*|'*'!*`.
- Review and enable Excel's `Trust Center > External Content` settings.

## Mitigation

- Set `DisableDDEServerLaunch` registry value to `1` under `HKCU\Software\Microsoft\Office\<version>\Excel\Security`.
- Enable Protected View for all externally sourced Excel files.
- Block Excel files from running embedded DDE via Group Policy.
