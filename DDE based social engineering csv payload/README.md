# DDE-Based Social Engineering – CSV Payload

## Overview

Dynamic Data Exchange (DDE) is a Windows inter-process communication protocol that Microsoft Office applications support as a legacy feature. CSV files containing DDE formulas are opened by Excel, which then executes the embedded formula.

## How it Works

When the victim opens the CSV file in Microsoft Excel, the application prompts the user to update external links. If the user accepts, Excel executes the embedded DDE formula, which can launch arbitrary commands via `cmd.exe`.

## PoC

The file `Estates_ePIMS_2016.csv` contains the following DDE payload in a cell:

```
=cmd|' /C calc'!A0
```

When opened in Excel and the DDE prompt is accepted, this executes `calc.exe`.

**To reproduce a clean PoC CSV:**

```
=cmd|' /C calc'!A0
```

Save a `.csv` file with the above value in any cell, then open it in Excel.

## MITRE ATT&CK

| Field | Value |
|---|---|
| Technique | T1559.002 – Inter-Process Communication: Dynamic Data Exchange |
| Tactic | Execution |
| Platform | Windows |

## Detection

- Monitor Office applications spawning `cmd.exe` or `powershell.exe` as child processes.
- Alert on DDE-related registry keys: `HKCU\Software\Microsoft\Office\*\Excel\Security\DisableDDEServerLaunch`.
- Block or warn on CSV files containing `=cmd|` or `=DDE(` formulas.

## Mitigation

- Disable DDE in Office via Group Policy (`DisableDDEServerLaunch = 1`).
- Enable Protected View for files from the internet.
- Apply Microsoft security advisory [4053440](https://docs.microsoft.com/en-us/security-updates/securityadvisories/2017/4053440).
