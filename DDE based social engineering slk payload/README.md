# DDE-Based Social Engineering – SLK Payload

## Overview

Symbolic Link (`.slk`) is a text-based spreadsheet format supported by Microsoft Excel. SLK files can carry DDE-style formula execution via the `E` record type, which Excel evaluates on open without a DDE prompt — making this a stealthier variant than the CSV/DOCX DDE technique.

## How it Works

The SLK format uses a record structure where the `E` (expression) field in a cell record can contain an external command reference. Excel evaluates these expressions when loading the file. Unlike standard DDE prompts, some older Excel versions execute the payload silently.

## PoC

The file `Estates_ePIMS_2016.slk` contains the following payload in a cell expression record:

```
C;X16;K#REF!;Ecmd|' /C calc'!A0
```

The `E` value `cmd|' /C calc'!A0` references the external `cmd` DDE topic with the argument `/C calc`, launching `calc.exe`.

**To create your own PoC SLK file:**

```
ID;PWXL;N;E
P;PGeneral
C;X1;Y1;Ecmd|' /C calc'!A0
E
```

Save the above as `poc.slk` and open it in Microsoft Excel.

## MITRE ATT&CK

| Field | Value |
|---|---|
| Technique | T1559.002 – Inter-Process Communication: Dynamic Data Exchange |
| Tactic | Execution |
| Platform | Windows |

## Detection

- Monitor Excel spawning `cmd.exe` or `powershell.exe` as child processes.
- Alert on `.slk` files with `E` records containing pipe characters (`|`) typical of DDE references.
- Log and block `.slk` file downloads from the internet.

## Mitigation

- Disable DDE via Office Group Policy settings.
- Block or sandbox `.slk` files at the email gateway.
- Apply the Excel security update that adds Protected View support for SLK files.
