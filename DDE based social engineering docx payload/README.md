# DDE-Based Social Engineering – DOCX Payload

## Overview

Dynamic Data Exchange (DDE) fields can be embedded inside Microsoft Word documents (`.doc` / `.docx`). When the document is opened, Word evaluates the DDE field and prompts the user to update linked data. If confirmed, the embedded command is executed by the OS.

## How it Works

A DDE field is inserted into the document using Word's `Ctrl+F9` field code syntax:

```
{ DDEAUTO cmd "/C calc" }
```

On open, Word displays a dialog asking whether to update the field. If the user clicks **Yes**, `cmd.exe` is spawned with the supplied arguments.

## PoC

The file `phs398.doc` contains a DDE field that launches `calc.exe` as a PoC.

**To create your own PoC DOCX:**

1. Open a blank Word document.
2. Press `Ctrl+F9` to insert a field code.
3. Type the following inside the braces:

   ```
   DDEAUTO cmd "/C calc"
   ```

4. Save the file and reopen it — Word will prompt to execute the DDE field.

## MITRE ATT&CK

| Field | Value |
|---|---|
| Technique | T1559.002 – Inter-Process Communication: Dynamic Data Exchange |
| Tactic | Execution |
| Platform | Windows |

## Detection

- Monitor Word spawning `cmd.exe` or `powershell.exe` as child processes.
- Alert on field codes containing `DDEAUTO` or `DDE` in Office documents.
- Enable Protected View and disable DDE auto-execution in Office Trust Center settings.

## Mitigation

- Disable DDE via registry: `HKCU\Software\Microsoft\Office\<version>\Word\Options\DontUpdateLinks = 1`.
- Deploy the Office security update from [MS17-014](https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2017/ms17-014).
- Enable Protected View for files received via email or downloaded from the internet.
