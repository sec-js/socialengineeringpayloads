# DDE-Based Social Engineering – MSG (Outlook) Payload

## Overview

Microsoft Outlook `.msg` files can carry embedded DDE fields within their body content. When such a message is opened and the user agrees to update external links, the DDE formula is executed by the underlying Office engine.

## How it Works

A DDE payload is embedded in the body of an Outlook message (`.msg` format). When the victim opens the message, Outlook processes the DDE field and prompts the user. If accepted, an arbitrary command is executed.

This technique is effective because `.msg` files can be sent as email attachments and are often trusted by recipients familiar with the format.

## PoC

The file `FW EXTERNAL  SWIFT COPY 50000$.msg` is a spear-phishing Outlook message containing a DDE payload that launches `calc.exe`.

**To create your own PoC MSG:**

1. Compose a new Outlook email.
2. Insert a DDE field using `Insert > Field` or press `Ctrl+F9`:

   ```
   { DDEAUTO cmd "/C calc" }
   ```

3. Save the email as a `.msg` file using `File > Save As`.
4. Open the saved `.msg` — Outlook will prompt to execute the DDE field.

## Social Engineering Context

The filename `FW EXTERNAL SWIFT COPY 50000$.msg` simulates a forwarded financial transaction notification, creating urgency that pressures the recipient into opening it without scrutiny.

## MITRE ATT&CK

| Field | Value |
|---|---|
| Technique | T1559.002 – Inter-Process Communication: Dynamic Data Exchange |
| Tactic | Execution |
| Sub-technique | Spear Phishing Attachment (T1566.001) |
| Platform | Windows |

## Detection

- Monitor `OUTLOOK.EXE` spawning child processes such as `cmd.exe`.
- Alert on `.msg` attachments with embedded DDE field codes.
- Inspect Outlook Safe Documents settings and Protected View configuration.

## Mitigation

- Disable DDE in Office applications via Group Policy.
- Enable Outlook's attachment preview restrictions.
- Train users to be suspicious of forwarded financial-themed attachments.
