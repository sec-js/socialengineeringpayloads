# Fake Attachment Scam

## Overview

This technique involves crafting a Microsoft Outlook message (`.msg`) that visually simulates an email with a file attachment but embeds the "attachment" as an OLE object or inline image within the message body. The victim perceives a legitimate-looking document and is deceived into clicking it.

## How it Works

The `.msg` file is formatted to display what appears to be an attached document inside the email body (e.g., a Microsoft Word document icon). The visible "attachment" is actually an embedded OLE object or a hyperlinked image. When clicked, it either:

- Executes an embedded payload (OLE path), or
- Redirects the victim to a malicious URL (hyperlink path).

## PoC

The file `FW Confidential.msg` demonstrates the fake attachment scam technique. It presents as a forwarded confidential document with an embedded fake attachment.

**To create your own PoC:**

1. Compose a new Outlook email with a professional-looking body.
2. Insert a screenshot or image of a document icon as an inline image.
3. Hyperlink the image to a target URL, or embed a real OLE object with a benign payload (e.g., `calc.exe`).
4. Save the file as `.msg` and send or deliver to the target.

**Minimal OLE PoC:** Embed a `.bat` file containing `calc.exe` as an OLE object inside the email body, disguised with a Word document icon.

## Social Engineering Context

The filename `FW Confidential.msg` uses:
- **FW** (forwarded) — implies urgency and social proof ("someone already sent this").
- **Confidential** — triggers curiosity and perceived importance.

This combination increases the likelihood of the victim opening and interacting with the message.

## MITRE ATT&CK

| Field | Value |
|---|---|
| Technique | T1566.001 – Spear Phishing Attachment |
| Tactic | Initial Access |
| Platform | Windows |

## Detection

- Inspect `.msg` files for embedded OLE objects with executable MIME types.
- Alert on email messages where displayed "attachments" are inline OLE objects rather than real MIME attachments.
- Monitor Outlook spawning unexpected child processes.

## Mitigation

- Enable email gateway scanning for OLE-embedded executables in `.msg` files.
- Configure Outlook to block embedded object activation from untrusted senders.
- Conduct user awareness training on identifying fake attachment scams.
