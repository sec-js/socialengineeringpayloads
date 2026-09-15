# MITRE ATT&CK Technique Mapping

> **⚠️ DISCLAIMER**: This document is for **educational and research purposes ONLY**.
> All techniques are mapped to help defenders understand and detect social engineering attacks.

---

## Overview

This document maps all payloads in the Social Engineering Payloads repository to MITRE ATT&CK
techniques. Use this reference to understand the threat landscape and prioritize defenses.

**MITRE ATT&CK Framework Version**: 14.0  
**Last Updated**: 2025-01-01

---

## Existing Payloads — Technique Mapping

### DDE-Based Payloads

#### 1. DDE CSV Payload
**File**: `DDE based social engineering csv payload/Estates_ePIMS_2016.csv`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1204.002 | User Execution: Malicious File | — | Execution | High |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | — | Execution | High |
| T1027 | Obfuscated Files or Information | — | Defense Evasion | Medium |

**Detection Opportunities**:
- CSV files containing `=CMD` or `=DDE` field prefixes
- calc.exe or cmd.exe spawned by Microsoft Excel
- Windows Event ID 4688 (Process Creation) monitoring

**Mitigation**:
- Disable Dynamic Data Exchange via Group Policy
- Apply Protected View settings for Office applications
- Block CSV files in email attachments when not expected

---

#### 2. DDE DOCX Payload
**File**: `DDE based social engineering docx payload/phs398.doc`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1204.002 | User Execution: Malicious File | — | Execution | High |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | — | Execution | High |
| T1203 | Exploitation for Client Execution | — | Execution | High |

**Detection Opportunities**:
- WINWORD.EXE spawning unusual child processes
- DDE field update prompts (user interaction required)
- Network connections from WINWORD.EXE

**Mitigation**:
- Disable DDE via registry: `HKCU\Software\Microsoft\Office\<version>\Word\Security\AllowDDE = 0`
- Enable Office macro security settings
- Use Attack Surface Reduction (ASR) rules

---

#### 3. DDE Outlook MSG Payload
**File**: `DDE based social engineering msg (OUTLOOK) payload/FW EXTERNAL SWIFT COPY 50000$.msg`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1204.002 | User Execution: Malicious File | — | Execution | High |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | — | Execution | High |
| T1434 | Internal Spearphishing | — | Lateral Movement | High |

**Social Engineering Element**: Financial urgency ($50,000 SWIFT transfer) triggers action.

**Detection Opportunities**:
- MSG files with embedded DDE objects
- OUTLOOK.EXE spawning child processes
- Email content analysis for financial urgency language

**Mitigation**:
- Disable DDE in Outlook
- Enable Safe Links and Safe Attachments (Microsoft Defender for Office 365)
- Financial transfer security policy verification procedures

---

#### 4. DDE SLK Payload
**File**: `DDE based social engineering slk payload/Estates_ePIMS_2016.slk`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1204.002 | User Execution: Malicious File | — | Execution | High |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | — | Execution | High |
| T1036 | Masquerading | — | Defense Evasion | Medium |

**Notes**: SLK (Symbolic Link) format often bypasses email filters that focus on common Office formats.

**Detection Opportunities**:
- .slk files in email attachments (uncommon format)
- Excel spawning child processes
- Content inspection of SLK format for embedded commands

**Mitigation**:
- Block SLK files at email gateway
- Configure Excel to require confirmation before running external commands

---

#### 5. DDE XLS Payload
**File**: `DDE based social engineering xls payload/new-osha300form1-1-04.xls`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1204.002 | User Execution: Malicious File | — | Execution | High |
| T1059.003 | Command and Scripting Interpreter: Windows Command Shell | — | Execution | High |
| T1036.006 | Masquerading: Space after Filename | — | Defense Evasion | Medium |

**Social Engineering Element**: Impersonates OSHA compliance form — triggers urgency in workplace setting.

**Detection Opportunities**:
- XLS files with DDE fields
- Microsoft Excel spawning cmd.exe
- Unusual network activity from Excel process

---

### Object Embedding Payloads

#### 6. Embedded Object in Office Document
**Directory**: `Embedding Object in office document/`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1204.002 | User Execution: Malicious File | — | Execution | High |
| T1055 | Process Injection | — | Defense Evasion | High |
| T1027.006 | Obfuscated Files: HTML Smuggling | — | Defense Evasion | Medium |

**Detection Opportunities**:
- Office documents with embedded OLE objects
- Object Linking and Embedding (OLE) analysis tools
- Unusual process spawning from Office applications

**Mitigation**:
- Disable OLE object execution in Office
- Use AMSI for Office macro scanning
- Deploy ASR rule: Block Office applications from creating executable content

---

### Execution Payloads

#### 7. PowerShell on Mouseover (PowerPoint)
**File**: `Execute powershell on mouseover - Powerpoint (pps)/`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1204.002 | User Execution: Malicious File | — | Execution | High |
| T1059.001 | Command and Scripting Interpreter: PowerShell | — | Execution | High |
| T1218.011 | System Binary Proxy Execution: Rundll32 | — | Defense Evasion | High |

**Technique Details**: Mouse hover action triggers PowerShell execution via mouseover event.

**Detection Opportunities**:
- POWERPNT.EXE spawning PowerShell
- PowerShell execution policies and logging
- Windows Event ID 4104 (PowerShell Script Block Logging)

**Mitigation**:
- Enable PowerShell constrained language mode
- Configure PowerShell execution policy
- Enable PowerShell script block logging

---

### Social Engineering Payloads

#### 8. Fake Attachment Scam
**File**: `Fake attachment scam/FW Confidential.msg`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1204.002 | User Execution: Malicious File | — | Execution | Medium |
| T1036 | Masquerading | — | Defense Evasion | Medium |
| T1598 | Phishing for Information | — | Reconnaissance | Medium |

**Social Engineering Element**: "Confidential" subject line triggers curiosity/urgency.

---

#### 9. Link Manipulation Attack
**Directory**: `Link manipulation attack/linkmanipulation/`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.002 | Phishing: Spearphishing Link | — | Initial Access | High |
| T1204.001 | User Execution: Malicious Link | — | Execution | High |
| T1598.003 | Phishing for Information: Spearphishing Link | — | Reconnaissance | High |
| T1036 | Masquerading | — | Defense Evasion | Medium |

**Technique Details**: Manipulates URLs to appear legitimate while pointing to malicious destinations.

**Detection Opportunities**:
- URL analysis and reputation checking
- Domain registration age and WHOIS analysis
- SSL certificate analysis for phishing domains

**Mitigation**:
- Deploy email link scanning (Safe Links)
- User training on URL verification
- DNS filtering and web proxy with URL categorization

---

#### 10. PDF with Malicious URL
**Files**: `PDF with malicious URL/50000usd.pdf`, `100000usd-pdf.jar`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1204.002 | User Execution: Malicious File | — | Execution | High |
| T1566.002 | Phishing: Spearphishing Link | — | Initial Access | High |
| T1036 | Masquerading | — | Defense Evasion | Medium |

**Notes**: Financial theme ($50,000/$100,000) exploits greed/urgency.

---

#### 11. Password Protected Document
**Files**: `Password protected document/Confidential.docx`, `SWIFT transaction acknowledgement.msg`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1204.002 | User Execution: Malicious File | — | Execution | High |
| T1027 | Obfuscated Files or Information | — | Defense Evasion | High |
| T1036 | Masquerading | — | Defense Evasion | Medium |

**Evasion Technique**: Password prevents automated scanning of document content.

**Detection Opportunities**:
- Password-protected file delivery heuristics
- Behavioral analysis post-decryption
- Password included in email body (indicator of technique)

---

### Credential Harvesting Payloads

#### 12. Steal Credentials via Fake Excel
**Directory**: `Steal credentials using fake excel doc/excel/`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1056.003 | Input Capture: Web Portal Capture | — | Collection | High |
| T1539 | Steal Web Session Cookie | — | Collection | High |
| T1078 | Valid Accounts | — | Defense Evasion | High |

**Technique Details**: HTML page mimics Microsoft login to capture credentials.

**Detection Opportunities**:
- Web form submission monitoring
- Look-alike domain detection
- Browser security warnings for credential entry on non-HTTPS pages

---

#### 13. Steal Credentials via Basic Auth (Word)
**File**: `Steal credential using a word document which pop for basic authentication/Protected_document.docx`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1056.003 | Input Capture: Web Portal Capture | — | Collection | High |
| T1187 | Forced Authentication | — | Collection | High |
| T1078 | Valid Accounts | — | Defense Evasion | High |

**Technique Details**: Word document triggers basic authentication dialog via embedded resource.

---

### Web-Based Payloads

#### 14. Tabnabbing Attack
**Directory**: `Tabnabbing attack/incident/`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.002 | Phishing: Spearphishing Link | — | Initial Access | High |
| T1185 | Browser Session Hijacking | — | Collection | High |
| T1204.001 | User Execution: Malicious Link | — | Execution | Medium |
| T1056.003 | Input Capture: Web Portal Capture | — | Collection | High |

**Technique Details**: Background tab replaces content with phishing page when user is inactive.

---

#### 15. LNK Download and Execute
**File**: `lnk - download and execute calc HTA/Employee Survey.lnk`

| MITRE ID | Technique | Sub-technique | Tactic | Severity |
|----------|-----------|---------------|--------|----------|
| T1566.001 | Phishing: Spearphishing Attachment | — | Initial Access | High |
| T1204.002 | User Execution: Malicious File | — | Execution | High |
| T1547.009 | Boot or Logon Autostart: Shortcut Modification | — | Persistence | Medium |
| T1218.005 | System Binary Proxy: Mshta | — | Defense Evasion | High |

**Technique Details**: Windows shortcut (.lnk) downloads and executes HTA payload.

**Detection Opportunities**:
- LNK files with unusual target paths
- LNK files in email attachments
- mshta.exe execution monitoring

---

## Enhanced Payload Technique Mapping

### Advanced DDE Evasion

| Payload | MITRE ID | Technique | Tactic |
|---------|----------|-----------|--------|
| DDE Base64 Encoded | T1027.010 | Obfuscated Files: Command Obfuscation | Defense Evasion |
| DDE XOR Obfuscated | T1027 | Obfuscated Files or Information | Defense Evasion |
| DDE Staged | T1105 | Ingress Tool Transfer | Command & Control |
| DDE Environment Vars | T1027 | Obfuscated Files or Information | Defense Evasion |

### Credential Harvesting

| Payload | MITRE ID | Technique | Tactic |
|---------|----------|-----------|--------|
| MFA Capture | T1111 | Multi-Factor Authentication Interception | Collection |
| Silent NTLM Capture | T1187 | Forced Authentication | Collection |
| Credential Validation | T1078 | Valid Accounts | Defense Evasion |
| Auto-Submit to C2 | T1041 | Exfiltration Over C2 Channel | Exfiltration |

### Office Macros

| Payload | MITRE ID | Technique | Tactic |
|---------|----------|-----------|--------|
| P-code Encrypted VBA | T1059.005 | VB Command Interpreter | Execution |
| Excel 4.0 Macros | T1137.001 | Office Application Startup: Office Template Macros | Persistence |
| Metadata Injection | T1027 | Obfuscated Files | Defense Evasion |
| Template Injection | T1221 | Template Injection | Defense Evasion |

### PDF Advanced

| Payload | MITRE ID | Technique | Tactic |
|---------|----------|-----------|--------|
| JS Payload in PDF | T1059.007 | JS Command Interpreter | Execution |
| Form Field Capture | T1056.003 | Web Portal Capture | Collection |
| Annotation Abuse | T1027 | Obfuscated Files | Defense Evasion |
| Embedded Executable | T1204.002 | Malicious File Execution | Execution |
| Launch Chain | T1218 | System Binary Proxy Execution | Defense Evasion |

### Link Manipulation

| Payload | MITRE ID | Technique | Tactic |
|---------|----------|-----------|--------|
| Homograph Domains | T1036 | Masquerading | Defense Evasion |
| RTLO Bypass | T1036.002 | Masquerading: Right-to-Left Override | Defense Evasion |
| Typosquatting | T1036 | Masquerading | Defense Evasion |
| XSS + Open Redirect | T1189 | Drive-by Compromise | Initial Access |
| Parameter Poisoning | T1190 | Exploit Public-Facing Application | Initial Access |

---

## Emerging Payload Technique Mapping

### Living-off-the-Land (LOLBins)

| Payload | MITRE ID | Technique | Tactic |
|---------|----------|-----------|--------|
| certutil download | T1105 | Ingress Tool Transfer | Command & Control |
| rundll32 exec | T1218.011 | Rundll32 Proxy Execution | Defense Evasion |
| mshta bypass | T1218.005 | Mshta Proxy Execution | Defense Evasion |
| cmstp UAC bypass | T1218.003 | CMSTP Proxy Execution | Defense Evasion |
| regsvcs/regasm | T1218.009 | Regsvcs/Regasm | Defense Evasion |

### Cloud & SaaS

| Payload | MITRE ID | Technique | Tactic |
|---------|----------|-----------|--------|
| SharePoint Link | T1566.002 | Spearphishing Link | Initial Access |
| Teams Injection | T1534 | Internal Spearphishing | Lateral Movement |
| Slack Bot Abuse | T1534 | Internal Spearphishing | Lateral Movement |
| Google Drive | T1566.002 | Spearphishing Link | Initial Access |
| S3 Exposure | T1552.005 | Unsecured Credentials: Cloud Instance Metadata | Collection |

### Mobile-First

| Payload | MITRE ID | Technique | Tactic |
|---------|----------|-----------|--------|
| Mobile Capture | T1056.003 | Web Portal Capture | Collection |
| SMS Bridge | T1598 | Phishing for Information | Reconnaissance |
| QR Execution | T1204.001 | Malicious Link | Execution |
| Fake Update | T1036 | Masquerading | Defense Evasion |

### Container & Orchestration

| Payload | MITRE ID | Technique | Tactic |
|---------|----------|-----------|--------|
| Container Escape | T1611 | Escape to Host | Privilege Escalation |
| K8s Manifest Injection | T1610 | Deploy Container | Defense Evasion |
| Registry Creds | T1552.007 | Container API | Collection |

### Supply Chain

| Payload | MITRE ID | Technique | Tactic |
|---------|----------|-----------|--------|
| Compromised Installer | T1195.002 | Supply Chain Compromise: Software | Initial Access |
| Package Poisoning | T1195.001 | Supply Chain Compromise: Dependencies | Initial Access |
| Dependency Injection | T1195.001 | Supply Chain Compromise: Dependencies | Initial Access |
| Fake Windows Update | T1036 | Masquerading | Defense Evasion |

### Authentication Bypass

| Payload | MITRE ID | Technique | Tactic |
|---------|----------|-----------|--------|
| NTLM Relay | T1557.001 | NTLM Relay | Collection |
| SSO Token Intercept | T1539 | Steal Web Session Cookie | Collection |
| OAuth Hijack | T1550.001 | Application Access Token | Defense Evasion |
| MFA Bypass | T1111 | MFA Interception | Collection |

---

## Tactic Coverage Summary

| Tactic | Number of Techniques Covered |
|--------|------------------------------|
| Initial Access | 12 |
| Execution | 10 |
| Persistence | 5 |
| Privilege Escalation | 2 |
| Defense Evasion | 15 |
| Collection | 12 |
| Command & Control | 4 |
| Exfiltration | 3 |
| Lateral Movement | 4 |
| Reconnaissance | 4 |

---

## Detection by Technique

| MITRE ID | Technique | Primary Detection Method |
|----------|-----------|--------------------------|
| T1566.001 | Spearphishing Attachment | Email gateway scanning, attachment analysis |
| T1566.002 | Spearphishing Link | URL reputation, link analysis |
| T1204.002 | Malicious File Execution | EDR, process monitoring |
| T1059.001 | PowerShell | Script block logging, event monitoring |
| T1059.003 | Windows Command Shell | Process monitoring, Event ID 4688 |
| T1059.005 | VBScript | AMSI, macro scanning |
| T1056.003 | Web Portal Capture | Network traffic analysis |
| T1185 | Browser Session Hijacking | Browser telemetry, SOC monitoring |
| T1187 | Forced Authentication | Network traffic analysis (SMB) |
| T1218.005 | Mshta | Process monitoring for mshta.exe |
| T1218.011 | Rundll32 | Process monitoring for rundll32.exe |
| T1566 | Phishing | Email security, user reporting |

---

*For detailed MITRE ATT&CK technique descriptions, see [MITRE_REFERENCE.md](MITRE_REFERENCE.md)*  
*For structured JSON data, see [../data/payload-techniques.json](../data/payload-techniques.json)*
