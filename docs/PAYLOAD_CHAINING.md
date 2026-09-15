# Payload Chaining Guide

> **⚠️ DISCLAIMER**: This documentation is for **educational and research purposes ONLY**.
> All techniques described are for understanding attack patterns and improving defensive capabilities.
> Do not use these techniques without explicit written authorization. The authors bear no responsibility for misuse.

---

## Overview

Payload chaining combines multiple social engineering techniques into multi-stage attack sequences
that are more effective and harder to detect than single-stage attacks. Each stage builds on the
previous to escalate access, exfiltrate data, or maintain persistence.

This document provides:
- Visual ASCII flowcharts for 8 attack chains
- Step-by-step explanations
- Mapping to existing payloads in this repository
- MITRE ATT&CK technique references
- Detection and mitigation strategies

---

## Table of Contents

1. [Initial Access → Credential Theft → Persistence Chain](#chain-1)
2. [Email Phishing → Multi-Format Fallback Chain](#chain-2)
3. [PDF → Web Exploitation → C2 Communication Chain](#chain-3)
4. [Office Macro Cascade Chain](#chain-4)
5. [Credential Harvesting → Impersonation → Lateral Movement Chain](#chain-5)
6. [Multi-Layer Social Engineering Chain](#chain-6)
7. [Browser-Based Persistent Foothold Chain](#chain-7)
8. [Repository-Based Supply Chain Attack Chain](#chain-8)

---

<a name="chain-1"></a>
## Chain 1: Initial Access → Credential Theft → Persistence

### Overview
This chain establishes initial access via a document-based payload, harvests credentials,
then establishes persistence mechanisms for long-term access.

### Flowchart

```
[Attacker]
    |
    v
[Craft DDE Payload]
    |
    +-- CSV (.csv) --------+
    +-- Excel (.xls) ------+  (Stage 1: Delivery)
    +-- Word (.docx) ------+
    |
    v
[Send via Spear-Phishing Email]
    |  MITRE: T1566.001
    v
[Target Opens Document]
    |
    v
[DDE Execution Prompt] ---------> [User Clicks "Yes"] 
    |                                      |
    v                                      v
[User Clicks "No"] -----> [FAIL]   [Command Executes]
                                          |
                          +--------------+---------------+
                          |                              |
                          v                              v
              [Download Credential Harvester]   [Launch Fake Login Page]
              MITRE: T1105                      MITRE: T1056.003
                          |                              |
                          v                              v
              [Capture Domain Credentials]   [Capture Web Credentials]
              MITRE: T1003                   MITRE: T1539
                          |                              |
                          +--------------+---------------+
                                         |
                                         v
                              [Validate Stolen Credentials]
                              MITRE: T1078
                                         |
                              +----------+----------+
                              |                     |
                              v                     v
                   [Create Backdoor Account]  [Schedule Task]
                   MITRE: T1136              MITRE: T1053.005
                              |                     |
                              +-----------+---------+
                                          |
                                          v
                               [Persistence Established]
                               MITRE: T1547
```

### Stage Details

#### Stage 1: Initial Delivery
- **Payload Used**: `DDE based social engineering csv payload/` or `DDE based social engineering xls payload/`
- **Technique**: Spear-phishing with DDE-enabled document
- **MITRE**: T1566.001 (Phishing: Spearphishing Attachment)
- **Evasion**: File appears as legitimate spreadsheet data

#### Stage 2: Execution
- **Payload Used**: DDE command execution via document field
- **Technique**: User is prompted to update field data (DDE mechanism)
- **MITRE**: T1204.002 (User Execution: Malicious File)
- **Detection Point**: Application-level prompt monitoring

#### Stage 3: Credential Harvesting
- **Payload Used**: `Steal credentials using fake excel doc/` or `Steal credential using a word document/`
- **Technique**: Fake login page served locally or via remote URL
- **MITRE**: T1056.003 (Input Capture: Web Portal Capture)
- **Evasion**: Mimics legitimate enterprise login portal

#### Stage 4: Persistence
- **Technique**: Scheduled task or registry run key creation
- **MITRE**: T1053.005 (Scheduled Task/Job: Scheduled Task)
- **Detection**: Process creation monitoring, registry auditing

### Detection Opportunities
| Stage | Detection Method | Log Source |
|-------|-----------------|------------|
| Delivery | Email filtering, attachment scanning | Mail gateway logs |
| Execution | DDE prompt monitoring | Application event logs |
| Harvesting | Network traffic to fake login | Proxy/firewall logs |
| Persistence | Scheduled task creation | Windows Security Event 4698 |

### Mitigations
- Disable DDE in Office via Group Policy
- Enable Protected View for email attachments
- Deploy MFA to reduce credential theft impact
- Monitor for abnormal scheduled task creation

---

<a name="chain-2"></a>
## Chain 2: Email Phishing → Multi-Format Fallback Chain

### Overview
Attacker sends emails with multiple attachment types as fallbacks—if one format is blocked or
detected, others serve as backup delivery mechanisms.

### Flowchart

```
[Attacker Prepares Multi-Format Campaign]
    |
    +--[CSV Attachment]----+
    +--[XLS Attachment]----+
    +--[DOCX Attachment]---+  All embedded in single email
    +--[MSG Attachment]----+
    +--[Malicious Link]----+
    |
    v
[Phishing Email Sent]
MITRE: T1566.001 / T1566.002
    |
    v
[Email Gateway Scan]
    |
    +--[CSV blocked?]--NO-->  [Target opens CSV]  --> [DDE Executes]
    |                                                         |
    +--[XLS blocked?]--NO-->  [Target opens XLS]  --> [DDE Executes]
    |                                                         |
    +--[DOCX blocked?]--NO--> [Target opens DOCX] --> [DDE Executes]
    |                                                         |
    +--[All blocked?]--YES--> [Link in body]      --> [Browser Opens]
                              MITRE: T1566.002           |
                                                         v
                                                [Tabnabbing / Credential Page]
                                                MITRE: T1056.003
                                                         |
                              +--------------------------+
                              |
                              v
                   [Credentials Captured]
                   MITRE: T1078
```

### Stage Details

#### Stage 1: Multi-Format Preparation
- **Payloads Used**: All DDE variants (csv, xls, docx, slk, msg)
- **Strategy**: Include multiple formats targeting different applications
- **MITRE**: T1566.001

#### Stage 2: Fallback Link
- **Payload Used**: `Link manipulation attack/` or `Tabnabbing attack/`
- **Strategy**: If all attachments fail, embedded hyperlink is final fallback
- **MITRE**: T1566.002 (Phishing: Spearphishing Link)

#### Stage 3: Tabnabbing
- **Payload Used**: `Tabnabbing attack/`
- **Technique**: Opens in background tab, waits for user to return
- **MITRE**: T1185 (Browser Session Hijacking)

### Detection Opportunities
- Emails with multiple suspicious attachment types
- Attachment scanning for DDE fields
- Link analysis for redirect chains
- Browser process monitoring

### Mitigations
- Block macro-enabled Office documents at email gateway
- Enable Protected View by default
- User awareness training on multi-vector phishing
- Deploy email link scanning

---

<a name="chain-3"></a>
## Chain 3: PDF → Web Exploitation → C2 Communication

### Overview
PDF with malicious URL initiates a chain from document to web exploitation to command-and-control
communication establishment.

### Flowchart

```
[Attacker]
    |
    v
[Craft Malicious PDF]
MITRE: T1566.001
    |
    +-- Embedded JavaScript
    +-- Malicious URL in body
    +-- Launch action
    |
    v
[Target Opens PDF]
MITRE: T1204.002
    |
    v
[PDF Renders URL / Executes JS]
    |
    +--[JavaScript Enabled?]--YES--> [Execute embedded JS]
    |                                        |
    +--[JavaScript Disabled?]--NO--> [User clicks link]
                                             |
                              +--------------+
                              |
                              v
                   [Browser Opens Attacker URL]
                   MITRE: T1189 (Drive-by Compromise)
                              |
                              v
                   [Malicious Web Page Loads]
                              |
              +---------------+---------------+
              |                               |
              v                               v
   [Browser Exploit Attempt]      [Fake Login Page]
   MITRE: T1203                   MITRE: T1056.003
              |                               |
              v                               v
   [Code Execution Achieved]     [Credentials Harvested]
              |                               |
              +--------------+----------------+
                             |
                             v
                  [Download C2 Agent / Implant]
                  MITRE: T1105
                             |
                             v
                  [Establish C2 Channel]
                  MITRE: T1571
                             |
              +--------------+---------------+
              |              |               |
              v              v               v
    [HTTP/S Beacon]  [DNS Tunneling]  [WebSocket C2]
    MITRE: T1071.001 MITRE: T1071.004 MITRE: T1102
```

### Stage Details

#### Stage 1: PDF Delivery
- **Payload Used**: `PDF with malicious URL/`
- **Technique**: PDF with embedded URL or JavaScript
- **MITRE**: T1566.001
- **Evasion**: PDF appears legitimate (financial document, invoice)

#### Stage 2: Web Exploitation
- **Technique**: Landing page attempts browser exploitation
- **MITRE**: T1189 (Drive-by Compromise), T1203 (Exploitation for Client Execution)

#### Stage 3: C2 Establishment
- **Technique**: Downloaded implant establishes command channel
- **MITRE**: T1071 (Application Layer Protocol), T1105 (Ingress Tool Transfer)

### Detection Opportunities
- PDF metadata analysis for embedded URLs
- JavaScript in PDF files
- Unusual outbound connections post-document-open
- DNS query anomalies

### Mitigations
- Disable JavaScript in PDF readers
- Deploy HTTPS inspection
- Block direct outbound connections from PDF reader processes
- Monitor for process injection post-PDF open

---

<a name="chain-4"></a>
## Chain 4: Office Macro Cascade Chain

### Overview
Layered Office macro execution using multiple document types in sequence, with each stage
downloading and executing the next.

### Flowchart

```
[Stage 0: Delivery]
    |
    v
[Password-Protected Document Email]
MITRE: T1566.001
    |  (Password provided in email body to bypass scanning)
    v
[Target Opens Document & Enters Password]
MITRE: T1204.002
    |
    v
[Stage 1: Macro Loader Document]
    |  MITRE: T1059.005 (Visual Basic)
    +-- Minimal macro (evades signature detection)
    +-- Downloads Stage 2 document
    |
    v
[Stage 2: Dropper Document Downloaded]
MITRE: T1105
    |  (Appears as legitimate template update)
    v
[Stage 2 Macro Executes]
MITRE: T1059.005
    |
    +-- Disables macro security settings
    +-- Downloads payload executable
    +-- Creates scheduled task
    |
    v
[Stage 3: Payload Execution]
MITRE: T1204.002
    |
    +--[Credential Harvester]---> [Send to C2]
    +--[Keylogger]-------------> [Exfiltrate via HTTPS]
    +--[Reverse Shell]---------> [Connect to C2 Server]
    |
    v
[Persistent Access Established]
MITRE: T1547
```

### Stage Details

#### Stage 0: Delivery
- **Payload Used**: `Password protected document/`
- **Strategy**: Password prevents automated scanning
- **MITRE**: T1566.001, T1027 (Obfuscated Files)
- **Detection Evasion**: Most email scanners cannot read password-protected archives

#### Stage 1: Macro Loader
- **Technique**: Minimal VBA that only downloads Stage 2
- **MITRE**: T1059.005 (Command and Scripting Interpreter: Visual Basic)
- **Evasion**: Small footprint avoids behavioral detection

#### Stage 2: Dropper
- **Technique**: Full macro with persistence mechanisms
- **MITRE**: T1059.005, T1547 (Boot or Logon Autostart Execution)

#### Stage 3: Payload
- **Technique**: Final executable or script
- **MITRE**: T1059 (Command and Scripting Interpreter)

### Detection Opportunities
| Layer | Detection Method |
|-------|-----------------|
| Email | Password-protected attachment heuristics |
| Stage 1 | Network connection from Office process |
| Stage 2 | Macro downloading executables |
| Stage 3 | Unusual process spawned from Office |

### Mitigations
- Disable macros in Office via Group Policy (HKCU settings)
- Enable Attack Surface Reduction rules in Windows Defender
- Monitor for WINWORD.EXE spawning child processes
- Deploy Application Whitelisting

---

<a name="chain-5"></a>
## Chain 5: Credential Harvesting → Impersonation → Lateral Movement

### Overview
Combines credential theft techniques to harvest credentials, then uses them to impersonate
legitimate users for lateral movement across the network.

### Flowchart

```
[Phase 1: Intelligence Gathering]
    |
    +-- LinkedIn/OSINT: identify target employees
    +-- Email header analysis: identify internal domains
    +-- Enumerate public resources
    |
    v
[Phase 2: Initial Credential Theft]
    |
    +--[Method A: Fake Excel Login]-------+
    |  MITRE: T1056.003                  |
    |  Payload: Steal credentials fake   |
    |  excel doc/                        |
    +--[Method B: Basic Auth Pop-up]-----+
    |  MITRE: T1056.003                  |
    |  Payload: Steal credential word    |
    |  document basic auth/              |
    +--[Method C: Tabnabbing]------------+
       MITRE: T1185
       Payload: Tabnabbing attack/
                                         |
                                         v
                              [Credentials Obtained]
                              MITRE: T1078
                                         |
                                         v
                              [Validate Credentials]
                              (Test against login portals)
                                         |
                              +----------+----------+
                              |                     |
                              v                     v
                    [VPN/Citrix Access]    [Email Access (OWA)]
                    MITRE: T1078          MITRE: T1078.002
                              |                     |
                              v                     v
                    [Internal Network]    [Internal Email]
                    Access Gained         Access Gained
                              |                     |
                              +-----------+---------+
                                          |
                                          v
                               [Phase 3: Lateral Movement]
                                          |
                              +-----------+-----------+
                              |           |           |
                              v           v           v
                    [Pass-the-Hash]  [WMI Exec]  [Send Internal
                    MITRE: T1550.002 MITRE:       Phishing]
                                     T1047        MITRE: T1534
```

### Stage Details

#### Phase 1: OSINT/Reconnaissance
- **Technique**: Open source intelligence gathering
- **MITRE**: T1598 (Phishing for Information), T1591 (Gather Victim Org Information)

#### Phase 2: Credential Theft
- **Payloads Used**: 
  - `Steal credentials using fake excel doc/`
  - `Steal credential using a word document which pop for basic authentication/`
  - `Tabnabbing attack/`
- **MITRE**: T1056.003, T1185

#### Phase 3: Lateral Movement
- **Technique**: Use stolen credentials to access internal systems
- **MITRE**: T1550, T1534 (Internal Spearphishing)

### Detection Opportunities
- Multiple failed authentication attempts
- Logins from unusual geographic locations or times
- Internal emails with phishing characteristics
- Lateral movement via WMI or SMB

### Mitigations
- Implement MFA on all externally accessible services
- Network segmentation to limit lateral movement
- Privileged Access Workstations (PAW)
- User Entity Behavior Analytics (UEBA)

---

<a name="chain-6"></a>
## Chain 6: Multi-Layer Social Engineering Chain

### Overview
Combines technical payloads with psychological manipulation techniques across multiple
communication channels for a coordinated attack.

### Flowchart

```
[Pre-attack: Establish Trust]
    |
    +-- Create fake LinkedIn profile of IT support
    +-- Send connection requests to targets
    +-- Engage in 2-3 weeks of normal interaction
    |
    v
[Layer 1: Phone Vishing]
MITRE: T1598.004
    |  "Hi, this is IT support. We detected suspicious activity
    |   on your account. I'm sending you a verification link now."
    v
[Layer 2: Email (Spear-Phishing)]
MITRE: T1566.001
    |
    +-- Professional template matching internal comms style
    +-- Reference to phone call ("as I mentioned...")
    +-- Password-protected attachment
    |  Payload: Password protected document/
    v
[Target Opens Attachment]
MITRE: T1204.002
    |
    v
[Layer 3: DDE Execution / Fake Login]
    |
    +--[DDE triggers download]---------> [Malware installed]
    |  Payload: DDE csv/xls/docx        MITRE: T1105
    |
    +--[Fake Login Popup]--------------> [Credentials stolen]
       Payload: Steal credentials        MITRE: T1056.003
       fake excel/
    |
    v
[Layer 4: SMS Follow-up]
MITRE: T1598
    "Your verification was successful. Your account is now secure."
    (Builds trust, reduces suspicion)
    |
    v
[Persistence + Exfiltration Begins]
MITRE: T1020, T1547
```

### Social Engineering Psychology
This chain exploits:
1. **Authority** - Attacker poses as IT support
2. **Urgency** - "Suspicious activity detected" creates panic
3. **Social Proof** - LinkedIn connection validates identity
4. **Reciprocity** - Phone call builds trust before email
5. **Commitment** - Once engaged by phone, target more likely to open email

### Detection Opportunities
- Vishing often logged by call center security
- Unusual LinkedIn connections with internal staff
- Multi-channel phishing patterns in SIEM
- User reports of unexpected IT calls

### Mitigations
- Out-of-band verification for IT support requests
- Security awareness training on multi-channel attacks
- Clear IT support contact verification procedures
- Report suspicious contact channels

---

<a name="chain-7"></a>
## Chain 7: Browser-Based Persistent Foothold Chain

### Overview
Uses web-based payloads to establish a persistent foothold in the browser, enabling
long-term access to credentials and browsing data.

### Flowchart

```
[Stage 1: Initial Browser Compromise]
    |
    +--[Tabnabbing Attack]
    |  MITRE: T1185
    |  Payload: Tabnabbing attack/
    |
    +--[Link Manipulation]
    |  MITRE: T1204.001
    |  Payload: Link manipulation attack/
    |
    v
[Stage 2: Browser Extension Installation]
MITRE: T1176
    |  User tricked into installing "security" extension
    v
[Extension Persists in Browser]
    |
    +-- Read all browsing data      MITRE: T1217
    +-- Intercept form submissions  MITRE: T1056.004
    +-- Modify page content         MITRE: T1185
    +-- Redirect searches           MITRE: T1608.004
    |
    v
[Stage 3: Credential Collection]
MITRE: T1539
    |
    +-- Banking credentials
    +-- Corporate SSO tokens
    +-- Session cookies
    +-- Password manager access
    |
    v
[Stage 4: Exfiltration via Extension]
MITRE: T1041
    |  Extension sends data to attacker-controlled server
    v
[Persistent Long-Term Access]
    |
    +-- Maintain access even after password reset
    +-- Monitor for new credential entry
    +-- Serve targeted ads / phishing content
```

### Stage Details

#### Stage 1: Initial Compromise
- **Payloads Used**: `Tabnabbing attack/`, `Link manipulation attack/`
- **MITRE**: T1185 (Browser Session Hijacking), T1204.001

#### Stage 2: Extension Persistence  
- **Technique**: Malicious browser extension auto-installed or social engineered
- **MITRE**: T1176 (Browser Extensions)
- **Evasion**: Extension appears legitimate (ad blocker, security tool)

#### Stage 3: Collection
- **MITRE**: T1539 (Steal Web Session Cookie), T1056.004 (Credential API Hooking)

### Detection Opportunities
- Unusual browser extension installations
- Browser process making unexpected network connections
- Content Security Policy violations
- Certificate pinning failures

### Mitigations
- Whitelist approved browser extensions via policy
- Monitor browser extension installations
- Use browser isolation technology
- Deploy endpoint detection for browser process behavior

---

<a name="chain-8"></a>
## Chain 8: Repository-Based Supply Chain Attack

### Overview
Compromises software distribution channels to deliver payloads to large numbers of targets
through trusted software repositories or update mechanisms.

### Flowchart

```
[Stage 1: Repository Reconnaissance]
    |
    +-- Identify popular open-source packages
    +-- Find packages with weak maintainer security
    +-- Identify corporate dependencies
    |
    v
[Stage 2: Repository Compromise]
MITRE: T1195.001
    |
    +--[Account Takeover]----------> [Push malicious update]
    |  MITRE: T1078               |
    |                              |
    +--[Typosquatting]-----------> [Wait for installs]
    |  MITRE: T1608.001           |
    |                              |
    +--[Dependency Confusion]----> [Malicious internal package]
       MITRE: T1195.001           |
                                   |
                                   v
                        [Targets Install Package]
                        MITRE: T1195.001
                                   |
                                   v
                        [Malicious Code Executes]
                        MITRE: T1059
                                   |
                        +----------+----------+
                        |          |          |
                        v          v          v
              [Credential   [Backdoor    [Data
              Theft]         Install]     Exfiltration]
              T1552          T1547        T1020
                        |          |          |
                        +-----------+---------+
                                    |
                                    v
                         [Widespread Compromise]
                         (All consumers of package affected)
```

### Stage Details

#### Stage 1: Target Selection
- **Technique**: Identify high-value packages with large user bases
- **MITRE**: T1592 (Gather Victim Host Information)

#### Stage 2: Compromise Methods
- **Account Takeover**: Phish maintainer credentials
  - MITRE: T1566 → T1078
- **Typosquatting**: Register similar package names
  - MITRE: T1608.001 (Stage Capabilities: Upload Malware)
- **Dependency Confusion**: Upload package matching internal name
  - MITRE: T1195.001 (Supply Chain Compromise: Compromise Software Dependencies)

#### Stage 3: Payload Delivery
- **Technique**: install/postinstall scripts execute malicious code
- **MITRE**: T1195.001, T1059

### Detection Opportunities
- Package integrity verification (checksums, signatures)
- Behavioral monitoring of package install scripts
- Network connections from package manager processes
- Code review of third-party dependencies

### Mitigations
- Use package signing and verification
- Pin dependency versions in production
- Implement Software Composition Analysis (SCA)
- Monitor for dependency confusion indicators
- Private package registries with access control

---

## Summary: Attack Chain MITRE Mapping

| Chain | Primary Techniques | Tactics Covered |
|-------|-------------------|-----------------|
| Chain 1: Initial Access → Persistence | T1566.001, T1204.002, T1056.003, T1078, T1053.005 | Initial Access, Execution, Persistence, Collection |
| Chain 2: Multi-Format Phishing | T1566.001, T1566.002, T1185, T1056.003 | Initial Access, Collection |
| Chain 3: PDF → C2 | T1566.001, T1189, T1203, T1105, T1071 | Initial Access, Execution, Command & Control |
| Chain 4: Office Macro Cascade | T1566.001, T1059.005, T1105, T1547 | Initial Access, Execution, Persistence |
| Chain 5: Credential → Lateral Movement | T1598, T1056.003, T1078, T1550, T1534 | Reconnaissance, Collection, Lateral Movement |
| Chain 6: Multi-Layer SE | T1598.004, T1566.001, T1204.002, T1056.003, T1020 | Reconnaissance, Initial Access, Collection, Exfiltration |
| Chain 7: Browser Persistence | T1185, T1176, T1539, T1056.004, T1041 | Collection, Persistence, Exfiltration |
| Chain 8: Supply Chain | T1195.001, T1078, T1608.001, T1059, T1020 | Initial Access, Execution, Exfiltration |

---

## General Detection Recommendations

1. **Email Security Gateway**: Scan all attachments; block DDE-enabled Office files
2. **Endpoint Detection & Response (EDR)**: Monitor process chains from Office applications
3. **Security Information & Event Management (SIEM)**: Correlate multi-stage attack indicators
4. **User & Entity Behavior Analytics (UEBA)**: Detect unusual access patterns
5. **Network Traffic Analysis (NTA)**: Identify C2 communication patterns
6. **Security Awareness Training**: Educate users on multi-channel social engineering

## General Mitigation Recommendations

1. **Patch Management**: Keep all software updated
2. **Principle of Least Privilege**: Limit user permissions
3. **Network Segmentation**: Limit lateral movement potential
4. **Multi-Factor Authentication**: Protect all externally accessible services
5. **Backup & Recovery**: Ensure resilience against ransomware
6. **Incident Response Plan**: Have documented response procedures

---

*Reference: [MITRE ATT&CK Framework](https://attack.mitre.org/)*
