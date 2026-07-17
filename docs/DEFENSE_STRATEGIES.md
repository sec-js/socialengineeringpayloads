# Defense Strategies

> **⚠️ DISCLAIMER**: This document is for **defensive security purposes**.
> All strategies are designed to help organizations protect against social engineering attacks.

---

## Overview

This document provides comprehensive defense strategies for all payload types covered in this
repository. Effective defense requires a layered approach — no single control is sufficient.

**Defense-in-Depth Model**:
```
[Prevention] → [Detection] → [Response] → [Recovery]
```

---

## Defensive Framework

### 1. Email Security

Email remains the primary delivery vector for all social engineering payloads.

#### Technical Controls

| Control | Payloads Protected Against | Implementation |
|---------|---------------------------|----------------|
| DMARC/DKIM/SPF | Spoofed sender addresses | DNS records + email gateway |
| Attachment sandboxing | DDE, Macros, LNK, PDF | Email gateway policy |
| URL rewriting + click-time scan | Malicious links | Safe Links (M365), Proofpoint |
| Attachment blocking by type | .lnk, .hta, .vbs | Email gateway block list |
| Anti-phishing ML models | All phishing | Exchange ATP, Proofpoint |
| Internal DMARC enforcement | Internal impersonation | Exchange transport rules |

#### Email Security Architecture
```
Internet Email
     |
     v
[Email Gateway / SEG]
     |
     +-- Reputation check (IP, domain, URL)
     +-- Attachment analysis (type, content)
     +-- Sandbox detonation (suspicious files)
     +-- DLP scanning (data exfiltration)
     +-- DMARC/DKIM/SPF validation
     |
     v
[Microsoft Defender for Office 365 / Proofpoint]
     |
     +-- Safe Links (time-of-click URL scanning)
     +-- Safe Attachments (async sandbox)
     +-- Anti-phishing (impersonation detection)
     |
     v
[Mailbox]
```

#### Configuration Recommendations
```
# Exchange Online Protection example settings
- Anti-phishing: Enable impersonation protection for key executives
- Safe Links: Enable "Do not allow users to click through to original URL"
- Safe Attachments: "Dynamic Delivery" mode (delivers message, checks attachment)
- Anti-spam: Set bulk complaint threshold to 6 or lower
```

---

### 2. Endpoint Protection

#### Defense Against DDE Payloads (P01-P05)

**Registry Configurations**:
```
# Disable DDE in Word
HKCU\Software\Microsoft\Office\<version>\Word\Security\AllowDDE = 0

# Disable DDE in Excel  
HKCU\Software\Microsoft\Office\<version>\Excel\Security\AllowDDE = 0

# Disable DDE in Outlook
HKCU\Software\Microsoft\Office\<version>\Outlook\Options\Mail\UseNoDde = 1
```

**Group Policy**:
```
Computer Configuration → Administrative Templates → Microsoft Office
→ Enable "Block DDE" for all Office applications
→ Enable Protected View for files from the internet
→ Enable Protected View for Outlook attachments
```

**Attack Surface Reduction Rules** (Windows Defender):
```powershell
# Enable key ASR rules
Set-MpPreference -AttackSurfaceReductionRules_Ids `
  "3b576869-a4ec-4529-8536-b80a7769e899","75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",`
  "d4f940ab-401b-4efc-aadc-ad5f3c50688a" `
  -AttackSurfaceReductionRules_Actions Enabled,Enabled,Enabled

# Key rules:
# 3b576869: Block Office apps from creating child processes
# 75668c1f: Block Office apps from injecting into other processes
# d4f940ab: Block Office apps from creating executable content
```

---

#### Defense Against Macro Payloads (P06, P07)

**Disable Macros**:
```
Group Policy → Office 2016 Policies → 
  Security → Trust Center →
    "Disable all macros without notification" for untrusted locations
```

**VBA Stamping** (trusted document control):
```
Only allow macros from:
- Digitally signed macros from trusted publishers
- Macros from specific trusted locations
```

**AMSI for Office** (Windows 10+):
- AMSI integration scans VBA code before execution
- Enabled by default in modern Office + Windows 10 combinations

---

#### Defense Against LNK Payloads (P15)

```
# Block .lnk files in email (exchange rule)
New-TransportRule -Name "Block LNK Attachments" `
  -AttachmentNameMatchesPatterns "*.lnk","*.url","*.hta","*.vbs" `
  -DeleteMessage:$true

# Monitor mshta.exe execution
Get-WinEvent -FilterHashtable @{LogName="Microsoft-Windows-Sysmon/Operational"; Id=1} |
  Where-Object {$_.Message -match "mshta.exe"} | Format-List
```

---

### 3. Credential Protection

#### Defense Against Credential Harvesting (P12, P13)

**Multi-Factor Authentication**:
```
Priority order (strongest to weakest):
1. FIDO2/Hardware Security Keys (not vulnerable to phishing)
2. Microsoft Authenticator (number matching, additional context)
3. Time-based OTP (TOTP) - authenticator apps
4. Push notifications (vulnerable to MFA fatigue)
5. SMS OTP (weakest - vulnerable to SIM swap)
```

**Conditional Access Policies**:
```json
{
  "policy": "Require MFA for all users",
  "conditions": {
    "users": "all",
    "applications": "all",
    "locations": "any"
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["mfa"]
  }
}
```

**Password Policies**:
```
- Minimum length: 12+ characters
- No complexity rules (increases reuse of weak passwords)
- Block known breached passwords (Azure AD Password Protection)
- Enable SSPR with MFA
```

**Network Controls for NTLM Capture (P13)**:
```powershell
# Block outbound SMB at firewall (port 445, 139)
# Group Policy: Network security: Restrict NTLM
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" `
  -Name "RestrictSendingNTLMTraffic" -Value 2  # Deny all NTLM to remote servers
```

---

#### Defense Against Tabnabbing (P14)

**Browser Policies**:
```
- Deploy uBlock Origin or similar content blocker
- Configure browser via policy: block cross-origin navigation in background tabs
- CSP headers on internal web applications
```

**User Training**:
```
Train users to:
1. Check the URL before entering credentials
2. Use password managers (auto-fill only on correct domain)
3. Report suspicious login prompts
```

**Password Manager as Defense**:
Password managers auto-fill only on the exact domain they recorded the password for.
Tabnabbing to a fake domain will not auto-fill, alerting the user to the discrepancy.

---

### 4. Browser Security

#### Defense Against Browser-Based Attacks

**Extension Management**:
```
# Chrome Enterprise Policy
"ExtensionInstallBlocklist": ["*"],
"ExtensionInstallAllowlist": ["specific-approved-extension-id"]
"ExtensionInstallForcelist": ["managed-extension-id"]
```

**Content Security Policy**:
```http
Content-Security-Policy: default-src 'self'; script-src 'self'; frame-ancestors 'none'
```

**Browser Isolation**:
- Remote Browser Isolation (RBI) for high-risk browsing
- Microsoft Defender Application Guard for Edge

---

### 5. Network Controls

#### Perimeter Firewall

```
Required outbound blocks:
- Port 445/139: SMB (prevents NTLM hash capture)
- Port 135: RPC (remote execution prevention)

Monitor outbound:
- Port 443: All HTTPS (inspect if possible)
- Port 80: HTTP (inspect)
- Port 53: DNS (monitor for tunneling)
```

#### DNS Filtering
```
Recommended blocklists:
- Malware domains (Spamhaus, abuse.ch)
- Newly registered domains (< 30 days old)
- DGA (Domain Generation Algorithm) patterns
- Known phishing domains

Tools:
- Cisco Umbrella
- Cloudflare Gateway
- Pi-hole with custom blocklists
```

#### Web Proxy

```
Category blocks:
- Newly observed domains (24-48hr hold)
- Dynamic DNS services
- URL shortener expansion
- Free hosting platforms (limited)
```

---

### 6. Detection Engineering

#### SIEM Detection Rules

**DDE Execution**:
```
Event: Process Creation (Event ID 4688 / Sysmon Event ID 1)
Condition: ParentProcess = EXCEL.EXE OR WINWORD.EXE
AND ChildProcess = cmd.exe OR powershell.exe OR mshta.exe
Action: High severity alert
```

**Credential Page Submission**:
```
Event: HTTP POST to external domain
Source: Endpoint browser process
Destination: Non-corporate domain
Data: Contains form data with password fields
Action: Medium severity alert → Investigate
```

**Unusual Network from Office**:
```
Event: Network connection (Sysmon Event ID 3)
Condition: ProcessName = WINWORD.EXE OR EXCEL.EXE
AND DestinationPort ≠ 80 AND DestinationPort ≠ 443
AND DestinationIP is external
Action: High severity alert
```

**NTLM to External Host**:
```
Event: Network connection on port 445
Condition: Source = Internal workstation
AND Destination = External IP
Action: High severity alert (NTLM hash capture attempt)
```

---

### 7. User Awareness Training

#### Training Program Elements

**Tier 1: All Employees**
- Email phishing recognition
- Link verification techniques
- MFA importance and usage
- Reporting procedures
- Password hygiene

**Tier 2: High-Risk Roles** (executives, finance, HR, IT)
- Spear-phishing recognition
- Voice phishing (vishing) awareness
- Business Email Compromise (BEC) scenarios
- Financial transfer verification procedures

**Tier 3: IT/Security Staff**
- Advanced technical payload recognition
- Incident response procedures
- Threat hunting concepts
- Security monitoring awareness

#### Phishing Simulation Program

```
Frequency: Monthly for all users
Escalation:
  - 1 click: Educational landing page
  - 2 clicks in 3 months: Mandatory training
  - 3 clicks in 3 months: Manager notification + mandatory 1:1 training
  
Metrics:
  - Click rate (goal: < 5%)
  - Report rate (goal: > 20% of simulations reported)
  - Credential submission rate (goal: 0%)
```

---

### 8. Incident Response

#### Phishing Incident Playbook

```
1. DETECTION (0-15 min)
   - User reports suspicious email
   - Automated alert from email gateway
   
2. TRIAGE (15-60 min)
   - Collect email headers and artifacts
   - Determine scope: how many users received it?
   - Determine if anyone clicked/opened
   
3. CONTAINMENT (1-4 hours)
   - Remove email from all mailboxes
   - Block sender/domain at gateway
   - Block malicious URLs/IPs
   - Isolate affected endpoints if execution confirmed
   
4. INVESTIGATION (4-24 hours)
   - Analyze payload (sandbox)
   - Review endpoint logs for execution indicators
   - Check for lateral movement
   - Review credential usage anomalies
   
5. REMEDIATION (24-72 hours)
   - Reset affected user credentials
   - Revoke and reissue OAuth tokens
   - Patch any exploited vulnerabilities
   - Update security controls
   
6. POST-INCIDENT (1-2 weeks)
   - Root cause analysis
   - Lessons learned documentation
   - Update detection rules
   - Update training program
```

---

## Defense Effectiveness by Payload Type

| Payload | Email Filter | Endpoint AV | EDR | Network | User Training |
|---------|-------------|------------|-----|---------|---------------|
| DDE Payloads | Medium | Low | High | Low | Medium |
| Macros | Medium | Medium | High | Low | Medium |
| Credential Pages | Medium | None | Low | Medium | High |
| LNK Payloads | High (if blocking) | Medium | High | Low | Medium |
| PDF Malicious URL | Medium | Low | Low | High | High |
| Tabnabbing | Low | None | None | Low | High |
| Link Manipulation | High | None | None | High | High |

**Key Insight**: Most payloads have gaps in at least one control. User training has
high effectiveness across multiple payload types, making it a critical investment.

---

## Security Tool Recommendations

| Category | Commercial Options | Open Source Options |
|----------|-------------------|---------------------|
| Email Security | Proofpoint, Mimecast | SpamAssassin |
| EDR | CrowdStrike, SentinelOne | Wazuh, Velociraptor |
| SIEM | Splunk, Microsoft Sentinel | Elastic SIEM, Graylog |
| DNS Filtering | Cisco Umbrella, ZScaler | Pi-hole, Blocky |
| Web Proxy | Symantec, Palo Alto | Squid |
| Phishing Sim | KnowBe4, Proofpoint | GoPhish |
| Sandbox | Joe Sandbox, Cuckoo | Cuckoo Sandbox |

---

*See [DETECTION_EVASION.md](DETECTION_EVASION.md) for understanding attacker evasion techniques*  
*See [TECHNIQUE_MAPPING.md](TECHNIQUE_MAPPING.md) for MITRE ATT&CK control mappings*
