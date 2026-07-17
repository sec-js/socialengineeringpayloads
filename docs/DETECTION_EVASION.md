# Detection Evasion Techniques

> **⚠️ DISCLAIMER**: This document is for **educational and defensive research purposes ONLY**.
> This information helps security teams understand attacker evasion techniques to build
> better detections. Do not use these techniques without explicit authorization.

---

## Overview

Understanding how attackers evade detection allows defenders to:
1. Tune security controls to detect evasion attempts
2. Prioritize behavioral detection over signature-based detection
3. Understand limitations of current security tooling
4. Build more resilient detection pipelines

---

## 1. Email Security Evasion

### Bypassing Attachment Scanning

#### Password-Protected Files
- **Technique**: ZIP, RAR, or Office documents with password
- **Bypass**: Email scanners cannot decrypt and inspect content
- **Tell**: Password often included in email body (indicator!)
- **Detection**: Flag password-protected attachments, especially from external senders
- **Payloads**: `Password protected document/`

#### Unusual File Formats
- **Technique**: Use SLK, MHT, RTF, SYLK instead of common DOCX/XLS
- **Bypass**: Some scanners only handle common formats
- **Detection**: Flag unusual document formats from external email
- **Payloads**: `DDE based social engineering slk payload/`

#### Container Format Nesting
- **Technique**: ZIP > ISO > LNK (multiple layers)
- **Bypass**: Some scanners don't recursively inspect nested containers
- **Detection**: Alert on multi-layer archive attachments

#### HTML Smuggling
- **Technique**: HTML attachment contains base64-encoded payload decoded by JavaScript
- **Bypass**: Payload only exists after browser renders HTML
- **Detection**: Analyze HTML for suspicious JavaScript that decodes files

#### Cloud Storage Links Instead of Attachments
- **Technique**: Link to SharePoint, OneDrive, Google Drive instead of direct attachment
- **Bypass**: Email scanners don't follow links to trusted cloud services
- **Detection**: Monitor file downloads from cloud storage links in emails

---

### Bypassing URL Scanning

#### URL Shorteners
- **Technique**: bit.ly, tinyurl.com hide final destination
- **Bypass**: Scanner may not follow multiple redirects
- **Detection**: Expand all short URLs before delivery

#### Time-of-Click Evasion
- **Technique**: URL returns benign content at scan time, malicious later
- **Bypass**: Safe links that check at click time are more effective
- **Detection**: Re-scan URLs at click time (Microsoft Safe Links, Proofpoint URL Defense)

#### Legitimate Service Abuse
- **Technique**: Host phishing pages on legitimate services (GitHub Pages, Netlify, Firebase)
- **Bypass**: Domain reputation of parent service is trusted
- **Detection**: Analyze page content, not just domain reputation

#### Geofencing/IP Targeting
- **Technique**: Payload only served to IPs in target organization's IP range
- **Bypass**: Sandbox analysis from different IP appears benign
- **Detection**: Hard to fully detect; combine with URL reputation and behavioral analysis

---

## 2. Endpoint & AV Evasion

### DDE Payload Evasion

#### String Obfuscation
```
Detected: =CMD("cmd /c calc.exe","")
Evaded:   =CHAR(61)&CHAR(67)&CHAR(77)&CHAR(68)...
Also:     =A1&A2&A3... (where cells contain command pieces)
```

#### Formula Spreading
- Split formula across multiple cells
- Reference cells from other worksheets
- Use named ranges with innocuous names

#### Environment Variable Obfuscation
```cmd
# Each env var piece set separately
SET x1=cal
SET x2=c.e
SET x3=xe
# Combined at execution
```

#### Alternate Formula Engines
- Excel 4.0 XLM macros (different engine than VBA/DDE)
- WEBSERVICE/FILTERXML functions for network access
- RTD (Real-Time Data) functions

---

### VBA Macro Evasion

#### P-code vs Source Stripping
- Remove VBA source code, keep p-code
- AV products scanning source code see nothing
- p-code still executes

#### Sleep/Environment Checks
```vba
' Anti-sandbox: check for user interaction before executing
If Now() < DateValue("2024-01-01") Then Exit Sub
If Application.UserName = "user" Then Exit Sub  ' Generic sandbox username
```

#### String Construction at Runtime
```vba
' Don't use: Shell "cmd /c calc.exe"
' Use:
Dim s As String
s = "cm" & Chr(100) & " /c " & Chr(99) & "alc.exe"
Shell s
```

#### API Call Obfuscation
```vba
' Direct API call (detectable)
Dim wsh As New WScript.Shell
' Alternative: late binding
Dim obj As Object
Set obj = CreateObject(Chr(87) & Chr(83) & Chr(99) & "ript.Shell")
```

---

## 3. Network Evasion

### C2 Traffic Blending

#### Protocol Selection
- Use HTTPS (443) to blend with normal traffic
- DNS-based C2 (hard to block without breaking DNS)
- Use cloud provider APIs (Azure, AWS, GCP) as C2 infrastructure

#### Domain Fronting Concepts
- Route C2 traffic through CDN providers
- CDN handles TLS; actual destination hidden from SNI inspection
- Modern CDNs are blocking this technique

#### Beacon Interval Jitter
```
Regular beacon: detected by network baseline monitoring
Jittered beacon: random interval ± 30% makes detection harder
```

#### Normal-Looking User-Agents
```
# Suspicious (blank or unusual UA)
curl/7.68.0

# Better (mimics real browser)
Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

---

## 4. File System Evasion

### NTFS Alternate Data Streams (ADS)
- Store payload in ADS: `file.txt:payload.exe`
- `dir` command doesn't show ADS
- Execution: `wscript.exe file.txt:payload.js`
- **Detection**: Sysmon monitoring for ADS creation

### Filename Tricks

#### Extension Spoofing
- Double extension: `invoice.pdf.exe`
- Space padding: `invoice.pdf          .exe`
- Right-to-Left Override: `invoice‮fdp.exe` → appears as `invoiceexe.pdf`

#### Case Mixing
- `CaLc.ExE` may bypass case-sensitive string matching

---

## 5. Behavioral Evasion

### Time-Based Evasion

#### Delayed Execution
```vba
' Don't execute immediately
Application.OnTime DateSerial(Year(Now), Month(Now), Day(Now) + 1), "ExecutePayload"
```

#### Working Hours Check
```vba
If Hour(Now) < 9 Or Hour(Now) > 17 Then Exit Sub
If Weekday(Now) = 1 Or Weekday(Now) = 7 Then Exit Sub  ' Weekend check
```

### Sandbox Detection

#### User Interaction Requirements
- Check if mouse has moved (sandboxes often don't simulate movement)
- Check for recent keyboard input
- Check number of running processes (sandboxes have fewer)

#### Environment Fingerprinting
```vba
' Check for sandbox artifacts (for detection/defense reference)
If InStr(LCase(Environ("COMPUTERNAME")), "sandbox") > 0 Then Exit Sub
If InStr(LCase(Environ("USERNAME")), "sandbox") > 0 Then Exit Sub
If FileLen("C:\Windows\explorer.exe") = 0 Then Exit Sub  ' Simulated env
```

---

## 6. Social Engineering Evasion

### Security Awareness Training Bypass

#### Targeted, Contextual Pretexts
- Research target on LinkedIn, company website
- Reference real projects, real colleagues' names
- Match internal naming conventions and email formatting

#### Multi-Stage Trust Building
- Initial contact 2-3 weeks before attack
- Provide value first (useful information, resource)
- Attack only after trust is established

#### Avoiding Common Red Flags
- Don't use generic subject lines ("Invoice", "Payment")
- Don't use urgent calls to action in first contact
- Match writing style of impersonated sender
- Use correct job titles and internal terminology

---

## Detection Recommendations

### What Defenders Should Focus On

Rather than trying to detect every evasion technique (arms race), focus on:

1. **Behavioral baselines**: Office applications spawning shells is always suspicious
2. **Process lineage**: Unusual parent-child process relationships
3. **Network anomalies**: Office/PDF readers making outbound connections
4. **Credential use patterns**: UEBA for abnormal authentication
5. **User reporting**: Train users to report suspicious emails (significant intelligence source)

### Detection Architecture

```
Email Gateway           Endpoint Detection              Network
─────────────────       ──────────────────────          ─────────────────
Attachment scan    →    EDR process monitoring  →       Proxy/NGFW
URL reputation          Memory scanning                 DNS monitoring  
AV scan                 Behavioral analytics            NetFlow analysis
DMARC/DKIM/SPF         Script logging                  DLP
Sandbox detonation      Registry monitoring             CASB
```

### Prioritized Detection Controls

| Priority | Control | Covers |
|----------|---------|--------|
| 1 | Office spawning cmd/PowerShell | DDE, Macros |
| 2 | Password-protected attachment heuristics | P11 bypass |
| 3 | Re-scan URLs at click time | Time-of-click evasion |
| 4 | Block outbound SMB from endpoints | NTLM capture |
| 5 | PDF JavaScript disable | PDF JS payloads |
| 6 | Script block logging (PowerShell) | PS execution |
| 7 | DNS filtering | C2 communication |
| 8 | UEBA for credential anomalies | Credential theft |

---

*See [DEFENSE_STRATEGIES.md](DEFENSE_STRATEGIES.md) for comprehensive defensive controls*  
*See [EVOLVED_TECHNIQUES.md](EVOLVED_TECHNIQUES.md) for technique evolution details*
