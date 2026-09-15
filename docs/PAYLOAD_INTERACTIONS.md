# Payload Interactions & Combination Matrix

> **⚠️ DISCLAIMER**: This document is for **educational and research purposes ONLY**.
> Understanding payload synergies helps defenders anticipate multi-stage attacks.

---

## Overview

Social engineering payloads don't exist in isolation. Understanding how they interact,
complement each other, and form attack chains enables both better offensive simulation
(red teaming) and defensive detection.

---

## Payload Catalog

The following payloads are referenced throughout this document:

| ID | Payload | Type | Primary Goal |
|----|---------|------|--------------|
| P01 | DDE CSV | DDE-based | Code Execution |
| P02 | DDE DOCX | DDE-based | Code Execution |
| P03 | DDE Outlook MSG | DDE-based | Code Execution |
| P04 | DDE SLK | DDE-based | Code Execution |
| P05 | DDE XLS | DDE-based | Code Execution |
| P06 | Embedded Object | OLE | Code Execution |
| P07 | PowerPoint Mouseover | Script | Code Execution |
| P08 | Fake Attachment Scam | Social Eng | Deception |
| P09 | Link Manipulation | URL | Credential/Redirect |
| P10 | PDF Malicious URL | PDF | URL/Code Execution |
| P11 | Password Protected Doc | Evasion | Delivery Bypass |
| P12 | Steal Creds - Excel | Credential | Credential Theft |
| P13 | Steal Creds - Word Auth | Credential | Credential Theft |
| P14 | Tabnabbing | Browser | Credential Theft |
| P15 | LNK HTA | Shortcut | Code Execution |

---

## Compatibility Matrix

This matrix shows which payloads can be chained together effectively:

```
     P01 P02 P03 P04 P05 P06 P07 P08 P09 P10 P11 P12 P13 P14 P15
P01:  -   ✓   ✓   ✓   ✓   ○   ○   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓
P02:  ✓   -   ✓   ✓   ✓   ✓   ○   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓
P03:  ✓   ✓   -   ✓   ✓   ✓   ○   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓
P04:  ✓   ✓   ✓   -   ✓   ○   ○   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓
P05:  ✓   ✓   ✓   ✓   -   ○   ○   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓
P06:  ○   ✓   ✓   ○   ○   -   ○   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓
P07:  ○   ○   ○   ○   ○   ○   -   ✓   ✓   ○   ✓   ✓   ✓   ✓   ✓
P08:  ✓   ✓   ✓   ✓   ✓   ✓   ✓   -   ✓   ✓   ✓   ✓   ✓   ✓   ✓
P09:  ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   -   ✓   ✓   ✓   ✓   ✓   ✓
P10:  ✓   ✓   ✓   ✓   ✓   ✓   ○   ✓   ✓   -   ✓   ✓   ✓   ✓   ✓
P11:  ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   -   ✓   ✓   ✓   ✓
P12:  ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   -   ✓   ○   ✓
P13:  ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   -   ○   ✓
P14:  ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ○   ○   -   ✓
P15:  ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   ✓   -

Legend:
  ✓ = High synergy (strong combination)
  ○ = Limited synergy (weak or situational combination)  
  - = Same payload (no combination)
```

---

## High-Value Payload Combinations

### Combination 1: Password-Protected DDE (P11 + P02)

**Synergy Level**: ★★★★★ (Very High)

**How It Works**:
```
P11: Password-protected DOCX → Bypasses email scanning
P02: DDE payload inside the document → Executes when opened
```

**Chain**:
1. Email with password-protected DOCX (P11)
2. Password included in email body
3. Target enters password, document decrypts
4. DDE fields execute payload (P02)

**Why Effective**:
- P11 defeats content scanning (encrypted)
- P02 executes upon document open
- Double social engineering: email urgency + password increases trust

**MITRE**: T1566.001 → T1027 → T1204.002 → T1059.003

---

### Combination 2: Fake Attachment + Link (P08 + P09)

**Synergy Level**: ★★★★☆ (High)

**How It Works**:
```
P08: Fake attachment scam email → Clicks on "attachment" (actually a link)
P09: Link manipulation → Redirects to phishing/malicious page
```

**Chain**:
1. Email with fake inline image appearing as PDF thumbnail (P08)
2. User clicks "Download PDF"
3. Actually navigates to P09 link manipulation page
4. Page serves real malicious content or credential harvest

**Why Effective**:
- P08 tricks user into thinking they're downloading a normal attachment
- P09 serves the actual payload via web
- No attachment to scan

---

### Combination 3: Tabnabbing + Credential Theft (P14 + P12)

**Synergy Level**: ★★★★★ (Very High)

**How It Works**:
```
P14: Tabnabbing → Replaces inactive tab with fake login page
P12: Credential harvesting page → Captures entered credentials
```

**Chain**:
1. Email contains link (safe-looking) → opens tab (P14)
2. User works in other tabs
3. Tab silently replaces content with Excel/O365 login page (P12)
4. User returns, thinks they got logged out
5. Credentials submitted to attacker

**Why Effective**:
- Timing-based: user less suspicious when returning to a tab
- Appears to be a session timeout (common and trusted experience)
- Combines browser trust with credential page quality

---

### Combination 4: DDE Downloader + Credential Page (P01 + P12)

**Synergy Level**: ★★★★☆ (High)

**How It Works**:
```
P01: DDE CSV payload → Executes command
Command downloads and opens local copy of P12
P12: Credential page hosted locally → Higher trust, no URL to analyze
```

**Chain**:
1. CSV with DDE formula downloads P12 HTML from attacker server
2. Stores in `%TEMP%\` directory
3. Opens in default browser as `file:///C:/Users/.../login.html`
4. User enters credentials (trusted because no suspicious URL)

**Why Effective**:
- Local file:// URL bypasses URL reputation services
- File was just "opened by the spreadsheet" — seems legitimate
- Harder to detect than network-based credential pages

---

### Combination 5: MSG DDE + Internal Spearphishing (P03 + Any)

**Synergy Level**: ★★★★☆ (High when inside network)

**How It Works**:
```
P03: Outlook MSG payload → Executes on compromised system
Provides access to email account
Use email account for further spearphishing
```

**Chain**:
1. External phishing delivers P03 (SWIFT payment, financial urgency)
2. DDE executes, provides access to machine/email
3. Use compromised email to send internal phishing (T1534)
4. Internal emails with P02/P05 sent to colleagues
5. Higher trust due to internal sender

**Why Effective**:
- Internal email bypasses external email security
- Trusted sender significantly increases open rates
- Lateral movement via social engineering

---

### Combination 6: LNK + DDE Multi-Format (P15 + P01/P02/P05)

**Synergy Level**: ★★★★☆ (High)

**How It Works**:
```
P15: LNK shortcut downloads multiple payload types
If Excel opens → P05 (XLS DDE) executes
If Word opens → P02 (DOCX DDE) executes
Redundancy ensures execution across different default apps
```

---

## Delivery Mechanism Interactions

### Email as Primary Vector

Most payloads can be delivered via email. Delivery effectiveness depends on:

| Email Element | Impact on Success | Notes |
|---------------|------------------|-------|
| Sender reputation | High | Internal > Partner > External |
| Subject line urgency | High | "Action Required" vs "Hello" |
| Attachment type | Medium | .docx widely trusted, .exe blocked |
| HTML vs Plain Text | Medium | HTML allows inline images for P08 |
| Mobile vs Desktop | Low-Medium | Mobile harder to inspect links |

---

### Cross-Platform Payload Interactions

| Platform | DDE Payloads | Credential Pages | Browser-Based |
|----------|-------------|-----------------|---------------|
| Windows + Office | Excellent | Good | Good |
| macOS + Office | Limited | Good | Good |
| Web (O365) | None | Good | Good |
| Mobile | None | Excellent (mobile-first) | Excellent |
| Linux | None | Good | Good |

---

## Temporal Interactions (Attack Timing)

Some payload combinations work better in sequence over time:

### Slow-Burn Combination (2-3 weeks)
```
Week 1: Initial trust building
  → Connect on LinkedIn
  → Send harmless email ("Saw your presentation at conference")
  
Week 2: False sense of security
  → Follow-up with useful information/resource
  
Week 3: Attack delivery
  → "Thought you'd find this spreadsheet useful" (P05)
  → High trust due to established relationship
```

### Quick-Strike Combination (same day)
```
09:00: Vishing call ("I'm from IT, you'll get an email shortly")
09:05: Phishing email with P11 (password-protected doc)
09:06: "Password is Invoice2024" texted to target
09:10: Target opens document (P02 DDE executes)
```

### Reactive Combination (event-driven)
```
[News: Major data breach announced]
→ Attacker sends "Security Alert" email within hours (P09/P12)
→ Target searches for information, finds link
→ High relevance makes click more likely
```

---

## Complementary Payload Properties

### Coverage Matrix

| Property | DDE | Credential | Browser | PDF | LNK |
|----------|-----|------------|---------|-----|-----|
| Executes code | ✓ | ✗ | ✗ | ✓ | ✓ |
| Harvests credentials | ✗ | ✓ | ✓ | ○ | ✗ |
| Persists | ✗ | ✗ | ✓ | ✗ | ✗ |
| Bypasses email scan | ○ | ✗ | ✗ | ✓ | ✓ |
| Works offline | ✓ | ✗ | ✗ | ✓ | ✓ |
| Works cross-platform | ✗ | ✓ | ✓ | ✓ | ✗ |
| No user awareness needed | ✗ | ✗ | ✓ (tab) | ✗ | ✗ |

### Gap Analysis
- **No payloads cover**: Linux-specific attacks, macOS-specific attacks, mobile native
- **Weak coverage**: Persistence, lateral movement (all initial access focused)
- **Strong coverage**: DDE execution, credential harvesting, browser-based attacks

---

## Detection Cross-Reference

### Detections That Cover Multiple Payloads

| Detection Method | Payloads Covered |
|-----------------|-----------------|
| Office process spawning cmd.exe | P01-P07, P11 |
| Network connection from Office apps | P01-P07, P11 |
| Unusual browser form submissions | P09, P10, P12, P13, P14 |
| New scheduled task creation | Payloads with persistence |
| Outbound SMB (NTLM capture) | P13 |
| mshta.exe execution | P15 |
| DDE field detection in documents | P01-P05 |

### Most Efficient Detection Coverage

Implementing the following 5 detections covers all 15 payloads:

1. **Office application spawning unexpected child processes** — covers P01-P07, P11
2. **Suspicious network connections from document viewer processes** — covers P01-P10
3. **Unusual credential form submissions** — covers P09, P12, P13, P14
4. **mshta.exe and cscript.exe execution monitoring** — covers P15
5. **Email attachment analysis (DDE, OLE, LNK)** — covers all delivery-based payloads

---

*See [PAYLOAD_CHAINING.md](PAYLOAD_CHAINING.md) for complete attack chain documentation*  
*See [TECHNIQUE_MAPPING.md](TECHNIQUE_MAPPING.md) for MITRE ATT&CK mappings*
