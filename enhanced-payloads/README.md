# Enhanced Payloads

> **⚠️ DISCLAIMER**: All payloads in this directory are for **educational and research purposes ONLY**.
> Use only in authorized environments. The PoC payloads execute `calc.exe` as a benign demonstration.

---

## Overview

This directory contains evolved versions of the existing social engineering payloads,
demonstrating how attackers adapt techniques to bypass modern defenses.

Understanding these evolved techniques helps:
- Defenders tune detection rules to catch variants
- Red teamers simulate realistic advanced threats
- Researchers understand the threat landscape evolution

---

## Category Overview

### A. Advanced DDE Evasion
Evolved versions of DDE payloads that bypass DDE-disable policies and AV signatures.

| Directory | Technique | Evasion Method |
|-----------|-----------|----------------|
| `dde-base64-encoded/` | DDE + encoding | Base64 character construction |
| `dde-xor-obfuscated/` | DDE + XOR | Runtime XOR decode |
| `dde-staged/` | Two-stage DDE | Minimal loader + remote payload |
| `dde-environment-vars/` | DDE + env vars | Environment variable assembly |

### B. Intelligent Credential Harvesting
Advanced credential capture techniques including real-time MFA interception.

| Directory | Technique | Capability |
|-----------|-----------|------------|
| `credential-mfa-capture/` | AiTM proxy | Real-time MFA bypass |
| `credential-silent-capture/` | NTLM/WebDAV | No visible popup |
| `credential-validation/` | Live validation | Confirm creds work |
| `credential-auto-submit/` | C2 exfil | Auto-forward to attacker |

### C. Advanced Office Macro Techniques
Macro techniques that bypass AV, whitelisting, and security policies.

| Directory | Technique | Bypass Method |
|-----------|-----------|---------------|
| `macro-pcode-encrypted/` | P-code macros | Source code stripped |
| `macro-xlm-excel4/` | Excel 4.0 macros | Legacy macro engine |
| `macro-metadata-injection/` | Metadata payload | Stored in doc properties |
| `macro-template-injection/` | Remote template | Clean doc + remote malicious template |

### D. PDF Advanced Exploitation
Advanced PDF payload techniques beyond simple URL embedding.

| Directory | Technique | Vector |
|-----------|-----------|--------|
| `pdf-javascript-payload/` | PDF JavaScript | Embedded JS execution |
| `pdf-form-field-capture/` | Form capture | Form POST exfiltration |
| `pdf-annotation-abuse/` | Annotations | Hidden annotation execution |
| `pdf-embedded-executable/` | Embedded binary | Executable inside PDF |
| `pdf-launch-chain/` | Launch actions | PDF launch action |

### E. Advanced Link Manipulation
Sophisticated URL and domain techniques to evade security controls.

| Directory | Technique | Method |
|-----------|-----------|--------|
| `link-homograph-domains/` | Homograph | Unicode lookalike characters |
| `link-rtlo-bypass/` | RTLO | Right-to-Left Override |
| `link-typosquatting/` | Typosquatting | Common typing errors |
| `link-xss-redirect-chain/` | XSS + redirect | Open redirect chain |
| `link-parameter-poisoning/` | Parameter abuse | Query string manipulation |

---

## Quick Reference

### MITRE ATT&CK Coverage

| Category | Primary Technique | MITRE ID |
|----------|------------------|----------|
| DDE Evasion | Obfuscated Files | T1027 |
| DDE Staged | Ingress Tool Transfer | T1105 |
| Credential MFA | MFA Interception | T1111 |
| Credential NTLM | Forced Authentication | T1187 |
| Macro P-code | Visual Basic | T1059.005 |
| Macro XLM | Office Template | T1137.001 |
| Macro Template | Template Injection | T1221 |
| PDF JavaScript | JavaScript | T1059.007 |
| Homograph | Masquerading | T1036 |
| RTLO | Right-to-Left Override | T1036.002 |

---

## Usage Notes

1. All PoC files execute `calc.exe` (Windows Calculator) as a benign payload
2. Replace `calc.exe` with authorized test payloads for red team engagements
3. Test only in isolated, authorized lab environments
4. Do not use against production systems without written authorization

---

## Detection Summary

Most enhanced payloads can be detected by:

1. **Behavioral monitoring**: Office/PDF reader spawning unexpected processes
2. **Network monitoring**: Document readers making outbound connections
3. **Content analysis**: Deep inspection of file contents (not just extensions)
4. **DNS analysis**: Newly registered lookalike domains
5. **Process lineage**: Unusual parent-child process relationships

See [EVOLVED_TECHNIQUES.md](../docs/EVOLVED_TECHNIQUES.md) for detailed evasion and detection guidance.

---

*See [../docs/EVOLVED_TECHNIQUES.md](../docs/EVOLVED_TECHNIQUES.md) for detailed documentation*
