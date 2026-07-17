# Multi-Factor Authentication Credential Capture

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Documents the Adversary-in-the-Middle (AiTM) phishing technique that intercepts MFA tokens
in real-time by acting as a transparent proxy between the victim and legitimate service.

## How It Works
```
Victim → [Phishing Proxy] → Real Service
         (captures: username, password, MFA token, session cookie)
```

## MITRE ATT&CK
- **T1111** — Multi-Factor Authentication Interception (Collection)
- **T1557** — Adversary-in-the-Middle (Collection)

## Detection
- Impossible travel / simultaneous authentication anomalies
- Unusual session token usage after authentication
- Conditional access policy enforcement
- FIDO2 token usage not vulnerable to this technique

## Mitigation
- Use FIDO2/hardware security keys (phishing-resistant MFA)
- Implement Conditional Access with device compliance requirements
- Enable Microsoft Entra ID Protection sign-in risk policies

## Files
- `capture-template.html` — Conceptual template showing form structure (educational)

## References
- [MITRE T1111](https://attack.mitre.org/techniques/T1111/)
- [Microsoft AiTM Blog](https://www.microsoft.com/en-us/security/blog/)
