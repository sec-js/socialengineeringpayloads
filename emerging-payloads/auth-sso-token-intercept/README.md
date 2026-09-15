# Authentication Attack: sso-token-intercept

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Authentication bypass technique: SSO TOKEN INTERCEPT

Modern authentication bypass techniques often target the protocol or token layer rather
than trying to guess or brute-force passwords.

## MITRE ATT&CK
- **T1557** — Adversary-in-the-Middle (Collection)
- **T1550.001** — Application Access Token (Defense Evasion)
- **T1539** — Steal Web Session Cookie (Collection)
- **T1111** — MFA Interception (Collection)

## Detection
- Conditional Access policy enforcement
- Anomalous authentication pattern detection (UEBA)
- Impossible travel detection

## Mitigation
- FIDO2/hardware keys (most phishing-resistant)
- Conditional Access with device compliance requirements
- Token binding where supported
- Regular OAuth application permission audits

## References
- [MITRE T1557](https://attack.mitre.org/techniques/T1557/)
- [MITRE T1550](https://attack.mitre.org/techniques/T1550/)
