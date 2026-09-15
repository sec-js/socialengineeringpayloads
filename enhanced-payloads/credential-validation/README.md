# Credential Validation

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Documents the technique of automatically validating stolen credentials against
public-facing authentication endpoints before using them in subsequent attack stages.

## How It Works
1. Credentials captured via phishing
2. Automated validation against OWA, VPN portal, or cloud login
3. Valid credentials flagged for use in lateral movement
4. Invalid/expired credentials discarded

## MITRE ATT&CK
- **T1078** — Valid Accounts (Defense Evasion, Persistence, Privilege Escalation, Initial Access)
- **T1110.003** — Brute Force: Password Spraying (related technique)

## Detection
- Alert on multiple authentication attempts from unusual IPs
- Monitor for logins from known hosting providers or Tor
- Implement login velocity limits

## Mitigation
- Multi-factor authentication (makes credentials alone insufficient)
- IP-based Conditional Access policies
- Account lockout after failed attempts

## References
- [MITRE T1078](https://attack.mitre.org/techniques/T1078/)
