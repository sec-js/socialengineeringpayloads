# rundll32.exe — Living-off-the-Land Payload

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
rundll32.exe is a Windows utility for executing DLL functions that attackers abuse to
execute malicious code while appearing to use a legitimate system binary.

## Common Abuse Patterns (for detection/defense reference)
```cmd
# Execute DLL with specific function
rundll32.exe payload.dll,EntryFunction

# Execute JavaScript via URL.dll (historical)
rundll32.exe javascript:"\..\mshtml,RunHTMLApplication ";...

# Execute via advpack.dll
rundll32.exe advpack.dll,LaunchINFSection malicious.inf,DefaultInstall
```

## MITRE ATT&CK
- **T1218.011** — System Binary Proxy Execution: Rundll32 (Defense Evasion)

## Detection
- Monitor rundll32.exe with unusual DLL targets (non-Windows directories)
- Alert on rundll32.exe with JavaScript arguments
- Sysmon network connections from rundll32.exe
- Parent process monitoring (Office → rundll32)

## Mitigation
- AppLocker rules to restrict rundll32.exe execution context
- Monitor rundll32 spawning child processes
- Attack Surface Reduction rules

## References
- [MITRE T1218.011](https://attack.mitre.org/techniques/T1218/011/)
- [LOLBAS rundll32](https://lolbas-project.github.io/lolbas/Binaries/Rundll32/)
