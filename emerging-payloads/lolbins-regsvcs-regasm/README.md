# LOLBin: regsvcs-regasm Technique

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Living-off-the-Land technique using legitimate Windows binary to bypass security controls.

## MITRE ATT&CK
- **T1218** — System Binary Proxy Execution (Defense Evasion)

## Detection
- Monitor the binary for unusual arguments or network connections
- Alert on execution from Office or email client parent processes
- Behavioral analysis of process arguments

## Mitigation
- AppLocker/WDAC restrictions on LOLBin execution
- Application whitelisting
- Behavioral monitoring

## References
- [LOLBAS Project](https://lolbas-project.github.io/)
- [MITRE T1218](https://attack.mitre.org/techniques/T1218/)
