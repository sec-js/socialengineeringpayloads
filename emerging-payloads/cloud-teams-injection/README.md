# Cloud Attack: teams-injection

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Social engineering attack targeting cloud/SaaS platform TEAMS INJECTION to deliver payloads
or harvest credentials while bypassing perimeter security controls.

## Why Cloud Attacks Are Effective
- Cloud services often exempt from URL/domain blocking
- Files hosted on legitimate infrastructure appear trusted
- Cloud-to-cloud access bypasses on-premise security controls

## MITRE ATT&CK
- **T1566.002** — Phishing: Spearphishing Link (Initial Access)
- **T1534** — Internal Spearphishing (Lateral Movement)

## Detection
- Monitor cloud service audit logs for unusual external sharing
- Alert on new external user additions
- Analyze downloaded files from cloud services

## Mitigation
- Configure cloud DLP policies
- Enable Conditional Access for cloud services
- Regular access reviews of cloud sharing settings
- Microsoft Defender for Cloud Apps / CASB solutions

## References
- [MITRE T1566.002](https://attack.mitre.org/techniques/T1566/002/)
