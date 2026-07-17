# Emerging Payloads

> **⚠️ DISCLAIMER**: All content in this directory is for **educational and research purposes ONLY**.
> These represent emerging attack vectors to help defenders understand and prepare.

---

## Overview

This directory documents emerging social engineering attack categories not covered by the
existing payload collection. These represent current and near-future threats based on
security research and observed incidents.

---

## Categories

### A. Living-off-the-Land (LOLBins) Attacks
Using legitimate Windows system binaries to execute malicious actions.

| Directory | Binary | Primary Use |
|-----------|--------|-------------|
| `lolbins-certutil/` | certutil.exe | Download & decode |
| `lolbins-rundll32/` | rundll32.exe | Proxy execution |
| `lolbins-mshta/` | mshta.exe | AppLocker bypass |
| `lolbins-cmstp/` | cmstp.exe | UAC bypass |
| `lolbins-regsvcs-regasm/` | regsvcs/regasm | .NET assembly load |
| `lolbins-execution-chain/` | Multiple | Chained execution |

### B. Cloud & SaaS Platform Attacks
Social engineering via cloud services that bypass perimeter defenses.

| Directory | Platform | Attack Type |
|-----------|----------|-------------|
| `cloud-onedrive-sharepoint/` | Microsoft 365 | Document phishing |
| `cloud-teams-injection/` | Microsoft Teams | Payload injection |
| `cloud-slack-bot/` | Slack | Bot impersonation |
| `cloud-google-drive/` | Google Workspace | Document phishing |
| `cloud-aws-s3-exposure/` | AWS | Credential exposure |

### C. Mobile-First Phishing
Attack techniques optimized for mobile devices and SMS.

| Directory | Target | Technique |
|-----------|--------|-----------|
| `mobile-optimized-capture/` | Mobile browser | Responsive credential page |
| `mobile-sms-bridge/` | SMS/Email | Smishing + email chain |
| `mobile-qr-execution/` | QR camera | QR code phishing |
| `mobile-fake-update/` | Mobile apps | Fake app update prompt |

### D. Browser Extension Attacks
Malicious browser extensions for credential theft and persistence.

| Directory | Browser | Technique |
|-----------|---------|-----------|
| `browser-extension-injection/` | Chrome/Firefox | Auto-install extension |
| `browser-settings-hijack/` | Any | Settings modification |
| `browser-search-redirect/` | Any | Search engine hijack |
| `browser-startup-script/` | Any | Startup script injection |

### E. Container & Orchestration Attacks
Social engineering targeting DevOps and cloud-native environments.

| Directory | Platform | Attack |
|-----------|----------|--------|
| `container-escape-payload/` | Docker | Container escape |
| `k8s-manifest-injection/` | Kubernetes | Manifest injection |
| `container-registry-creds/` | Any registry | Credential theft |

### F. Supply Chain Attacks
Compromising software distribution for broad-scale payload delivery.

| Directory | Target | Technique |
|-----------|--------|-----------|
| `supply-chain-installer/` | Software installers | Trojanized installer |
| `supply-chain-npm-nuget/` | npm/NuGet | Package poisoning |
| `supply-chain-dependency-injection/` | Any package manager | Dependency confusion |
| `supply-chain-windows-update-fake/` | Windows Update | Fake update prompt |

### G. Authentication Bypass
Techniques to bypass multi-factor authentication and modern auth.

| Directory | Target | Technique |
|-----------|--------|-----------|
| `auth-ntlm-relay/` | Windows/AD | NTLM relay |
| `auth-sso-token-intercept/` | SSO systems | Token interception |
| `auth-oauth-hijack/` | OAuth apps | Consent phishing |
| `auth-mfa-bypass/` | MFA systems | AiTM/fatigue |

---

## Threat Landscape Context

These categories represent emerging vectors based on:
- Current threat intelligence reports (CISA, Microsoft, Mandiant)
- Academic security research
- Bug bounty disclosures
- Observed real-world campaign analysis

---

## MITRE ATT&CK Coverage

| Category | Key Technique IDs |
|----------|-------------------|
| LOLBins | T1105, T1218.003, T1218.005, T1218.009, T1218.011 |
| Cloud/SaaS | T1566.002, T1534, T1552.005 |
| Mobile | T1056.003, T1598, T1204.001, T1036 |
| Browser Extensions | T1176, T1217, T1056.004 |
| Containers | T1611, T1610, T1552.007 |
| Supply Chain | T1195.001, T1195.002 |
| Auth Bypass | T1557.001, T1539, T1550.001, T1111 |

---

*See [../docs/EMERGING_THREATS.md](../docs/EMERGING_THREATS.md) for detailed threat analysis*
