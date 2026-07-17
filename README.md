### SocialEngineeringPayloads

<<<<<<< HEAD
A comprehensive collection of social engineering tricks, payloads, and educational documentation
for credential theft and spear phishing attack research. Includes evolved techniques, payload
chaining guides, MITRE ATT&CK mapping, and automation frameworks.

> **NOTE**: Most payloads are PoC to execute `calc.exe` (Windows Calculator) as a benign demonstration.
=======
[![Interactive Dashboard](https://img.shields.io/badge/Interactive_Dashboard-GitHub_Pages-blue?style=for-the-badge&logo=github)](https://sec-js.github.io/socialengineeringpayloads/)

This is a collection of social engineering tricks and payloads being used for credential theft and spear phishing attacks.

**🔍 Explore the [Interactive Payload Dashboard](https://sec-js.github.io/socialengineeringpayloads/) — searchable, filterable, with MITRE ATT&CK mapping, dark/light theme, and mobile support.**

NOTE: Most of these payloads are PoC to execute calc.exe
>>>>>>> origin/copilot/create-interactive-web-dashboard

---

### ⚠️ Disclaimer

These details/samples are for **Educational purpose ONLY**. Do not use without permission. The usual disclaimer applies, especially the fact that me (bhdresh) is not liable for any damages caused by direct or indirect use of the information or functionality provided by these programs. The author or any Internet provider bears NO responsibility for content or misuse of these programs or any derivatives thereof. By using these details/samples you accept the fact that any damage (dataloss, system crash, system compromise, etc.) caused by the use of these is not bhdresh's responsibility.

Finally, this is a personal development, please respect its philosophy and don't use it for bad things!

---

## Payload Categories

### 📄 DDE-Based Attacks
Execute commands via Dynamic Data Exchange in Office documents:
- [DDE CSV Payload](./DDE%20based%20social%20engineering%20csv%20payload/) — DDE in spreadsheet CSV
- [DDE DOCX Payload](./DDE%20based%20social%20engineering%20docx%20payload/) — DDE in Word document
- [DDE Outlook MSG](./DDE%20based%20social%20engineering%20msg%20%28OUTLOOK%29%20payload/) — DDE in Outlook message
- [DDE SLK Payload](./DDE%20based%20social%20engineering%20slk%20payload/) — DDE in Symbolic Link format
- [DDE XLS Payload](./DDE%20based%20social%20engineering%20xls%20payload/) — DDE in Excel spreadsheet

### 🔗 Object Embedding & Execution
- [Embedded Objects](./Embedding%20Object%20in%20office%20document/) — OLE object embedding
- [PowerPoint Mouseover](./Execute%20powershell%20on%20mouseover%20-%20Powerpoint%20%28pps%29/) — PowerShell via mouse hover
- [LNK Download & Execute](./lnk%20-%20download%20and%20execute%20calc%20HTA/) — Shortcut file payload

### 🎣 Social Engineering & Deception
- [Fake Attachment Scam](./Fake%20attachment%20scam/) — Email attachment deception
- [Password Protected Document](./Password%20protected%20document/) — Encrypted document bypass

### 🔑 Credential Theft
- [Steal Credentials via Excel](./Steal%20credentials%20using%20fake%20excel%20doc/) — Fake Microsoft login
- [Steal Credentials via Basic Auth](./Steal%20credential%20using%20a%20word%20document%20which%20pop%20for%20basic%20authentication/) — NTLM auth capture

### 🌐 Web-Based Attacks
- [Link Manipulation](./Link%20manipulation%20attack/) — URL masquerading
- [PDF with Malicious URL](./PDF%20with%20malicious%20URL/) — PDF URL delivery
- [Tabnabbing Attack](./Tabnabbing%20attack/) — Browser tab replacement

---

## 📚 Documentation & Resources

### Attack Chain Documentation
| Document | Description |
|----------|-------------|
| [PAYLOAD_CHAINING.md](./docs/PAYLOAD_CHAINING.md) | 8 multi-stage attack chain flowcharts |
| [EVOLVED_TECHNIQUES.md](./docs/EVOLVED_TECHNIQUES.md) | Evolved payload technique guide |
| [EMERGING_THREATS.md](./docs/EMERGING_THREATS.md) | Emerging attack vector overview |
| [PAYLOAD_INTERACTIONS.md](./docs/PAYLOAD_INTERACTIONS.md) | How payloads interact and combine |

### Defensive Resources
| Document | Description |
|----------|-------------|
| [DEFENSE_STRATEGIES.md](./docs/DEFENSE_STRATEGIES.md) | Comprehensive defense guide |
| [DETECTION_EVASION.md](./docs/DETECTION_EVASION.md) | Evasion techniques for defenders |

### MITRE ATT&CK Reference
| Document | Description |
|----------|-------------|
| [TECHNIQUE_MAPPING.md](./docs/TECHNIQUE_MAPPING.md) | All payloads mapped to ATT&CK |
| [MITRE_REFERENCE.md](./docs/MITRE_REFERENCE.md) | Detailed ATT&CK technique reference |
| [payload-techniques.json](./data/payload-techniques.json) | Machine-readable mapping data |

### Contributing
- [CONTRIBUTING.md](./CONTRIBUTING.md) — How to contribute new techniques

---

## 🔧 Tools & Automation

### Chain Orchestrator
Located in [`tools/chain-orchestrator/`](./tools/chain-orchestrator/)

```bash
# List available attack chains
python tools/chain-orchestrator/orchestrator.py --list

# Simulate an attack chain
python tools/chain-orchestrator/orchestrator.py --simulate \
    tools/chain-orchestrator/configs/chain-config-1.yaml

# Validate chain configuration
python tools/chain-orchestrator/validate-chain.py \
    tools/chain-orchestrator/configs/chain-config-1.yaml

# Generate documentation
python tools/chain-orchestrator/generate-docs.py \
    tools/chain-orchestrator/configs/chain-config-1.yaml

# Interactive CLI
python tools/chain-orchestrator/cli.py
```

---

## 🎯 Enhanced Payload Templates

Advanced evolved techniques in [`enhanced-payloads/`](./enhanced-payloads/):

| Category | Techniques |
|----------|------------|
| [DDE Evasion](./enhanced-payloads/) | Base64 encoding, XOR obfuscation, staged delivery, env vars |
| [Credential Capture](./enhanced-payloads/) | MFA intercept, NTLM capture, validation, auto-submit |
| [Office Macros](./enhanced-payloads/) | P-code, XLM/Excel 4.0, metadata injection, template injection |
| [PDF Exploitation](./enhanced-payloads/) | JavaScript, form fields, annotations, embedded executables |
| [Link Manipulation](./enhanced-payloads/) | Homograph, RTLO, typosquatting, XSS redirect, param poisoning |

---

## 🌐 Emerging Attack Categories

New payload categories in [`emerging-payloads/`](./emerging-payloads/):

| Category | Coverage |
|----------|----------|
| [Living-off-the-Land](./emerging-payloads/) | certutil, rundll32, mshta, cmstp, regsvcs/regasm |
| [Cloud & SaaS](./emerging-payloads/) | Teams, SharePoint, Slack, Google Drive, AWS S3 |
| [Mobile-First](./emerging-payloads/) | Mobile pages, SMS bridge, QR codes, fake updates |
| [Browser Extensions](./emerging-payloads/) | Extension injection, settings hijack, search redirect |
| [Containers](./emerging-payloads/) | Container escape, K8s manifest injection |
| [Supply Chain](./emerging-payloads/) | Installer, NPM/NuGet poisoning, dependency injection |
| [Authentication Bypass](./emerging-payloads/) | NTLM relay, SSO tokens, OAuth hijack, MFA bypass |

---

## Quick Reference: Payload Comparison

| Payload | Target App | Technique | MITRE | Detection Difficulty |
|---------|-----------|-----------|-------|---------------------|
| DDE CSV | Excel | DDE execution | T1566.001 | Medium |
| DDE DOCX | Word | DDE execution | T1566.001 | Medium |
| DDE MSG | Outlook | DDE execution | T1566.001 | Medium |
| DDE SLK | Excel | DDE (uncommon format) | T1566.001 | High |
| DDE XLS | Excel | DDE execution | T1566.001 | Medium |
| Embedded Object | Office | OLE execution | T1204.002 | Medium |
| PowerPoint Mouseover | PowerPoint | Mouse hover PS | T1059.001 | High |
| Fake Attachment | Email | Deception | T1036 | Hard |
| Link Manipulation | Browser | URL redirect | T1566.002 | Medium |
| PDF Malicious URL | PDF Reader | URL execution | T1566.001 | Medium |
| Password Protected | Office | Scan bypass | T1027 | Very High |
| Steal Creds (Excel) | Browser | Fake login | T1056.003 | Medium |
| Steal Creds (Auth) | Word | NTLM capture | T1187 | Hard |
| Tabnabbing | Browser | Tab replacement | T1185 | Hard |
| LNK HTA | Windows | Shortcut exec | T1218.005 | Medium |

---

### Licence
CC BY 4.0 licence - https://creativecommons.org/licenses/by/4.0/
