# Contributing to Social Engineering Payloads

> **⚠️ IMPORTANT**: All contributions must be for **educational and defensive research purposes ONLY**.
> Contributions that could facilitate illegal activity will not be accepted.

---

## Overview

Thank you for your interest in contributing to the Social Engineering Payloads repository.
This collection helps security researchers, penetration testers, and defenders understand
and protect against social engineering attacks.

---

## Code of Conduct

By contributing to this project, you agree to:

1. **Ethical use only**: All materials are for educational/defensive purposes
2. **No illegal activity**: Do not contribute content that facilitates unauthorized access
3. **Respect privacy**: Do not include real personal data or real target information
4. **Professional conduct**: Be respectful and constructive in all interactions
5. **Disclosure responsibility**: Follow responsible disclosure for any vulnerabilities

---

## Types of Contributions

We welcome the following types of contributions:

### ✅ Accepted Contributions
- New payload types that demonstrate social engineering techniques
- Documentation improvements and clarifications
- Detection and defense documentation
- MITRE ATT&CK mappings and updates
- Real-world technique explanations (anonymized)
- Tools for analysis, detection, and simulation

### ❌ Not Accepted
- Actual working malware (all PoCs should use calc.exe or similar benign payload)
- Exploit code targeting specific CVEs without defensive context
- Content targeting specific individuals or organizations
- Content that could be used for doxxing or harassment

---

## Repository Structure

```
socialengineeringpayloads/
├── [Payload Category]/          # Existing payload categories
├── docs/                        # Documentation
│   ├── PAYLOAD_CHAINING.md      # Attack chain documentation
│   ├── TECHNIQUE_MAPPING.md     # MITRE ATT&CK mapping
│   ├── MITRE_REFERENCE.md       # MITRE reference guide
│   ├── EVOLVED_TECHNIQUES.md    # Evolved technique guide
│   ├── EMERGING_THREATS.md      # Emerging threat overview
│   ├── PAYLOAD_INTERACTIONS.md  # Payload interaction documentation
│   ├── DETECTION_EVASION.md     # Detection evasion reference
│   └── DEFENSE_STRATEGIES.md    # Defense strategies
├── enhanced-payloads/           # Evolved payload templates
├── emerging-payloads/           # New payload categories
├── data/                        # Structured data files
│   └── payload-techniques.json  # MITRE mapping data
└── tools/                       # Tools and utilities
    └── chain-orchestrator/      # Chain orchestration framework
```

---

## Adding a New Payload Category

### Step 1: Create Directory Structure

```bash
mkdir -p "New Payload Category/"
```

### Step 2: Create Payload Files

For PoC payloads:
- Use `calc.exe` as the example payload (repository convention)
- Do NOT include actual malicious code
- Include a disclaimer comment/note in all files

### Step 3: Create Documentation

Each payload category **must** include:

1. **README.md** — Required documentation file:

```markdown
# [Payload Name]

## Overview
Brief description of the technique.

## Disclaimer
Educational purposes only. Do not use without authorization.

## How It Works
Technical explanation of the mechanism.

## Files
- `filename.ext` - Description of file

## Detection
How security tools detect this payload.

## Mitigation
How to protect against this payload.

## MITRE ATT&CK
- Technique ID: T####.###
- Technique Name: [Name]
- Tactic: [Tactic]

## References
- [Reference 1](URL)
```

### Step 4: Update MITRE Mapping

Add your payload to `data/payload-techniques.json`:

```json
{
  "id": "payload_XXX",
  "name": "[Payload Name]",
  "category": "[Category]",
  "file": "[path/to/file]",
  "description": "[Description]",
  "techniques": [
    {
      "mitre_id": "T####.###",
      "name": "[Technique Name]",
      "tactics": ["[Tactic]"],
      "subtechniques": []
    }
  ]
}
```

### Step 5: Update docs/TECHNIQUE_MAPPING.md

Add your payload to the appropriate section with:
- MITRE technique ID
- Technique name
- Tactic
- Detection opportunity
- Mitigation recommendation

---

## Adding Enhanced Payload Variants

Enhanced payloads go in `enhanced-payloads/`:

```
enhanced-payloads/
└── [technique-name]/
    ├── README.md           # Required documentation
    ├── payload-template.*  # Template file
    └── analysis.md         # (optional) Technical analysis
```

### Requirements for Enhanced Payloads
- Clear explanation of how it differs from the base technique
- Detection signatures that would catch this variant
- Mitigation strategies specific to the variant
- MITRE technique mapping

---

## Adding Emerging Technique Coverage

Emerging payloads go in `emerging-payloads/`:

```
emerging-payloads/
└── [category-name]/
    ├── README.md           # Required documentation
    ├── poc-template.*      # PoC template file
    └── defense-notes.md    # (optional) Defense notes
```

### Requirements for Emerging Payloads
- Clear threat landscape context (why is this emerging?)
- Real-world incident examples (anonymized/public)
- Detection methodology
- Defensive controls

---

## Documentation Contributions

### Updating MITRE Mappings

When MITRE ATT&CK releases new versions:
1. Check for new or updated technique IDs
2. Update `docs/TECHNIQUE_MAPPING.md`
3. Update `data/payload-techniques.json`
4. Update `docs/MITRE_REFERENCE.md`

### Adding Attack Chain Documentation

New attack chains should follow the format in `docs/PAYLOAD_CHAINING.md`:
1. ASCII flowchart of the chain
2. Stage-by-stage explanation
3. Payloads used at each stage
4. Detection opportunities
5. MITRE ATT&CK mapping
6. Mitigation strategies

---

## Tools Contributions

Tools go in the `tools/` directory:

```
tools/
└── [tool-name]/
    ├── README.md       # Tool documentation
    ├── requirements.txt # Dependencies (if Python)
    └── [tool files]
```

### Tool Requirements
- Must have a clear defensive or educational purpose
- README must include: installation, usage, examples
- Include appropriate error handling
- Comment complex code sections
- Include disclaimers about educational use

### Python Code Style
- Follow PEP 8 style guidelines
- Use type hints for function signatures
- Include docstrings for all functions
- Handle exceptions gracefully

---

## Pull Request Process

### Before Submitting

1. **Test your changes**: Verify all files are correctly formatted
2. **Check for secrets**: Ensure no real credentials, IPs, or personal data
3. **Verify file formats**: JSON/YAML files should be valid
4. **Update relevant documentation**: Keep docs in sync with code

### PR Template

When submitting a PR, include:

```markdown
## Type of Change
- [ ] New payload
- [ ] Documentation improvement
- [ ] Tool addition/update
- [ ] MITRE mapping update
- [ ] Bug fix

## Description
[Describe what you've added or changed]

## Educational Value
[Explain what defenders learn from this contribution]

## MITRE ATT&CK Coverage
[List any MITRE techniques covered or updated]

## Testing
[Describe any testing performed]

## Checklist
- [ ] Includes README.md with documentation
- [ ] Includes MITRE mapping
- [ ] Includes detection guidance
- [ ] Includes mitigation guidance
- [ ] Uses calc.exe (not actual malware)
- [ ] No real credentials or personal data
- [ ] No actual exploit code targeting specific CVEs
```

---

## Style Guidelines

### File Naming
- Directory names: Descriptive, with spaces or hyphens for readability
- Document files: `UPPERCASE_WITH_UNDERSCORES.md`
- Payload files: Descriptive names matching real-world document names
- Tool files: `lowercase-with-hyphens.py`

### Documentation
- Use clear headings (##, ###)
- Include code blocks with language specifiers
- Use tables for comparison data
- Include disclaimers in all new files
- Keep README files to the point

### PoC Code
- Include disclaimer comment at top of all scripts
- Use `calc.exe` as the benign demo payload
- Comment all significant code sections
- Include error handling

---

## Review Process

1. **Initial review** (1-2 days): Check for policy compliance and basic quality
2. **Technical review** (3-5 days): Verify technical accuracy of technique descriptions
3. **Documentation review** (1-2 days): Check documentation quality and completeness
4. **Merge**: Approved PRs are merged to main branch

---

## Questions?

- Open a GitHub Issue for questions about contribution requirements
- Use the Discussions tab for broader questions about techniques

---

## License

All contributions must be compatible with the repository's CC BY 4.0 license.
By contributing, you agree to license your contribution under CC BY 4.0.

[CC BY 4.0](https://creativecommons.org/licenses/by/4.0/)
