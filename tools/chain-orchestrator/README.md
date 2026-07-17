# Chain Orchestrator

> **⚠️ DISCLAIMER**: This tool is for **educational and research purposes ONLY**.
> Use only in authorized environments with written permission.

A framework for understanding, documenting, and simulating social engineering attack chains
for defensive security research and red team exercises.

---

## Overview

The Chain Orchestrator provides:
- **Configuration-driven** attack chain definitions
- **Validation** of chain configurations for completeness
- **Documentation generation** including ASCII flowcharts
- **Simulation** of chain execution (dry run only)
- **Interactive CLI** for exploring and building chains

---

## Installation

### Prerequisites

```bash
# Python 3.8+
python --version

# Install dependencies
pip install -r requirements.txt
```

### Optional: PyYAML

Without PyYAML, the tool operates with limited functionality:

```bash
pip install pyyaml
```

---

## Quick Start

```bash
# List available chains
python orchestrator.py --list

# Load and inspect a chain
python orchestrator.py --load configs/chain-config-1.yaml

# Validate a chain configuration
python validate-chain.py configs/chain-config-1.yaml

# Generate documentation
python generate-docs.py configs/chain-config-1.yaml

# Simulate execution (dry run only)
python orchestrator.py --simulate configs/chain-config-1.yaml

# Interactive CLI
python cli.py
```

---

## Tool Reference

### orchestrator.py — Chain Execution Engine

```
Usage: python orchestrator.py [OPTIONS]

Options:
  --list              List all available chain configurations
  --load FILE         Load and display a chain configuration
  --validate FILE     Validate a chain configuration
  --simulate FILE     Simulate chain execution (dry run)
  --report FILE       Generate execution report
  --output FILE       Save report to file

Examples:
  python orchestrator.py --list
  python orchestrator.py --simulate configs/chain-config-1.yaml
  python orchestrator.py --report configs/chain-config-3.yaml --output report.md
```

---

### validate-chain.py — Configuration Validator

```
Usage: python validate-chain.py [FILE | --all [DIR]]

Options:
  FILE                Validate a specific configuration file
  --all [DIR]         Validate all configs in directory (default: configs/)

Validation checks:
  - Required fields (name, description, version, stages)
  - Stage required fields (name, type, description)
  - MITRE ATT&CK technique format
  - Stage type validity

Examples:
  python validate-chain.py configs/chain-config-1.yaml
  python validate-chain.py --all
  python validate-chain.py --all configs/
```

---

### generate-docs.py — Documentation Generator

```
Usage: python generate-docs.py FILE [OUTPUT_DIR]

Generates:
  - ASCII flowchart (chain-name-flowchart.md)
  - Execution guide (chain-name-execution-guide.md)
  - MITRE summary table (chain-name-mitre-summary.md)

Examples:
  python generate-docs.py configs/chain-config-1.yaml
  python generate-docs.py configs/chain-config-1.yaml output/
```

---

### sequencer.py — Payload Sequencer

```
Usage: python sequencer.py

Demonstrates dependency-based payload sequencing.
Modify the example_chain list to sequence different payloads.
```

---

### cli.py — Interactive CLI

```
Usage: python cli.py

Interactive menu-driven interface for:
- Browsing predefined chains
- Building custom chains
- Viewing payload catalog
- Launching other tools
```

---

## Configuration Format

Chain configurations are YAML files with the following structure:

```yaml
name: "Chain Name"
version: "1.0.0"
description: "What this chain does"
category: "chain-category"
disclaimer: "Educational and research use only."

stages:
  - name: "Stage Name"
    type: "initial_access"          # MITRE tactic (lowercase with underscores)
    description: "What this stage does"
    mitre_technique: "T1566.001"    # MITRE ATT&CK technique ID
    payload: "path/to/payload"       # Payload reference
    detection: "How to detect this"  # Detection indicator
    mitigation: "How to prevent"     # Mitigation control
```

### Valid Stage Types

| Type | MITRE Tactic |
|------|--------------|
| `initial_access` | Initial Access |
| `execution` | Execution |
| `persistence` | Persistence |
| `privilege_escalation` | Privilege Escalation |
| `defense_evasion` | Defense Evasion |
| `collection` | Collection |
| `exfiltration` | Exfiltration |
| `command_and_control` | Command & Control |
| `lateral_movement` | Lateral Movement |
| `reconnaissance` | Reconnaissance |
| `resource_development` | Resource Development |

---

## Pre-built Chain Configurations

| File | Chain Name | Techniques |
|------|------------|------------|
| `chain-config-1.yaml` | Initial Access → Credential Theft → Persistence | T1566.001, T1204.002, T1056.003, T1078, T1053.005 |
| `chain-config-2.yaml` | Email Phishing Multi-Format Fallback | T1566.001, T1566.002, T1608, T1185 |
| `chain-config-3.yaml` | PDF → Web → C2 | T1566.001, T1189, T1105, T1071.001 |
| `chain-config-4.yaml` | Office Macro Cascade | T1027, T1059.005, T1105, T1547.001 |
| `chain-config-5.yaml` | Credential Harvesting → Lateral Movement | T1598, T1056.003, T1185, T1078, T1534 |
| `chain-config-6.yaml` | Multi-Layer Social Engineering | T1598.004, T1566.001, T1204.002 |
| `chain-config-7.yaml` | Browser-Based Persistent Foothold | T1566.002, T1176, T1539, T1041 |
| `chain-config-8.yaml` | Supply Chain Attack | T1592, T1195.001, T1059.007, T1552 |

---

## Advanced Usage

### Creating Custom Chains

1. Copy an existing config:
   ```bash
   cp configs/chain-config-1.yaml configs/my-custom-chain.yaml
   ```

2. Edit the configuration:
   ```bash
   nano configs/my-custom-chain.yaml
   ```

3. Validate your chain:
   ```bash
   python validate-chain.py configs/my-custom-chain.yaml
   ```

4. Generate documentation:
   ```bash
   python generate-docs.py configs/my-custom-chain.yaml output/
   ```

### Batch Operations

```bash
# Validate all configs
python validate-chain.py --all

# Generate docs for all chains
for f in configs/*.yaml; do
    python generate-docs.py "$f" output/
done
```

---

## Related Documentation

- [../../docs/PAYLOAD_CHAINING.md](../../docs/PAYLOAD_CHAINING.md) — Attack chain flowcharts
- [../../docs/TECHNIQUE_MAPPING.md](../../docs/TECHNIQUE_MAPPING.md) — MITRE ATT&CK mappings
- [../../docs/DEFENSE_STRATEGIES.md](../../docs/DEFENSE_STRATEGIES.md) — Defense guidance
- [../../data/payload-techniques.json](../../data/payload-techniques.json) — Structured data

---

## License

CC BY 4.0 — Educational use only. See repository root for full license.
