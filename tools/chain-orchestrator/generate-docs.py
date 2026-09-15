#!/usr/bin/env python3
"""
Documentation Generator
========================
DISCLAIMER: Educational and research purposes ONLY.

Auto-generates documentation including:
- ASCII attack chain flowcharts
- Execution guides
- MITRE ATT&CK summary tables
- Target-specific documentation
"""

import sys
import os
from pathlib import Path
from typing import Any

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║  DISCLAIMER: EDUCATIONAL AND RESEARCH USE ONLY                   ║
╚══════════════════════════════════════════════════════════════════╝
"""


class DocGenerator:
    """Generates documentation from chain configuration files."""
    
    def __init__(self) -> None:
        self.generated_docs: list[str] = []
    
    def load_chain(self, config_path: str) -> dict:
        """Load chain configuration."""
        path = Path(config_path)
        if not path.exists():
            raise FileNotFoundError(f"Config not found: {config_path}")
        
        if YAML_AVAILABLE:
            with open(path, 'r') as f:
                return yaml.safe_load(f)
        else:
            # Return minimal structure if no YAML
            return {'name': path.stem, 'stages': [], 'description': '(YAML parser required)'}
    
    def generate_ascii_flowchart(self, chain: dict) -> str:
        """
        Generate an ASCII flowchart for a chain configuration.
        
        Args:
            chain: Chain configuration dictionary
            
        Returns:
            ASCII art flowchart string
        """
        stages = chain.get('stages', [])
        name = chain.get('name', 'Attack Chain')
        
        lines = [
            f"# ASCII Flowchart: {name}",
            "",
            "```",
            f"[START: {name}]",
        ]
        
        for i, stage in enumerate(stages):
            stage_name = stage.get('name', f'Stage {i+1}')
            stage_type = stage.get('type', 'unknown').upper()
            mitre = stage.get('mitre_technique', 'N/A')
            
            # Draw connector
            if i > 0:
                lines.append("    |")
                lines.append("    v")
            
            # Draw stage box
            box_width = max(len(stage_name) + 4, 30)
            border = "+" + "-" * box_width + "+"
            
            lines.extend([
                border,
                f"| Stage {i+1}: {stage_name:<{box_width - 10}}|",
                f"| Type: {stage_type:<{box_width - 7}}|",
                f"| MITRE: {mitre:<{box_width - 8}}|",
                border,
            ])
            
            # Add detection point
            if stage.get('detection'):
                lines.append(f"    ← Detection: {stage.get('detection', 'N/A')[:40]}")
        
        lines.extend(["    |", "    v", "[END]", "```"])
        
        return '\n'.join(lines)
    
    def generate_execution_guide(self, chain: dict) -> str:
        """
        Generate a step-by-step execution guide for a chain.
        
        Args:
            chain: Chain configuration
            
        Returns:
            Formatted execution guide
        """
        lines = [
            f"# Execution Guide: {chain.get('name', 'Unknown')}",
            "",
            f"> **Version**: {chain.get('version', '1.0.0')}  ",
            f"> **Description**: {chain.get('description', 'N/A')}",
            f"> **Category**: {chain.get('category', 'N/A')}",
            "",
            "---",
            "",
            "## ⚠️ Authorization Requirements",
            "Before executing this chain:",
            "- [ ] Written authorization from target organization",
            "- [ ] Defined scope and rules of engagement",
            "- [ ] Emergency contact established",
            "- [ ] Change management approval",
            "",
            "---",
            "",
            "## Pre-Execution Checklist",
            "",
        ]
        
        prereqs = chain.get('prerequisites', [])
        if prereqs:
            for prereq in prereqs:
                lines.append(f"- [ ] {prereq}")
        else:
            lines.extend([
                "- [ ] Target environment reachable",
                "- [ ] Required tools available",
                "- [ ] Logging/capture infrastructure ready",
            ])
        
        lines.extend(["", "---", "", "## Stage-by-Stage Guide", ""])
        
        for i, stage in enumerate(chain.get('stages', [])):
            lines.extend([
                f"### Stage {i+1}: {stage.get('name', 'Unknown')}",
                "",
                f"**Type**: {stage.get('type', 'N/A')}  ",
                f"**MITRE**: [{stage.get('mitre_technique', 'N/A')}](https://attack.mitre.org/techniques/{stage.get('mitre_technique', 'T0000').replace('.', '/')}/)  ",
                f"**Description**: {stage.get('description', 'N/A')}",
                "",
            ])
            
            if stage.get('payload'):
                lines.extend([
                    "**Payload**:",
                    f"```",
                    f"{stage.get('payload', 'N/A')}",
                    "```",
                    "",
                ])
            
            if stage.get('detection'):
                lines.extend([
                    "**Detection Indicator**:",
                    f"> {stage.get('detection', 'N/A')}",
                    "",
                ])
            
            if stage.get('mitigation'):
                lines.extend([
                    "**Mitigation**:",
                    f"> {stage.get('mitigation', 'N/A')}",
                    "",
                ])
            
            lines.append("---")
            lines.append("")
        
        lines.extend([
            "## Post-Execution",
            "",
            "- [ ] Document all findings",
            "- [ ] Clean up any deployed payloads",
            "- [ ] Generate final report",
            "- [ ] Debrief with target team",
        ])
        
        return '\n'.join(lines)
    
    def generate_mitre_summary(self, chain: dict) -> str:
        """Generate MITRE ATT&CK technique summary table."""
        lines = [
            f"# MITRE ATT&CK Summary: {chain.get('name', 'Unknown')}",
            "",
            "| Stage | Technique ID | Technique Name | Tactic | Detection |",
            "|-------|-------------|----------------|--------|-----------|",
        ]
        
        for i, stage in enumerate(chain.get('stages', [])):
            mitre = stage.get('mitre_technique', 'N/A')
            stage_name = stage.get('name', f'Stage {i+1}')
            stage_type = stage.get('type', 'unknown')
            detection = stage.get('detection', 'See TECHNIQUE_MAPPING.md')[:40]
            
            lines.append(
                f"| {i+1} | {mitre} | {stage_name} | {stage_type} | {detection} |"
            )
        
        return '\n'.join(lines)
    
    def generate_all_docs(self, config_path: str, output_dir: str = None) -> dict[str, str]:
        """
        Generate all documentation for a chain configuration.
        
        Args:
            config_path: Path to YAML config
            output_dir: Optional directory to write files to
            
        Returns:
            Dictionary of filename → content
        """
        chain = self.load_chain(config_path)
        chain_name = chain.get('name', 'unknown').lower().replace(' ', '-')
        
        docs = {
            f"{chain_name}-flowchart.md": self.generate_ascii_flowchart(chain),
            f"{chain_name}-execution-guide.md": self.generate_execution_guide(chain),
            f"{chain_name}-mitre-summary.md": self.generate_mitre_summary(chain),
        }
        
        if output_dir:
            out_path = Path(output_dir)
            out_path.mkdir(parents=True, exist_ok=True)
            
            for filename, content in docs.items():
                file_path = out_path / filename
                with open(file_path, 'w') as f:
                    f.write(content)
                print(f"✓ Written: {file_path}")
        
        return docs


def main() -> int:
    """Main entry point."""
    print(DISCLAIMER)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python generate-docs.py <config-file>              # Print docs to stdout")
        print("  python generate-docs.py <config-file> <output-dir> # Write docs to directory")
        return 1
    
    config_path = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else None
    
    generator = DocGenerator()
    
    try:
        docs = generator.generate_all_docs(config_path, output_dir)
        
        if not output_dir:
            for filename, content in docs.items():
                print(f"\n{'='*60}")
                print(f"File: {filename}")
                print('='*60)
                print(content)
    except FileNotFoundError as e:
        print(f"✗ Error: {e}")
        return 1
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
