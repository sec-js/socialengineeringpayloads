#!/usr/bin/env python3
"""
Chain Orchestrator — Payload Chain Orchestration Engine
=========================================================
DISCLAIMER: Educational and research purposes ONLY. 
For authorized security testing and red team simulations only.

This tool reads YAML chain configuration files and orchestrates
the sequencing, validation, and documentation of payload chains.

Usage:
    python orchestrator.py --list
    python orchestrator.py --load configs/chain-config-1.yaml
    python orchestrator.py --validate configs/chain-config-1.yaml
    python orchestrator.py --report configs/chain-config-1.yaml
"""

import os
import sys
import json
import argparse
import datetime
from typing import Any
from pathlib import Path

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════╗
║  DISCLAIMER: EDUCATIONAL AND RESEARCH USE ONLY                       ║
║  Use only in authorized environments with written permission         ║
║  This tool is for understanding attack chains for defensive purposes ║
╚══════════════════════════════════════════════════════════════════════╝
"""


class ChainState:
    """Tracks the state of a chain execution."""
    
    def __init__(self, chain_id: str) -> None:
        self.chain_id = chain_id
        self.start_time = datetime.datetime.now()
        self.current_stage = 0
        self.stage_results: list[dict] = []
        self.status = "initialized"
    
    def advance_stage(self, stage_name: str, result: str) -> None:
        self.stage_results.append({
            'stage': self.current_stage,
            'name': stage_name,
            'result': result,
            'timestamp': datetime.datetime.now().isoformat()
        })
        self.current_stage += 1
    
    def to_dict(self) -> dict:
        return {
            'chain_id': self.chain_id,
            'start_time': self.start_time.isoformat(),
            'current_stage': self.current_stage,
            'status': self.status,
            'stages': self.stage_results
        }


class ChainOrchestrator:
    """
    Main orchestration engine for payload chain execution and simulation.
    
    Handles:
    - Loading chain configurations from YAML
    - Validating chain configurations
    - Sequencing payload stages
    - Generating execution reports
    """
    
    def __init__(self, configs_dir: str = "configs") -> None:
        self.configs_dir = Path(configs_dir)
        self.chain_states: dict[str, ChainState] = {}
        self.current_chain: dict = {}
    
    def load_chain(self, config_path: str) -> dict:
        """
        Load a chain configuration from YAML file.
        
        Args:
            config_path: Path to the YAML configuration file
            
        Returns:
            Chain configuration dictionary
        """
        config_file = Path(config_path)
        
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration not found: {config_path}")
        
        if not YAML_AVAILABLE:
            # Fallback: basic YAML-like parsing for simple configs
            return self._parse_simple_yaml(config_file)
        
        with open(config_file, 'r') as f:
            chain = yaml.safe_load(f)
        
        self.current_chain = chain
        print(f"✓ Loaded chain: {chain.get('name', 'Unknown')}")
        print(f"  Description: {chain.get('description', 'N/A')}")
        print(f"  Stages: {len(chain.get('stages', []))}")
        
        return chain
    
    def _parse_simple_yaml(self, config_file: Path) -> dict:
        """Basic YAML parser for environments without PyYAML."""
        print(f"[!] PyYAML not available, using basic parser for: {config_file}")
        result = {'name': config_file.stem, 'stages': []}
        
        with open(config_file, 'r') as f:
            content = f.read()
        
        # Extract name and description
        for line in content.split('\n'):
            line = line.strip()
            if line.startswith('name:'):
                result['name'] = line.split(':', 1)[1].strip().strip('"\'')
            elif line.startswith('description:'):
                result['description'] = line.split(':', 1)[1].strip().strip('"\'')
        
        return result
    
    def validate_chain(self, chain: dict) -> tuple[bool, list[str]]:
        """
        Validate a chain configuration for completeness and correctness.
        
        Args:
            chain: Chain configuration dictionary
            
        Returns:
            Tuple of (is_valid, list_of_issues)
        """
        issues = []
        
        # Required top-level fields
        required = ['name', 'description', 'stages']
        for field in required:
            if field not in chain:
                issues.append(f"Missing required field: {field}")
        
        if 'stages' in chain:
            for i, stage in enumerate(chain['stages']):
                # Each stage must have name and type
                if 'name' not in stage:
                    issues.append(f"Stage {i+1}: missing 'name'")
                if 'type' not in stage:
                    issues.append(f"Stage {i+1}: missing 'type'")
                
                # MITRE mapping recommended
                if 'mitre_technique' not in stage:
                    issues.append(f"Stage {i+1} ({stage.get('name', '?')}): missing MITRE mapping (recommended)")
        
        is_valid = not any(not i.startswith("Stage") or "missing MITRE" not in i for i in issues if "Missing required" in i)
        return len([i for i in issues if "Missing required" in i]) == 0, issues
    
    def simulate_chain(self, chain: dict, dry_run: bool = True) -> ChainState:
        """
        Simulate execution of a chain (dry run by default).
        
        In dry_run mode, only logs what would happen.
        In actual mode, would execute each stage.
        
        Args:
            chain: Chain configuration
            dry_run: If True, only simulate (default: True, always use True for safety)
            
        Returns:
            ChainState with execution results
        """
        chain_id = chain.get('id', 'chain_001')
        state = ChainState(chain_id)
        state.status = "running"
        
        print(f"\n{'='*50}")
        print(f"Chain Simulation: {chain.get('name', 'Unknown')}")
        print(f"Mode: {'DRY RUN (simulation only)' if dry_run else 'EXECUTION'}")
        print(f"{'='*50}\n")
        
        for i, stage in enumerate(chain.get('stages', [])):
            print(f"Stage {i+1}: {stage.get('name', 'Unknown')}")
            print(f"  Type: {stage.get('type', 'N/A')}")
            print(f"  Description: {stage.get('description', 'N/A')}")
            print(f"  MITRE: {stage.get('mitre_technique', 'N/A')}")
            
            if dry_run:
                print(f"  [DRY RUN] Would execute: {stage.get('payload', 'N/A')}")
                state.advance_stage(stage.get('name', f'stage_{i}'), 'simulated')
            
            print()
        
        state.status = "completed" if dry_run else "executed"
        self.chain_states[chain_id] = state
        
        return state
    
    def generate_report(self, chain: dict, state: ChainState = None) -> str:
        """
        Generate an execution/analysis report for a chain.
        
        Args:
            chain: Chain configuration
            state: Optional execution state
            
        Returns:
            Formatted report string
        """
        report_lines = [
            "# Chain Execution Report",
            f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            f"## Chain: {chain.get('name', 'Unknown')}",
            f"**Description**: {chain.get('description', 'N/A')}",
            f"**Category**: {chain.get('category', 'N/A')}",
            "",
            "## Stage Summary",
            "",
        ]
        
        for i, stage in enumerate(chain.get('stages', [])):
            report_lines.extend([
                f"### Stage {i+1}: {stage.get('name', 'Unknown')}",
                f"- **Type**: {stage.get('type', 'N/A')}",
                f"- **MITRE**: {stage.get('mitre_technique', 'N/A')}",
                f"- **Description**: {stage.get('description', 'N/A')}",
                f"- **Detection**: {stage.get('detection', 'See TECHNIQUE_MAPPING.md')}",
                "",
            ])
        
        if state:
            report_lines.extend([
                "## Execution State",
                f"- **Status**: {state.status}",
                f"- **Stages completed**: {state.current_stage}",
                ""
            ])
        
        report_lines.extend([
            "## Mitigation Recommendations",
            "",
            "See the following resources:",
            "- `docs/DEFENSE_STRATEGIES.md` — Comprehensive defense guide",
            "- `docs/TECHNIQUE_MAPPING.md` — MITRE ATT&CK mappings",
            "- `docs/PAYLOAD_CHAINING.md` — Chain-specific mitigations",
        ])
        
        return '\n'.join(report_lines)
    
    def list_configs(self) -> list[str]:
        """List available chain configurations."""
        if not self.configs_dir.exists():
            print(f"Configs directory not found: {self.configs_dir}")
            return []
        
        configs = list(self.configs_dir.glob("*.yaml")) + list(self.configs_dir.glob("*.yml"))
        return [str(c) for c in sorted(configs)]


def main() -> int:
    """Main entry point for the orchestrator CLI."""
    print(DISCLAIMER)
    
    parser = argparse.ArgumentParser(
        description='Chain Orchestrator — Payload chain management tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python orchestrator.py --list
  python orchestrator.py --load configs/chain-config-1.yaml
  python orchestrator.py --validate configs/chain-config-1.yaml
  python orchestrator.py --simulate configs/chain-config-1.yaml
  python orchestrator.py --report configs/chain-config-1.yaml
        """
    )
    
    parser.add_argument('--list', action='store_true', help='List available chain configurations')
    parser.add_argument('--load', metavar='FILE', help='Load a chain configuration')
    parser.add_argument('--validate', metavar='FILE', help='Validate a chain configuration')
    parser.add_argument('--simulate', metavar='FILE', help='Simulate chain execution (dry run)')
    parser.add_argument('--report', metavar='FILE', help='Generate chain report')
    parser.add_argument('--output', metavar='FILE', help='Output file for report')
    
    args = parser.parse_args()
    
    orchestrator = ChainOrchestrator()
    
    if args.list:
        configs = orchestrator.list_configs()
        if configs:
            print("Available chain configurations:")
            for c in configs:
                print(f"  - {c}")
        else:
            print("No chain configurations found in configs/ directory")
        return 0
    
    if args.load:
        try:
            chain = orchestrator.load_chain(args.load)
            print(f"\n✓ Successfully loaded: {args.load}")
            return 0
        except Exception as e:
            print(f"✗ Error loading config: {e}")
            return 1
    
    if args.validate:
        try:
            chain = orchestrator.load_chain(args.validate)
            is_valid, issues = orchestrator.validate_chain(chain)
            
            if is_valid:
                print(f"\n✓ Chain configuration is valid")
            else:
                print(f"\n✗ Chain configuration has issues:")
            
            for issue in issues:
                icon = "⚠️" if "recommended" in issue else "✗"
                print(f"  {icon} {issue}")
            
            return 0 if is_valid else 1
        except Exception as e:
            print(f"✗ Error: {e}")
            return 1
    
    if args.simulate:
        try:
            chain = orchestrator.load_chain(args.simulate)
            state = orchestrator.simulate_chain(chain, dry_run=True)
            print(f"\n✓ Simulation complete. {state.current_stage} stages processed.")
            return 0
        except Exception as e:
            print(f"✗ Error: {e}")
            return 1
    
    if args.report:
        try:
            chain = orchestrator.load_chain(args.report)
            report = orchestrator.generate_report(chain)
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(report)
                print(f"✓ Report written to: {args.output}")
            else:
                print(report)
            return 0
        except Exception as e:
            print(f"✗ Error: {e}")
            return 1
    
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
