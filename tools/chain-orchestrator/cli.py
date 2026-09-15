#!/usr/bin/env python3
"""
Chain Builder CLI
==================
DISCLAIMER: Educational and research purposes ONLY.

Interactive CLI tool for:
- Browsing available attack chains
- Building custom chains
- Generating configuration files
- Simulating chain execution
"""

import os
import sys
import json
from pathlib import Path
from typing import Optional

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════════╗
║  DISCLAIMER: EDUCATIONAL AND RESEARCH USE ONLY                       ║
║  Use only in authorized environments with written permission         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

BANNER = """
╔══════════════════════════════════════════════╗
║     Social Engineering Chain Orchestrator    ║
║          Interactive CLI Builder             ║
╚══════════════════════════════════════════════╝
"""

PAYLOAD_CATALOG = {
    "1": {"name": "DDE CSV Payload", "type": "initial_access", "mitre": "T1566.001"},
    "2": {"name": "DDE DOCX Payload", "type": "initial_access", "mitre": "T1566.001"},
    "3": {"name": "DDE XLS Payload", "type": "initial_access", "mitre": "T1566.001"},
    "4": {"name": "LNK HTA Payload", "type": "initial_access", "mitre": "T1218.005"},
    "5": {"name": "Password Protected Document", "type": "defense_evasion", "mitre": "T1027"},
    "6": {"name": "Credential Harvest (Excel)", "type": "collection", "mitre": "T1056.003"},
    "7": {"name": "Credential Harvest (Basic Auth)", "type": "collection", "mitre": "T1187"},
    "8": {"name": "Tabnabbing Attack", "type": "collection", "mitre": "T1185"},
    "9": {"name": "Scheduled Task Persistence", "type": "persistence", "mitre": "T1053.005"},
    "10": {"name": "Internal Spearphishing", "type": "lateral_movement", "mitre": "T1534"},
    "11": {"name": "certutil Download", "type": "command_and_control", "mitre": "T1105"},
    "12": {"name": "mshta Execution", "type": "defense_evasion", "mitre": "T1218.005"},
}

PREDEFINED_CHAINS = {
    "1": "Initial Access → Credential Theft → Persistence",
    "2": "Email Phishing Multi-Format Fallback",
    "3": "PDF → Web Exploitation → C2",
    "4": "Office Macro Cascade",
    "5": "Credential Harvesting → Lateral Movement",
    "6": "Multi-Layer Social Engineering",
    "7": "Browser-Based Persistent Foothold",
    "8": "Repository-Based Supply Chain Attack",
}


class ChainBuilderCLI:
    """Interactive CLI for building and managing attack chains."""
    
    def __init__(self) -> None:
        self.custom_chain: list[dict] = []
        self.running = True
    
    def clear_screen(self) -> None:
        """Clear terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')
    
    def print_menu(self) -> None:
        """Print main menu."""
        print("\n" + "="*50)
        print("  MAIN MENU")
        print("="*50)
        print("  1. Browse predefined attack chains")
        print("  2. Build custom chain")
        print("  3. View payload catalog")
        print("  4. Validate a chain config")
        print("  5. Generate documentation")
        print("  6. Simulate chain execution")
        print("  7. About / Help")
        print("  0. Exit")
        print("="*50)
    
    def browse_chains(self) -> None:
        """Browse predefined attack chains."""
        print("\n" + "="*50)
        print("  PREDEFINED ATTACK CHAINS")
        print("="*50)
        
        for num, name in PREDEFINED_CHAINS.items():
            print(f"  {num}. {name}")
        
        print("\n  B. Back to main menu")
        
        choice = input("\nSelect chain to view details (1-8, B): ").strip().upper()
        
        if choice == 'B':
            return
        
        if choice in PREDEFINED_CHAINS:
            self._show_chain_details(choice)
        else:
            print("Invalid choice.")
    
    def _show_chain_details(self, chain_num: str) -> None:
        """Show details of a predefined chain."""
        chain_name = PREDEFINED_CHAINS.get(chain_num, "Unknown")
        
        print(f"\n{'='*50}")
        print(f"  Chain {chain_num}: {chain_name}")
        print("="*50)
        print(f"\nConfiguration file: configs/chain-config-{chain_num}.yaml")
        print("\nTo view full details:")
        print(f"  python orchestrator.py --load configs/chain-config-{chain_num}.yaml")
        print(f"\nTo generate documentation:")
        print(f"  python generate-docs.py configs/chain-config-{chain_num}.yaml")
        print(f"\nTo validate:")
        print(f"  python validate-chain.py configs/chain-config-{chain_num}.yaml")
        
        input("\nPress Enter to continue...")
    
    def view_catalog(self) -> None:
        """View available payload catalog."""
        print("\n" + "="*60)
        print("  PAYLOAD CATALOG")
        print("="*60)
        print(f"  {'#':<4} {'Payload Name':<35} {'Type':<25} {'MITRE'}")
        print("-"*75)
        
        for num, payload in PAYLOAD_CATALOG.items():
            print(f"  {num:<4} {payload['name']:<35} {payload['type']:<25} {payload['mitre']}")
        
        input("\nPress Enter to continue...")
    
    def build_custom_chain(self) -> None:
        """Interactive custom chain builder."""
        print("\n" + "="*50)
        print("  CUSTOM CHAIN BUILDER")
        print("="*50)
        
        # Get chain metadata
        print("\nChain Configuration:")
        chain_name = input("  Chain name: ").strip()
        chain_desc = input("  Description: ").strip()
        
        if not chain_name:
            print("Chain name required.")
            return
        
        self.custom_chain = []
        
        # Add stages
        print("\nAvailable payloads (enter 'done' when finished):")
        for num, payload in PAYLOAD_CATALOG.items():
            print(f"  {num}. {payload['name']} ({payload['type']})")
        
        while True:
            print("\nCurrent chain stages:", [s['name'] for s in self.custom_chain])
            choice = input("Add payload (number) or 'done': ").strip()
            
            if choice.lower() == 'done':
                break
            
            if choice in PAYLOAD_CATALOG:
                payload = PAYLOAD_CATALOG[choice].copy()
                self.custom_chain.append(payload)
                print(f"  ✓ Added: {payload['name']}")
            else:
                print("  Invalid selection.")
        
        if not self.custom_chain:
            print("No stages added. Chain not saved.")
            return
        
        # Generate configuration
        self._generate_custom_config(chain_name, chain_desc)
    
    def _generate_custom_config(self, name: str, description: str) -> None:
        """Generate YAML config for custom chain."""
        config = {
            'name': name,
            'description': description,
            'version': '1.0.0',
            'disclaimer': 'Educational and research use only. Authorized environments only.',
            'stages': []
        }
        
        for i, stage in enumerate(self.custom_chain):
            config['stages'].append({
                'name': stage['name'],
                'type': stage['type'],
                'description': f"Stage {i+1}: {stage['name']}",
                'mitre_technique': stage['mitre'],
                'payload': 'calc.exe',  # PoC payload
                'detection': f"Monitor for {stage['type']} indicators",
                'mitigation': f"Apply controls for {stage['mitre']}"
            })
        
        # Display generated config
        print("\n" + "="*50)
        print("  GENERATED CONFIGURATION")
        print("="*50)
        
        if YAML_AVAILABLE:
            print(yaml.dump(config, default_flow_style=False, sort_keys=False))
        else:
            print(json.dumps(config, indent=2))
        
        # Offer to save
        save = input("\nSave to file? (y/n): ").strip().lower()
        if save == 'y':
            filename = name.lower().replace(' ', '-') + '.yaml'
            output_path = Path('configs') / filename
            output_path.parent.mkdir(exist_ok=True)
            
            with open(output_path, 'w') as f:
                if YAML_AVAILABLE:
                    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
                else:
                    json.dump(config, f, indent=2)
            
            print(f"✓ Saved to: {output_path}")
    
    def show_help(self) -> None:
        """Show help information."""
        print("""
╔══════════════════════════════════════════════════════════════════╗
║                    CHAIN ORCHESTRATOR HELP                       ║
╠══════════════════════════════════════════════════════════════════╣
║                                                                  ║
║  This tool helps security researchers understand and document    ║
║  social engineering attack chains for defensive purposes.        ║
║                                                                  ║
║  Components:                                                     ║
║    cli.py           - This interactive CLI                       ║
║    orchestrator.py  - Chain execution engine                     ║
║    sequencer.py     - Payload dependency resolver                ║
║    validate-chain.py - Configuration validator                   ║
║    generate-docs.py - Documentation generator                    ║
║                                                                  ║
║  Configuration files: configs/chain-config-*.yaml               ║
║                                                                  ║
║  All PoC payloads use calc.exe (Windows Calculator)              ║
║                                                                  ║
║  MITRE ATT&CK references:                                        ║
║    https://attack.mitre.org/                                     ║
║                                                                  ║
║  Related documentation:                                          ║
║    ../../docs/PAYLOAD_CHAINING.md                                ║
║    ../../docs/TECHNIQUE_MAPPING.md                               ║
║    ../../docs/DEFENSE_STRATEGIES.md                              ║
╚══════════════════════════════════════════════════════════════════╝
        """)
        input("Press Enter to continue...")
    
    def run(self) -> None:
        """Run the interactive CLI."""
        print(BANNER)
        print(DISCLAIMER)
        
        while self.running:
            self.print_menu()
            
            choice = input("\nSelect option: ").strip()
            
            if choice == '1':
                self.browse_chains()
            elif choice == '2':
                self.build_custom_chain()
            elif choice == '3':
                self.view_catalog()
            elif choice == '4':
                path = input("Enter config file path: ").strip()
                print(f"\nRun: python validate-chain.py {path}")
            elif choice == '5':
                path = input("Enter config file path: ").strip()
                outdir = input("Output directory (Enter for stdout): ").strip() or None
                print(f"\nRun: python generate-docs.py {path}" + (f" {outdir}" if outdir else ""))
            elif choice == '6':
                path = input("Enter config file path: ").strip()
                print(f"\nRun: python orchestrator.py --simulate {path}")
            elif choice == '7':
                self.show_help()
            elif choice == '0':
                print("\nExiting. Stay ethical!")
                self.running = False
            else:
                print("Invalid choice. Please try again.")


def main() -> int:
    """Main entry point."""
    cli = ChainBuilderCLI()
    
    try:
        cli.run()
    except KeyboardInterrupt:
        print("\n\nInterrupted. Exiting.")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
