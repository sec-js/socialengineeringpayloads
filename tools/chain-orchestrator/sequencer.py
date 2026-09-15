#!/usr/bin/env python3
"""
Payload Sequencer — Determine Optimal Payload Order
=====================================================
DISCLAIMER: Educational and research purposes ONLY.

Analyzes payload dependencies and determines the optimal execution order
for a given set of payloads in a chain.
"""

import sys
import json
from typing import Optional
from pathlib import Path


PAYLOAD_METADATA = {
    "dde-csv": {
        "name": "DDE CSV Payload",
        "type": "initial_access",
        "platform": ["windows"],
        "requires": [],
        "provides": ["code_execution"],
        "mitre": "T1566.001"
    },
    "dde-docx": {
        "name": "DDE DOCX Payload",
        "type": "initial_access",
        "platform": ["windows"],
        "requires": [],
        "provides": ["code_execution"],
        "mitre": "T1566.001"
    },
    "credential-excel": {
        "name": "Credential Harvest (Excel)",
        "type": "collection",
        "platform": ["windows", "linux", "macos"],
        "requires": [],
        "provides": ["credentials"],
        "mitre": "T1056.003"
    },
    "tabnabbing": {
        "name": "Tabnabbing Attack",
        "type": "collection",
        "platform": ["windows", "linux", "macos"],
        "requires": ["link_delivery"],
        "provides": ["credentials", "session_token"],
        "mitre": "T1185"
    },
    "persistence-schtask": {
        "name": "Scheduled Task Persistence",
        "type": "persistence",
        "platform": ["windows"],
        "requires": ["code_execution"],
        "provides": ["persistence"],
        "mitre": "T1053.005"
    },
    "lateral-internal-phish": {
        "name": "Internal Spearphishing",
        "type": "lateral_movement",
        "platform": ["windows", "linux", "macos"],
        "requires": ["credentials", "email_access"],
        "provides": ["lateral_access"],
        "mitre": "T1534"
    }
}


class PayloadSequencer:
    """
    Determines optimal payload ordering based on dependencies.
    
    Uses topological sort to ensure prerequisites are satisfied
    before dependent payloads are deployed.
    """
    
    def __init__(self) -> None:
        self.payloads = PAYLOAD_METADATA.copy()
    
    def load_custom_payloads(self, data_path: str) -> None:
        """Load custom payload definitions from data file."""
        path = Path(data_path)
        if path.exists():
            with open(path, 'r') as f:
                data = json.load(f)
            # Convert from payload-techniques.json format
            for p in data.get('payloads', []):
                self.payloads[p['id']] = {
                    'name': p['name'],
                    'type': p.get('category', 'unknown'),
                    'platform': p.get('platform', ['windows']),
                    'requires': [],
                    'provides': [],
                    'mitre': p.get('techniques', [{}])[0].get('mitre_id', 'N/A') if p.get('techniques') else 'N/A'
                }
    
    def check_prerequisites(self, payload_id: str, available_capabilities: list[str]) -> tuple[bool, list[str]]:
        """
        Check if prerequisites for a payload are satisfied.
        
        Args:
            payload_id: ID of the payload to check
            available_capabilities: Currently available capabilities
            
        Returns:
            Tuple of (can_execute, missing_prerequisites)
        """
        payload = self.payloads.get(payload_id)
        if not payload:
            return False, [f"Unknown payload: {payload_id}"]
        
        missing = []
        for req in payload.get('requires', []):
            if req not in available_capabilities:
                missing.append(req)
        
        return len(missing) == 0, missing
    
    def sequence_payloads(self, payload_ids: list[str], 
                          target_platform: str = "windows") -> list[dict]:
        """
        Determine the optimal execution order for a list of payloads.
        
        Uses topological sort based on capability dependencies.
        
        Args:
            payload_ids: List of payload IDs to sequence
            target_platform: Target platform filter
            
        Returns:
            Ordered list of payload execution instructions
        """
        # Filter to compatible payloads
        compatible = []
        for pid in payload_ids:
            p = self.payloads.get(pid)
            if p and (target_platform in p.get('platform', []) or 
                      'all' in p.get('platform', [])):
                compatible.append(pid)
            elif p:
                print(f"[!] Skipping {pid}: not compatible with {target_platform}")
        
        # Topological sort by capability dependencies
        ordered = []
        available_capabilities: list[str] = []
        remaining = list(compatible)
        max_iterations = len(remaining) * 2
        iterations = 0
        
        while remaining and iterations < max_iterations:
            iterations += 1
            progress_made = False
            
            for pid in list(remaining):
                can_exec, missing = self.check_prerequisites(pid, available_capabilities)
                if can_exec:
                    payload = self.payloads[pid]
                    ordered.append({
                        'id': pid,
                        'name': payload['name'],
                        'type': payload['type'],
                        'mitre': payload.get('mitre', 'N/A'),
                        'provides': payload.get('provides', []),
                        'execution_order': len(ordered) + 1
                    })
                    available_capabilities.extend(payload.get('provides', []))
                    remaining.remove(pid)
                    progress_made = True
            
            if not progress_made and remaining:
                # Circular dependency or unresolvable requirements
                print(f"[!] Cannot resolve dependencies for: {remaining}")
                # Add remaining payloads anyway (may have unmet deps)
                for pid in remaining:
                    ordered.append({
                        'id': pid,
                        'name': self.payloads.get(pid, {}).get('name', pid),
                        'type': self.payloads.get(pid, {}).get('type', 'unknown'),
                        'mitre': self.payloads.get(pid, {}).get('mitre', 'N/A'),
                        'warning': 'Prerequisites may not be met',
                        'execution_order': len(ordered) + 1
                    })
                break
        
        return ordered
    
    def generate_delivery_instructions(self, ordered_payloads: list[dict]) -> str:
        """
        Generate human-readable delivery instructions for an ordered payload sequence.
        
        Args:
            ordered_payloads: Ordered list from sequence_payloads()
            
        Returns:
            Formatted delivery instructions string
        """
        lines = [
            "# Payload Delivery Instructions",
            "## DISCLAIMER: For authorized red team use only",
            "",
            f"Total stages: {len(ordered_payloads)}",
            "",
        ]
        
        for p in ordered_payloads:
            lines.extend([
                f"## Stage {p['execution_order']}: {p['name']}",
                f"- **ID**: {p['id']}",
                f"- **Type**: {p['type']}",
                f"- **MITRE**: {p['mitre']}",
            ])
            
            if 'warning' in p:
                lines.append(f"- **⚠️ Warning**: {p['warning']}")
            
            lines.extend([
                f"- **Provides**: {', '.join(p.get('provides', []))}",
                "",
            ])
        
        lines.extend([
            "## Detection Notes",
            "Each stage has detectable indicators — see `docs/TECHNIQUE_MAPPING.md`",
        ])
        
        return '\n'.join(lines)
    
    def print_dependency_graph(self, payload_ids: list[str]) -> None:
        """Print ASCII dependency graph for visual analysis."""
        print("\nDependency Graph:")
        print("=" * 40)
        
        for pid in payload_ids:
            p = self.payloads.get(pid, {})
            print(f"\n{pid} ({p.get('name', 'Unknown')})")
            
            requires = p.get('requires', [])
            provides = p.get('provides', [])
            
            if requires:
                for req in requires:
                    print(f"  ← Requires: {req}")
            else:
                print(f"  ← No prerequisites")
            
            if provides:
                for prov in provides:
                    print(f"  → Provides: {prov}")


def main() -> None:
    """Demonstrate the sequencer functionality."""
    print("Payload Sequencer — Demonstration")
    print("=" * 40)
    
    sequencer = PayloadSequencer()
    
    # Example: sequence a credential harvesting chain
    example_chain = [
        "dde-csv",
        "persistence-schtask",  # Depends on code_execution
        "credential-excel",
        "tabnabbing",
    ]
    
    print(f"\nInput payloads: {example_chain}")
    print("\nAnalyzing dependencies...")
    
    sequencer.print_dependency_graph(example_chain)
    
    print("\nOptimal execution order:")
    ordered = sequencer.sequence_payloads(example_chain)
    
    for p in ordered:
        print(f"  {p['execution_order']}. {p['name']} (MITRE: {p['mitre']})")
    
    print("\nDelivery Instructions:")
    instructions = sequencer.generate_delivery_instructions(ordered)
    print(instructions)


if __name__ == "__main__":
    main()
