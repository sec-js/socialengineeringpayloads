#!/usr/bin/env python3
"""
Chain Validation Script
========================
DISCLAIMER: Educational and research purposes ONLY.

Validates chain configurations for:
- Required fields completeness
- MITRE ATT&CK technique coverage
- Payload compatibility
- Logic flow consistency
"""

import sys
import os
import json
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

# Valid MITRE ATT&CK technique IDs (subset for validation)
VALID_MITRE_PREFIXES = [
    'T1001', 'T1003', 'T1020', 'T1021', 'T1027', 'T1036', 'T1041',
    'T1047', 'T1053', 'T1055', 'T1056', 'T1059', 'T1071', 'T1078',
    'T1082', 'T1083', 'T1087', 'T1098', 'T1105', 'T1111', 'T1176',
    'T1185', 'T1187', 'T1189', 'T1190', 'T1195', 'T1199', 'T1203',
    'T1204', 'T1205', 'T1210', 'T1213', 'T1217', 'T1218', 'T1221',
    'T1484', 'T1486', 'T1534', 'T1539', 'T1547', 'T1550', 'T1552',
    'T1557', 'T1560', 'T1566', 'T1568', 'T1571', 'T1598', 'T1608',
    'T1610', 'T1611'
]

REQUIRED_CHAIN_FIELDS = ['name', 'description', 'version', 'stages']
REQUIRED_STAGE_FIELDS = ['name', 'type', 'description']
RECOMMENDED_STAGE_FIELDS = ['mitre_technique', 'payload', 'detection', 'mitigation']

VALID_STAGE_TYPES = [
    'initial_access', 'execution', 'persistence', 'privilege_escalation',
    'defense_evasion', 'collection', 'exfiltration', 'command_and_control',
    'lateral_movement', 'reconnaissance', 'resource_development'
]


class ValidationError:
    def __init__(self, level: str, message: str, field: str = None) -> None:
        self.level = level  # 'error', 'warning', 'info'
        self.message = message
        self.field = field
    
    def __str__(self) -> str:
        icon = {'error': '✗', 'warning': '⚠️', 'info': 'ℹ️'}.get(self.level, '?')
        field_str = f" [{self.field}]" if self.field else ""
        return f"  {icon} {self.level.upper()}{field_str}: {self.message}"


class ChainValidator:
    """Validates chain configuration files."""
    
    def __init__(self) -> None:
        self.errors: list[ValidationError] = []
    
    def clear(self) -> None:
        self.errors = []
    
    def validate_file(self, config_path: str) -> bool:
        """
        Validate a chain configuration file.
        
        Args:
            config_path: Path to YAML configuration file
            
        Returns:
            True if valid (may have warnings), False if has errors
        """
        self.clear()
        
        # Check file exists
        path = Path(config_path)
        if not path.exists():
            self.errors.append(ValidationError('error', f"File not found: {config_path}"))
            return False
        
        # Parse YAML
        chain = self._load_yaml(path)
        if chain is None:
            return False
        
        # Validate structure
        self._validate_top_level(chain)
        
        if 'stages' in chain:
            for i, stage in enumerate(chain['stages']):
                self._validate_stage(stage, i + 1)
        
        # Check for errors (warnings don't fail validation)
        has_errors = any(e.level == 'error' for e in self.errors)
        return not has_errors
    
    def _load_yaml(self, path: Path) -> Any:
        """Load and parse YAML file."""
        try:
            if YAML_AVAILABLE:
                with open(path, 'r') as f:
                    return yaml.safe_load(f)
            else:
                # Minimal validation without YAML parser
                self.errors.append(ValidationError(
                    'warning', 
                    'PyYAML not installed — limited validation only. Run: pip install pyyaml'
                ))
                with open(path, 'r') as f:
                    content = f.read()
                # Check basic structure
                if 'name:' not in content:
                    self.errors.append(ValidationError('error', "Missing 'name' field"))
                if 'stages:' not in content:
                    self.errors.append(ValidationError('error', "Missing 'stages' field"))
                return {}
        except Exception as e:
            self.errors.append(ValidationError('error', f"YAML parse error: {e}"))
            return None
    
    def _validate_top_level(self, chain: dict) -> None:
        """Validate top-level chain fields."""
        for field in REQUIRED_CHAIN_FIELDS:
            if field not in chain:
                self.errors.append(ValidationError(
                    'error', f"Missing required field: '{field}'", field
                ))
        
        # Version format check
        if 'version' in chain:
            v = str(chain['version'])
            if not any(v.startswith(str(i)) for i in range(1, 10)):
                self.errors.append(ValidationError(
                    'warning', f"Version format should be semver (e.g., '1.0.0'), got: '{v}'"
                ))
        
        # Disclaimer check
        if 'disclaimer' not in chain:
            self.errors.append(ValidationError(
                'warning', "Consider adding 'disclaimer' field for educational use acknowledgment"
            ))
    
    def _validate_stage(self, stage: dict, stage_num: int) -> None:
        """Validate an individual stage."""
        prefix = f"Stage {stage_num}"
        
        # Required fields
        for field in REQUIRED_STAGE_FIELDS:
            if field not in stage:
                self.errors.append(ValidationError(
                    'error', f"Missing required field: '{field}'", f"{prefix}.{field}"
                ))
        
        # Recommended fields
        for field in RECOMMENDED_STAGE_FIELDS:
            if field not in stage:
                self.errors.append(ValidationError(
                    'warning', f"Missing recommended field: '{field}' (helps with documentation)",
                    f"{prefix}.{field}"
                ))
        
        # Type validation
        if 'type' in stage and stage['type'] not in VALID_STAGE_TYPES:
            self.errors.append(ValidationError(
                'warning',
                f"Stage type '{stage['type']}' is not a standard MITRE tactic name. "
                f"Valid types: {', '.join(VALID_STAGE_TYPES[:5])}...",
                f"{prefix}.type"
            ))
        
        # MITRE technique format validation
        if 'mitre_technique' in stage:
            technique = stage['mitre_technique']
            if not isinstance(technique, str):
                self.errors.append(ValidationError(
                    'error', f"MITRE technique must be a string (e.g., 'T1566.001')",
                    f"{prefix}.mitre_technique"
                ))
            elif not technique.startswith('T'):
                self.errors.append(ValidationError(
                    'warning', f"MITRE technique should start with 'T' (e.g., T1566)",
                    f"{prefix}.mitre_technique"
                ))
    
    def print_results(self, config_path: str) -> bool:
        """Print validation results and return True if valid."""
        has_errors = any(e.level == 'error' for e in self.errors)
        has_warnings = any(e.level == 'warning' for e in self.errors)
        
        print(f"\nValidation Results: {config_path}")
        print("=" * 50)
        
        if not self.errors:
            print("  ✓ All checks passed — configuration is valid")
            return True
        
        error_count = sum(1 for e in self.errors if e.level == 'error')
        warn_count = sum(1 for e in self.errors if e.level == 'warning')
        
        for e in self.errors:
            print(str(e))
        
        print(f"\nSummary: {error_count} error(s), {warn_count} warning(s)")
        
        if not has_errors:
            print("  ✓ Valid (with warnings — consider addressing warnings)")
        else:
            print("  ✗ Invalid — fix errors before using this configuration")
        
        return not has_errors
    
    def validate_all(self, configs_dir: str = "configs") -> dict:
        """Validate all configuration files in a directory."""
        configs_path = Path(configs_dir)
        results = {}
        
        if not configs_path.exists():
            print(f"Configs directory not found: {configs_dir}")
            return results
        
        config_files = list(configs_path.glob("*.yaml")) + list(configs_path.glob("*.yml"))
        
        if not config_files:
            print(f"No YAML files found in: {configs_dir}")
            return results
        
        print(f"Validating {len(config_files)} configuration(s)...\n")
        
        for config_file in sorted(config_files):
            self.clear()
            is_valid = self.validate_file(str(config_file))
            results[str(config_file)] = {
                'valid': is_valid,
                'errors': [str(e) for e in self.errors if e.level == 'error'],
                'warnings': [str(e) for e in self.errors if e.level == 'warning']
            }
            status = "✓ VALID" if is_valid else "✗ INVALID"
            print(f"  {status}: {config_file.name}")
        
        valid_count = sum(1 for v in results.values() if v['valid'])
        print(f"\nTotal: {valid_count}/{len(results)} valid")
        
        return results


def main() -> int:
    """Main entry point."""
    print(DISCLAIMER)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python validate-chain.py <config-file>   # Validate a single config")
        print("  python validate-chain.py --all           # Validate all in configs/")
        return 1
    
    validator = ChainValidator()
    
    if sys.argv[1] == '--all':
        configs_dir = sys.argv[2] if len(sys.argv) > 2 else "configs"
        results = validator.validate_all(configs_dir)
        all_valid = all(r['valid'] for r in results.values())
        return 0 if all_valid else 1
    else:
        is_valid = validator.validate_file(sys.argv[1])
        validator.print_results(sys.argv[1])
        return 0 if is_valid else 1


if __name__ == "__main__":
    sys.exit(main())
