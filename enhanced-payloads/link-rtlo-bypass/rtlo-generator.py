#!/usr/bin/env python3
"""
Right-to-Left Override (RTLO) Filename Generator
==================================================
DISCLAIMER: Educational purposes ONLY. Do not use without authorization.

This tool demonstrates the RTLO (Right-to-Left Override) Unicode trick
used to make malicious files appear to have innocent extensions.

PURPOSE:
- Security awareness training
- Detection rule development  
- Testing filename inspection tools
- Understanding the attack technique

MITRE ATT&CK: T1036.002 (Masquerading: Right-to-Left Override)
"""

import sys
import os


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║  EDUCATIONAL USE ONLY - AUTHORIZED TESTING ENVIRONMENTS ONLY    ║
║  RTLO detection and awareness tool                               ║
╚══════════════════════════════════════════════════════════════════╝
"""

# Unicode Right-to-Left Override character
RTLO = '\u202E'
RTLO_DESCRIPTION = "U+202E RIGHT-TO-LEFT OVERRIDE"


def generate_rtlo_filename(real_extension: str, fake_extension: str, 
                            base_name: str = "document") -> dict:
    """
    Generate an RTLO filename example for educational purposes.
    
    Example: make evil.exe appear as evil.pdf
    
    Args:
        real_extension: The actual file extension (e.g., 'exe')
        fake_extension: The extension shown to the user (e.g., 'pdf')
        base_name: The base filename (e.g., 'invoice')
        
    Returns:
        Dict with actual and displayed filename information
    """
    # RTLO reverses characters after it
    # To make .exe look like .pdf:
    # filename: document[RTLO]exe.pdf
    # Displayed: documentfdp.exe → appears as: documentexe.pdf
    
    # Reverse the fake extension for correct display after RTLO
    fake_ext_reversed = fake_extension[::-1]
    
    # Construct the actual filename
    actual_filename = f"{base_name}{RTLO}{real_extension}.{fake_ext_reversed}"
    
    # What the user sees (characters after RTLO are reversed)
    displayed_filename = f"{base_name}{fake_extension[::-1][::-1]}.{real_extension}"
    # Actually shown as:
    displayed_as = f"{base_name}.{fake_extension}"
    
    return {
        'actual_filename': actual_filename,
        'displayed_as': displayed_as,
        'actual_extension': real_extension,
        'fake_extension': fake_extension,
        'rtlo_char': RTLO,
        'rtlo_position': len(base_name),
        'detection_note': f"Contains {RTLO_DESCRIPTION} at position {len(base_name)}"
    }


def analyze_filename_for_rtlo(filename: str) -> dict:
    """
    Analyze a filename for RTLO characters — defensive function.
    
    Args:
        filename: Filename to analyze
        
    Returns:
        Analysis results including any RTLO detections
    """
    results = {
        'filename': filename,
        'has_rtlo': RTLO in filename,
        'rtlo_positions': [],
        'risk_level': 'SAFE',
        'recommendation': 'Filename appears normal'
    }
    
    if RTLO in filename:
        positions = [i for i, c in enumerate(filename) if c == RTLO]
        results['rtlo_positions'] = positions
        results['risk_level'] = 'HIGH'
        results['recommendation'] = (
            f"SUSPICIOUS: Contains U+202E (RTLO) at position(s) {positions}. "
            "The displayed filename may differ from the actual filename. "
            "Do not open this file."
        )
    
    # Check for other suspicious Unicode
    suspicious_chars = {
        '\u200F': 'RIGHT-TO-LEFT MARK',
        '\u200E': 'LEFT-TO-RIGHT MARK',
        '\u2066': 'LEFT-TO-RIGHT ISOLATE',
        '\u2069': 'POP DIRECTIONAL ISOLATE',
    }
    
    found_suspicious = []
    for char, name in suspicious_chars.items():
        if char in filename:
            found_suspicious.append(f"U+{ord(char):04X} ({name})")
    
    if found_suspicious:
        results['other_suspicious_chars'] = found_suspicious
        if results['risk_level'] == 'SAFE':
            results['risk_level'] = 'MEDIUM'
    
    return results


def demonstrate_attack() -> None:
    """Show multiple RTLO examples for educational awareness."""
    print(DISCLAIMER)
    print("RTLO (Right-to-Left Override) Attack Examples")
    print("=" * 60)
    print("These examples show how files appear to have safe extensions")
    print("but are actually malicious file types.\n")
    
    examples = [
        ('exe', 'pdf', 'invoice'),
        ('exe', 'docx', 'report'),
        ('js', 'txt', 'readme'),
        ('cmd', 'jpg', 'photo'),
        ('bat', 'xlsx', 'spreadsheet'),
    ]
    
    print(f"{'Displayed As':<30} {'Actual Type':<15} {'Attack Scenario'}")
    print("-" * 65)
    
    for real_ext, fake_ext, name in examples:
        result = generate_rtlo_filename(real_ext, fake_ext, name)
        print(f"{result['displayed_as']:<30} .{real_ext:<14} Malicious {real_ext.upper()}")
    
    print("\n" + "=" * 60)
    print("DETECTION METHODS:")
    print("""
1. Inspect hex/byte content of filename, not display
2. Alert on U+202E in any filename (email, file system, download)
3. Tools: file command (Linux), alternate data streams scanner
4. Modern email clients: Show RTLO warning
5. Windows 10+: May show Punycode-style display for RTLO filenames
""")
    
    print("MITIGATION:")
    print("""
1. Email gateway: Flag emails with RTLO in attachment names
2. File system monitoring: Alert on file creation with RTLO chars
3. Endpoint security: Block execution of files with RTLO characters
4. User training: Never open files with unusual encoding
""")


if __name__ == "__main__":
    print(DISCLAIMER)
    
    if len(sys.argv) == 2:
        # Analyze a specific filename
        filename = sys.argv[1]
        print(f"Analyzing filename: {filename!r}\n")
        result = analyze_filename_for_rtlo(filename)
        print(f"Risk Level: {result['risk_level']}")
        print(f"Has RTLO: {result['has_rtlo']}")
        if result['rtlo_positions']:
            print(f"RTLO positions: {result['rtlo_positions']}")
        print(f"Recommendation: {result['recommendation']}")
        if 'other_suspicious_chars' in result:
            print(f"Other suspicious chars: {result['other_suspicious_chars']}")
    else:
        # Show demonstration
        demonstrate_attack()
        print("\nUsage:")
        print("  python rtlo-generator.py              # Show attack examples")
        print("  python rtlo-generator.py <filename>   # Analyze filename for RTLO")
