#!/usr/bin/env python3
"""
Homograph Domain Generator
===========================
DISCLAIMER: Educational purposes ONLY. Do not use without authorization.

This tool generates homograph attack examples for a given domain by replacing
ASCII characters with visually similar Unicode characters.

PURPOSE:
- Security researchers studying homograph attacks
- Blue teams testing DNS filtering and domain monitoring
- Defenders building detection rules for lookalike domains
- User awareness training: showing users how similar fake domains look

MITRE ATT&CK: T1036 (Masquerading)
"""

import sys
from typing import Generator


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║  EDUCATIONAL USE ONLY - AUTHORIZED TESTING ENVIRONMENTS ONLY    ║
║  Use for domain monitoring and detection rule development ONLY  ║
╚══════════════════════════════════════════════════════════════════╝
"""

# Unicode confusables mapping (ASCII char → list of similar Unicode chars)
# Based on Unicode confusables table (http://www.unicode.org/reports/tr39/)
CONFUSABLES: dict[str, list[str]] = {
    'a': ['а', 'ạ', 'ă', 'ā', 'ä', 'â', 'à', 'á'],  # Cyrillic а and others
    'b': ['ƅ', 'ḅ', 'ь'],
    'c': ['с', 'ċ', 'ĉ', 'č'],  # Cyrillic с
    'd': ['ḋ', 'ď', 'đ'],
    'e': ['е', 'ė', 'ê', 'ë', 'è', 'é'],  # Cyrillic е
    'g': ['ɡ', 'ġ', 'ĝ'],
    'h': ['һ', 'ħ', 'ĥ'],  # Cyrillic h-like
    'i': ['і', 'ı', 'î', 'ï', 'ì', 'í', 'ĩ'],  # Cyrillic і
    'j': ['ĵ', 'ǰ'],
    'k': ['κ', 'ķ'],  # Greek kappa
    'l': ['ĺ', 'ļ', 'ľ', 'ŀ', 'ł', '1', 'I'],
    'm': ['м', 'ṁ'],  # Cyrillic м
    'n': ['ń', 'ņ', 'ň', 'ñ'],
    'o': ['о', 'ο', 'ø', 'ô', 'ö', 'ò', 'ó', '0'],  # Cyrillic о, Greek ο
    'p': ['р', 'ρ', 'ṗ'],  # Cyrillic р, Greek ρ
    'q': ['ɋ', 'ʠ'],
    'r': ['г', 'ṙ', 'ŕ', 'ř'],  # Cyrillic г-like
    's': ['ѕ', 'ś', 'ş', 'š', 'ŝ'],  # Cyrillic ѕ
    't': ['т', 'ţ', 'ť'],  # Cyrillic т-like
    'u': ['υ', 'ü', 'û', 'ù', 'ú', 'ũ'],  # Greek υ
    'v': ['ν', 'ṿ'],  # Greek ν
    'w': ['ω', 'ẇ'],  # Greek ω
    'x': ['х', 'χ'],  # Cyrillic х, Greek χ
    'y': ['у', 'γ', 'ý', 'ÿ'],  # Cyrillic у, Greek γ
    'z': ['ż', 'ź', 'ž'],
}


def generate_homographs(domain: str, max_results: int = 10) -> list[dict]:
    """
    Generate homograph variants of a domain for monitoring purposes.
    
    Args:
        domain: The legitimate domain to generate variants for
        max_results: Maximum number of variants to generate
        
    Returns:
        List of dicts with 'domain', 'original', 'substitution', 'position'
    """
    results = []
    # Split domain from TLD for processing
    parts = domain.rsplit('.', 1)
    name_part = parts[0]
    tld = '.' + parts[1] if len(parts) > 1 else ''
    
    # Generate single-character substitution variants
    for i, char in enumerate(name_part.lower()):
        if char in CONFUSABLES and len(results) < max_results:
            for substitute in CONFUSABLES[char]:
                if len(results) >= max_results:
                    break
                    
                # Create the homograph domain
                homograph = name_part[:i] + substitute + name_part[i+1:] + tld
                
                if homograph != domain:
                    results.append({
                        'domain': homograph,
                        'original_char': char,
                        'substitute_char': substitute,
                        'position': i,
                        'unicode_point': f'U+{ord(substitute):04X}',
                        'punycode': _to_punycode(homograph),
                        'note': 'Visually identical to humans, different to computers'
                    })
    
    return results


def _to_punycode(domain: str) -> str:
    """Convert domain to punycode representation."""
    try:
        parts = domain.split('.')
        encoded_parts = []
        for part in parts:
            try:
                encoded_parts.append(part.encode('idna').decode('ascii'))
            except (UnicodeError, UnicodeDecodeError):
                encoded_parts.append(part)
        return '.'.join(encoded_parts)
    except Exception:
        return domain


def print_homograph_report(domain: str) -> None:
    """Print a formatted report of homograph variants for monitoring."""
    print(DISCLAIMER)
    print(f"Homograph Analysis Report for: {domain}")
    print("=" * 60)
    print("(For domain monitoring and detection rule creation)\n")
    
    variants = generate_homographs(domain)
    
    if not variants:
        print(f"No common homograph substitutions found for '{domain}'")
        return
    
    print(f"Generated {len(variants)} lookalike domain variant(s):\n")
    
    for v in variants:
        print(f"  Lookalike: {v['domain']}")
        print(f"  Punycode:  {v['punycode']}")
        print(f"  Substitution: '{v['original_char']}' → '{v['substitute_char']}' ({v['unicode_point']})")
        print(f"  Position: character {v['position'] + 1}")
        print()
    
    print("\nDEFENSIVE RECOMMENDATIONS:")
    print("1. Monitor Certificate Transparency logs for these domains")
    print("2. Configure DNS filtering to block newly registered lookalike domains")
    print("3. Use brand protection services to monitor domain registrations")
    print("4. Modern browsers show Punycode for mixed-script domains")
    print("5. DMARC/DKIM enforcement prevents email spoofing from these domains")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(DISCLAIMER)
        print("Usage: python domain-generator.py <domain>")
        print("Example: python domain-generator.py microsoft.com")
        print("\nThis tool generates homograph lookalike domains for monitoring/defense purposes.")
        sys.exit(1)
    
    target_domain = sys.argv[1]
    print_homograph_report(target_domain)
