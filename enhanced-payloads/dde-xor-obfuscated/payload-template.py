#!/usr/bin/env python3
"""
XOR DDE Payload Obfuscation Tool
=================================
DISCLAIMER: Educational purposes ONLY. Do not use without authorization.
This demonstrates XOR-based string obfuscation for DDE payloads.
PoC payload: calc.exe (Windows Calculator)

This tool shows how DDE command strings can be XOR-encoded to evade
signature-based detection that looks for literal command strings.

Usage: python xor-obfuscator.py [command] [key]
"""

import sys


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║  EDUCATIONAL USE ONLY - AUTHORIZED TESTING ENVIRONMENTS ONLY    ║
║  Do not use these techniques without explicit written permission ║
╚══════════════════════════════════════════════════════════════════╝
"""


def xor_encode(data: str, key: int) -> list[int]:
    """XOR encode a string with a single-byte key."""
    return [ord(c) ^ key for c in data]


def xor_decode(encoded: list[int], key: int) -> str:
    """XOR decode an encoded byte array."""
    return ''.join(chr(b ^ key) for b in encoded)


def generate_excel_formula(encoded_bytes: list[int], key: int) -> str:
    """
    Generate an Excel formula that decodes and executes XOR-encoded command.
    
    NOTE: This is for educational/detection purposes only.
    The formula demonstrates how XOR encoding can hide a DDE command.
    
    Returns a string showing the formula structure (not functional in safe mode).
    """
    # Build CHAR() sequence for the XOR key and encoded bytes
    chars = ','.join(f'CHAR({b})' for b in encoded_bytes)
    
    # This is a simplified educational representation
    # Real attackers would use Excel's INDIRECT() or other functions for decode
    formula_comment = f"""
# XOR Key: {key}
# Encoded bytes: {encoded_bytes}
# To decode: each_byte XOR {key}
# Formula structure (educational reference):
#   =INDIRECT([formula_that_decodes_XOR_and_calls_DDE])
# 
# Detection:
#   - Excel spawning cmd.exe regardless of obfuscation method
#   - Unusual INDIRECT() or CHAR() sequences in CSV cells
#   - Behavioral monitoring catches execution, not just the formula
"""
    return formula_comment


def demonstrate_encoding(command: str, key: int = 0x42) -> None:
    """Demonstrate XOR encoding of a DDE command."""
    print(DISCLAIMER)
    print(f"Command to encode: {command!r}")
    print(f"XOR Key: 0x{key:02X} ({key})")
    
    encoded = xor_encode(command, key)
    decoded = xor_decode(encoded, key)
    
    print(f"\nEncoded bytes: {encoded}")
    print(f"Decoded verification: {decoded!r}")
    print(f"Encoding successful: {command == decoded}")
    
    print("\nDDE Formula Structure (educational):")
    formula = generate_excel_formula(encoded, key)
    print(formula)
    
    print("\nDetection Notes:")
    print("- XOR-encoded DDE payloads still trigger process creation events")
    print("- Behavioral detection (Office spawning cmd.exe) is key")
    print("- Disable DDE via Group Policy to prevent all variants:")
    print("  HKCU\\Software\\Microsoft\\Office\\<ver>\\Excel\\Security\\AllowDDE = 0")


if __name__ == "__main__":
    # Default demonstration: calc.exe (PoC payload per repository convention)
    demo_command = "cmd /c calc.exe"
    demo_key = 0x42
    
    if len(sys.argv) >= 2:
        demo_command = sys.argv[1]
    if len(sys.argv) >= 3:
        demo_key = int(sys.argv[2], 0)
    
    demonstrate_encoding(demo_command, demo_key)
