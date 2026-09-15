#!/usr/bin/env python3
"""
QR Code URL Generator for Security Testing
============================================
DISCLAIMER: Educational purposes ONLY. Do not use without authorization.

This tool generates QR codes for security awareness training demonstrations.
It shows how QR codes can be used in phishing attacks (quishing) and how
security teams can detect and prevent QR-based attacks.

PURPOSE:
- Generate QR code examples for security awareness training
- Demonstrate QR code scanning risks
- Test QR code security controls
- Show how QR codes bypass URL scanning in emails

MITRE ATT&CK: T1204.001 (User Execution: Malicious Link)
"""

import sys
import os
import urllib.parse


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║  EDUCATIONAL USE ONLY - AUTHORIZED TESTING ENVIRONMENTS ONLY    ║
║  QR code security awareness and testing tool                     ║
╚══════════════════════════════════════════════════════════════════╝
"""


def explain_qr_phishing_attack() -> None:
    """Explain the QR code phishing (quishing) attack technique."""
    print(DISCLAIMER)
    print("QR Code Phishing (Quishing) — Attack Explanation")
    print("=" * 55)
    print("""
HOW QR CODE ATTACKS WORK:
==========================
1. Attacker embeds malicious URL in QR code image
2. QR code image inserted into phishing email
3. Email security tools scan for URLs in text — NOT in images
4. QR code bypasses email URL security scanning
5. Target scans QR with phone camera
6. Phone browser opens malicious URL

WHY QR CODES BYPASS SECURITY:
================================
Email Security Gap:
  Standard email scanning:
    ✓ Scans text URLs in email body
    ✓ Scans attachment links
    ✗ Does NOT decode QR codes in images
    
  Result: Malicious URL hidden in QR = invisible to email security

Phone Risk Factor:
  - Phone browsers may have weaker URL inspection
  - Mobile users less trained to verify URLs
  - BYOD phones often lack enterprise security controls
  - Quick QR scan = less time to think critically

COMMON ATTACK SCENARIOS:
==========================
1. "Verify your account" QR in corporate-looking email
2. QR code on fake package stickers or physical mail
3. QR codes on restaurant menus (attacker replaces stickers)
4. Conference materials with QR codes
5. QR code in PDF attachments (double bypass: PDF + QR)
""")


def generate_qr_url_format(target_url: str, campaign_id: str = "test001") -> dict:
    """
    Show the structure of a QR code phishing campaign URL.
    
    Returns information about URL structure, NOT a functional phishing URL.
    """
    # Encode the URL for analysis
    encoded = urllib.parse.quote(target_url, safe='/:@?&=')
    
    # Common structures used in phishing campaigns
    structures = {
        'direct': target_url,
        'tracking_param': f"{target_url}?ref={campaign_id}",
        'redirect_chain': f"https://[legit-service.com]/redirect?url={encoded}",
        'url_shortener': f"https://[shortener.com]/{campaign_id[:6]}",
    }
    
    return {
        'target_url': target_url,
        'campaign_id': campaign_id,
        'url_structures': structures,
        'qr_service_example': f"https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={encoded}",
        'note': 'Educational analysis only — do not create malicious QR codes'
    }


def generate_detection_rules() -> str:
    """Generate detection rules for QR code phishing."""
    return """
DETECTION RULES FOR QR CODE PHISHING:
========================================

Email Security Rules:
- Flag emails containing images with QR-code-like patterns
- Alert on emails without text URLs but with embedded images  
- Use ML-based QR code detection in email security gateway

Endpoint Rules:
- MDM/mobile policy: Restrict QR scanning apps
- Browser protection on mobile: URL reputation check after QR scan
- Alert on QR-decoded URLs matching phishing patterns

Network Rules:
- DNS filtering applied to QR-decoded URLs
- Web proxy: Apply same URL reputation to QR-sourced URLs

User Training:
- Never scan QR codes from emails (use text URL instead)
- Verify QR destination before providing credentials
- Report unexpected QR codes in emails
"""


def analyze_qr_url(url: str) -> dict:
    """Analyze a URL that might have come from a QR code for suspicious indicators."""
    indicators = []
    risk_score = 0
    
    parsed = urllib.parse.urlparse(url)
    
    # Check for suspicious indicators
    if parsed.netloc:
        domain = parsed.netloc.lower()
        
        # URL shortener
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.io']
        if any(s in domain for s in shorteners):
            indicators.append("URL shortener detected — destination unknown without following")
            risk_score += 30
        
        # IP address instead of domain
        import re
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            indicators.append("IP address used instead of domain name")
            risk_score += 40
        
        # Too many hyphens (phishing indicator)
        if domain.count('-') > 2:
            indicators.append(f"Multiple hyphens in domain ({domain.count('-')}) — possible phishing")
            risk_score += 20
    
    # Check for redirect parameters
    if 'redirect' in url.lower() or 'url=' in url.lower():
        indicators.append("URL contains redirect parameter")
        risk_score += 25
    
    risk_level = 'LOW' if risk_score < 30 else 'MEDIUM' if risk_score < 60 else 'HIGH'
    
    return {
        'url': url,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'indicators': indicators,
        'recommendation': 'Do not follow' if risk_level == 'HIGH' else 'Verify before following'
    }


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1].startswith('http'):
        # Analyze mode
        url = sys.argv[1]
        print(DISCLAIMER)
        print(f"Analyzing QR URL: {url}\n")
        result = analyze_qr_url(url)
        print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']})")
        if result['indicators']:
            print("Indicators:")
            for i in result['indicators']:
                print(f"  - {i}")
        print(f"Recommendation: {result['recommendation']}")
    else:
        explain_qr_phishing_attack()
        print(generate_detection_rules())
        print("\nUsage:")
        print("  python qr-generator.py              # Show attack explanation")
        print("  python qr-generator.py <url>        # Analyze URL for suspicious indicators")
