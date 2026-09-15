#!/usr/bin/env python3
"""
OAuth Flow Hijacking - Educational Reference
=============================================
DISCLAIMER: Educational purposes ONLY. Do not use without authorization.

This demonstrates OAuth consent phishing (also known as "OAuth abuse" or
"illicit consent grant attack") for security research purposes.

MITRE ATT&CK: T1550.001 (Application Access Token)
"""

import sys
import urllib.parse
import json
from typing import Optional


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║  DISCLAIMER: EDUCATIONAL AND RESEARCH USE ONLY                   ║
║  OAuth security awareness and detection reference                ║
╚══════════════════════════════════════════════════════════════════╝
"""


def explain_oauth_attack() -> None:
    """Explain OAuth consent phishing for defenders."""
    print(DISCLAIMER)
    print("OAuth Consent Phishing — Defender's Reference")
    print("=" * 55)
    print("""
OAUTH CONSENT PHISHING (ILLICIT CONSENT GRANT):
=================================================
How it works:
1. Attacker registers malicious OAuth app in Azure AD/Google
2. App requests broad permissions (mail.read, files.readwrite, etc.)
3. Phishing email/link directs victim to OAuth consent page
4. Victim authenticates with MFA (legitimately)
5. Victim grants consent to malicious app
6. Attacker gets persistent API token — valid until revoked
7. Access persists even after password change

WHY IT BYPASSES MFA:
====================
The victim authenticates legitimately (MFA passes).
They then consent to an app that has API access.
No need to steal credentials — the app token IS the access.

PERMISSIONS COMMONLY REQUESTED:
================================
- Mail.Read / Mail.ReadWrite: Read all email
- Files.ReadWrite.All: Read/write all files (OneDrive/SharePoint)
- User.ReadWrite.All: Create/modify user accounts
- offline_access: Refresh tokens for persistent access
- Calendars.Read: Access meeting information
- Contacts.ReadWrite: Access corporate directory

ATTACK VARIANTS:
================
1. Direct consent phishing:
   Link: https://login.microsoftonline.com/common/oauth2/authorize?
         client_id=ATTACKER_APP_ID&response_type=code&
         scope=Mail.Read%20Files.ReadWrite.All%20offline_access&
         redirect_uri=https://attacker.com/callback
         
2. App impersonation:
   Register app named "Microsoft Teams" or "OneDrive Backup"
   Use official Microsoft logos
   
3. Automated consent bypass:
   Azure AD admin consent misconfiguration allows user-granted consent
   to apps requesting any permissions

DETECTION:
==========
Windows/Azure:
- Monitor Azure AD audit logs: "Consent to application" events
- Alert on applications with broad permissions (especially offline_access)
- Review enterprise app consent grants regularly
- Azure Identity Protection: Risky OAuth application detection

Microsoft Defender for Cloud Apps:
- Enable OAuth app anomaly detection
- Alert on new apps with high-risk permissions
- Monitor app token usage for unusual patterns

Indicators of Compromise:
- Multiple users granting consent to same unknown app
- Unusual API access patterns (3am email downloads)
- New OAuth app with same name as legitimate app

MITIGATION:
===========
1. Azure AD: Disable user consent for OAuth apps
   Admin Center > Azure AD > Enterprise Applications > User Settings
   "Users can consent to apps accessing company data" → NO
   
2. Require admin approval for all OAuth apps
   Implement admin consent workflow

3. Allowlist approved OAuth applications

4. Regular auditing of consented applications:
   azure ad enterprise apps list | grep -E "(permissions|consent)"

5. Use Conditional Access to restrict app access
""")


def analyze_oauth_url(oauth_url: str) -> dict:
    """
    Analyze an OAuth authorization URL for suspicious indicators.
    
    Args:
        oauth_url: OAuth URL to analyze
        
    Returns:
        Analysis results with risk assessment
    """
    suspicious_indicators = []
    risk_score = 0
    
    parsed = urllib.parse.urlparse(oauth_url)
    params = urllib.parse.parse_qs(parsed.query)
    
    # Extract requested scopes
    scopes = params.get('scope', [''])[0].split()
    
    # High-risk scopes
    high_risk_scopes = {
        'Mail.ReadWrite': 'Full email access',
        'Files.ReadWrite.All': 'Full file access (OneDrive/SharePoint)',
        'User.ReadWrite.All': 'Create/modify all users',
        'Directory.ReadWrite.All': 'Full directory access',
        'offline_access': 'Persistent token (access after password change)',
        'https://graph.microsoft.com/.default': 'All application permissions'
    }
    
    found_high_risk = []
    for scope in scopes:
        if scope in high_risk_scopes:
            found_high_risk.append(f"{scope} ({high_risk_scopes[scope]})")
            risk_score += 20
    
    if found_high_risk:
        suspicious_indicators.append(f"High-risk scopes: {', '.join(found_high_risk)}")
    
    # Check redirect URI
    redirect_uri = params.get('redirect_uri', [''])[0]
    if redirect_uri:
        parsed_redirect = urllib.parse.urlparse(redirect_uri)
        trusted_domains = ['microsoftonline.com', 'microsoft.com', 'live.com']
        if not any(d in parsed_redirect.netloc for d in trusted_domains):
            suspicious_indicators.append(f"Redirect URI points to non-Microsoft domain: {parsed_redirect.netloc}")
            risk_score += 40
    
    # offline_access
    if 'offline_access' in scopes:
        suspicious_indicators.append("offline_access: Token persists after password reset")
        risk_score += 15
    
    risk_level = 'LOW' if risk_score < 20 else 'MEDIUM' if risk_score < 50 else 'HIGH'
    
    return {
        'url': oauth_url[:100] + '...' if len(oauth_url) > 100 else oauth_url,
        'scopes': scopes,
        'redirect_uri': redirect_uri,
        'risk_score': risk_score,
        'risk_level': risk_level,
        'suspicious_indicators': suspicious_indicators,
        'recommendation': 'Do not consent' if risk_level == 'HIGH' else 'Review carefully before consenting'
    }


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1].startswith('http'):
        # Analyze an OAuth URL
        url = sys.argv[1]
        print(DISCLAIMER)
        print(f"OAuth URL Analysis\n{'='*40}")
        result = analyze_oauth_url(url)
        print(f"Risk Level: {result['risk_level']} (Score: {result['risk_score']})")
        print(f"Scopes Requested: {', '.join(result['scopes']) or 'none'}")
        if result['redirect_uri']:
            print(f"Redirect URI: {result['redirect_uri']}")
        if result['suspicious_indicators']:
            print("\nSuspicious Indicators:")
            for i in result['suspicious_indicators']:
                print(f"  ⚠️  {i}")
        print(f"\nRecommendation: {result['recommendation']}")
    else:
        explain_oauth_attack()
        print("\nUsage:")
        print("  python oauth-intercept-template.py              # Show attack explanation")
        print("  python oauth-intercept-template.py <oauth-url>  # Analyze OAuth URL")
