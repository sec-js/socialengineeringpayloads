#!/usr/bin/env python3
"""
Microsoft Teams Webhook Payload Template
==========================================
DISCLAIMER: Educational purposes ONLY. Do not use without authorization.

Demonstrates how Microsoft Teams incoming webhooks can be used for:
1. Social engineering via Teams bot/webhook messages
2. Internal phishing via legitimate-looking Teams notifications

This is for:
- Security awareness training
- Blue team detection rule development
- Red team simulation in authorized environments

MITRE ATT&CK: T1534 (Internal Spearphishing)
"""

import json
import sys
from typing import Optional


DISCLAIMER = """
╔══════════════════════════════════════════════════════════════════╗
║  DISCLAIMER: EDUCATIONAL AND RESEARCH USE ONLY                   ║
║  Teams webhook security awareness and testing tool               ║
╚══════════════════════════════════════════════════════════════════╝
"""


def create_it_support_card(target_name: str, action_url: str = "#DEMO") -> dict:
    """
    Create an IT support Teams message card (educational template).
    
    Shows how attackers craft convincing IT support messages via Teams webhooks.
    
    Args:
        target_name: Target user's name (for personalization)
        action_url: URL for the action button
        
    Returns:
        Teams message card JSON
    """
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "FF0000",
        "summary": "Security Alert from IT Department",
        "sections": [{
            "activityTitle": "🔒 IT Security Alert",
            "activitySubtitle": "IT Department",
            "activityImage": "https://teams.microsoft.com/favicon.ico",
            "facts": [
                {
                    "name": "To",
                    "value": target_name
                },
                {
                    "name": "Priority",
                    "value": "⚠️ HIGH"
                },
                {
                    "name": "Reference",
                    "value": "INC-2024-XXXX"
                }
            ],
            "text": (
                f"Hi **{target_name}**,\n\n"
                "Our security monitoring system has detected unusual sign-in activity on your account. "
                "To protect your account, we need you to verify your identity within the next **30 minutes**.\n\n"
                "Please click 'Verify Account' below to confirm it was you."
            )
        }],
        "potentialAction": [{
            "@type": "OpenUri",
            "name": "Verify Account",
            "targets": [{
                "os": "default",
                "uri": action_url
            }]
        }],
        "_educational_notes": {
            "attack_type": "Internal Spearphishing via Teams Webhook",
            "why_effective": [
                "Teams messages from 'internal' bots appear more trusted",
                "Urgency (30 minutes, HIGH priority) pressures quick action",
                "Personalization (name) makes it seem legitimate",
                "Fake incident reference number adds credibility"
            ],
            "detection": [
                "Audit Teams webhook installations",
                "Monitor for incoming webhooks sending links to external domains",
                "Train users: IT never asks for credentials via Teams",
                "Verify unusual IT requests via phone call to known number"
            ],
            "mitigation": [
                "Disable external incoming webhooks in Teams admin",
                "Allowlist approved webhook URLs",
                "User training on Teams phishing",
                "Enable Teams message scanning (Defender for Office 365)"
            ]
        }
    }
    
    return card


def create_package_notification_card(sender: str = "IT Automation") -> dict:
    """
    Create a fake package/delivery Teams notification (social engineering).
    
    Shows how delivery notifications can be abused.
    """
    card = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "0078D4",
        "summary": "Package delivery notification",
        "sections": [{
            "activityTitle": "📦 Package Delivery Notification",
            "activitySubtitle": sender,
            "text": (
                "Your package could not be delivered. "
                "Please click below to reschedule delivery.\n\n"
                "**Tracking**: TRK-[FAKE-NUMBER]"
            )
        }],
        "potentialAction": [{
            "@type": "OpenUri",
            "name": "Reschedule Delivery",
            "targets": [{"os": "default", "uri": "#DEMO"}]
        }]
    }
    
    return card


def demonstrate_webhook_security() -> None:
    """Demonstrate Teams webhook security concepts."""
    print(DISCLAIMER)
    print("Microsoft Teams Webhook Security Analysis")
    print("=" * 50)
    
    print("""
TEAMS WEBHOOK ATTACK VECTORS:
================================
1. Outgoing Webhooks: Apps send messages to external URLs
   → Risk: Sensitive data leaked to external webhook
   
2. Incoming Webhooks: External services post to Teams channel
   → Risk: Attackers send phishing messages via webhook
   
3. Bot Framework Abuse: Malicious bots impersonating IT
   → Risk: Users trust "official-looking" bot messages

WHY TEAMS IS A TARGET:
========================
- High trust: Teams = internal corporate communication
- High click rates: Users expect notifications from IT
- Bypasses email security: Not subject to same email filtering
- Broad deployment: Used by 280M+ active users (2023)

REAL INCIDENT EXAMPLES:
========================
- 2023: "GIFShell" attack chain using Teams GIF images
- 2023: TeamsPhisher tool enabling external phishing via Teams
- Multiple campaigns using fake Microsoft support Teams messages

DETECTION METHODS:
==================
1. Teams Admin: Review installed apps and webhooks
2. Defender for Office 365: Enable Teams message scanning
3. Audit logs: Monitor webhook messages for external URLs
4. User training: IT never requests credentials via Teams
""")
    
    # Generate example cards for educational display
    example_card = create_it_support_card("Example User", "#DEMO")
    
    print("Example IT Support Phishing Card (JSON structure):")
    print("-" * 40)
    # Remove educational notes for display
    display_card = {k: v for k, v in example_card.items() if k != '_educational_notes'}
    print(json.dumps(display_card, indent=2)[:500] + "\n...[truncated]")
    
    print("\nSecurity Notes:")
    for note in example_card['_educational_notes']['detection']:
        print(f"  - {note}")


def check_webhook_url_safety(url: str) -> dict:
    """
    Analyze a webhook URL for suspicious indicators.
    
    Args:
        url: Webhook URL to analyze
        
    Returns:
        Analysis results
    """
    suspicious_indicators = []
    risk_level = "LOW"
    
    # Check for suspicious patterns
    if not url.startswith("https://"):
        suspicious_indicators.append("Not HTTPS — use only HTTPS webhooks")
        risk_level = "HIGH"
    
    trusted_domains = [
        "webhook.office.com",
        "outlook.office.com",
        "graph.microsoft.com"
    ]
    
    is_trusted = any(domain in url for domain in trusted_domains)
    if not is_trusted:
        suspicious_indicators.append("Webhook URL is not a Microsoft-hosted endpoint")
        risk_level = "HIGH" if risk_level != "HIGH" else risk_level
    
    if "ngrok" in url or "tunnel" in url or "localhost" in url:
        suspicious_indicators.append("Tunneling service detected (possible exfiltration)")
        risk_level = "CRITICAL"
    
    return {
        "url": url,
        "is_trusted_domain": is_trusted,
        "risk_level": risk_level,
        "indicators": suspicious_indicators,
        "recommendation": "BLOCK" if risk_level in ("HIGH", "CRITICAL") else "MONITOR"
    }


if __name__ == "__main__":
    if len(sys.argv) == 2:
        # Analyze a webhook URL
        url = sys.argv[1]
        print(DISCLAIMER)
        result = check_webhook_url_safety(url)
        print(f"Webhook URL Analysis: {url}")
        print(f"Risk Level: {result['risk_level']}")
        print(f"Trusted Domain: {result['is_trusted_domain']}")
        if result['indicators']:
            print("Indicators:")
            for i in result['indicators']:
                print(f"  - {i}")
        print(f"Recommendation: {result['recommendation']}")
    else:
        demonstrate_webhook_security()
        print("\nUsage:")
        print("  python teams-webhook-template.py              # Show security concepts")
        print("  python teams-webhook-template.py <webhook-url> # Analyze webhook URL")
