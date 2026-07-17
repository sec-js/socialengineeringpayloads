# Browser Attack: search-redirect

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Browser-based attack technique: SEARCH REDIRECT

Browser extensions have broad access to browsing data including credentials, cookies,
form data, and the ability to modify page content.

## MITRE ATT&CK
- **T1176** — Browser Extensions (Persistence)
- **T1217** — Browser Information Discovery (Discovery)
- **T1539** — Steal Web Session Cookie (Collection)

## Detection
- Monitor browser extension installations via enterprise policy
- Alert on extensions requesting broad permissions (all URLs, webRequest)
- Browser process network traffic analysis

## Mitigation
- Enterprise browser management: whitelist approved extensions only
- Browser extension policies via Group Policy / Intune
- Periodic extension audit and cleanup

## References
- [MITRE T1176](https://attack.mitre.org/techniques/T1176/)
