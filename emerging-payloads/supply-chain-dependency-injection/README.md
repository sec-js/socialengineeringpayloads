# Supply Chain Attack: dependency-injection

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Supply chain attack technique targeting software distribution: DEPENDENCY INJECTION

Supply chain attacks can compromise thousands of downstream users through a single
compromised package, installer, or update mechanism.

## MITRE ATT&CK
- **T1195.001** — Supply Chain Compromise: Compromise Software Dependencies (Initial Access)
- **T1195.002** — Supply Chain Compromise: Compromise Software Supply Chain (Initial Access)

## Detection
- Software Composition Analysis (SCA) in CI/CD pipelines
- Package integrity verification (checksums, signatures)
- Monitor for new packages with names similar to internal packages

## Mitigation
- Use package lock files with cryptographic hashes
- Private package registries for internal packages
- Code signing for installers and updates
- Dependency version pinning

## References
- [MITRE T1195](https://attack.mitre.org/techniques/T1195/)
- [CISA Supply Chain Security](https://www.cisa.gov/supply-chain-security)
