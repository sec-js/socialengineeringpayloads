# Container/Kubernetes Attack: registry-credscontainer-registry-creds

> **⚠️ DISCLAIMER**: Educational purposes ONLY. Do not use without authorization.

## Overview
Container or Kubernetes-targeting attack technique used in cloud-native social engineering
attack chains. Often combines with supply chain compromise to reach CI/CD pipelines.

## MITRE ATT&CK
- **T1610** — Deploy Container (Defense Evasion)
- **T1611** — Escape to Host (Privilege Escalation)
- **T1552.007** — Unsecured Credentials: Container API (Collection)

## Detection
- Kubernetes audit logs
- Container security scanning
- Runtime security monitoring (Falco, Sysdig)

## Mitigation
- Policy-as-Code (OPA/Gatekeeper) to block privileged containers
- Least-privilege container configurations
- Container image signing and verification
- Network policies for container-to-container communication

## References
- [MITRE T1611](https://attack.mitre.org/techniques/T1611/)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/)
