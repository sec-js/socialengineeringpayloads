#!/bin/bash
# Container Escape Proof of Concept - Educational Reference
# ===========================================================
# DISCLAIMER: Educational purposes ONLY. Do not use without authorization.
#
# This script demonstrates common container escape indicators
# for detection and policy development purposes.
#
# MITRE ATT&CK: T1611 (Escape to Host)
# 
# USE ONLY IN:
# - Isolated lab environments
# - Authorized penetration testing
# - Container security research
#
# PURPOSE:
# - Understanding escape techniques for defense
# - Writing detection rules
# - Testing OPA/Gatekeeper policies

echo "=============================================="
echo "  Container Escape Detection Reference Script"
echo "  EDUCATIONAL USE ONLY"
echo "=============================================="
echo ""

# ======================================================
# DETECTION CHECK 1: Is this container privileged?
# ======================================================
echo "[CHECK 1] Checking if container is running in privileged mode..."

if [ -w /sys/kernel/debug ] 2>/dev/null; then
    echo "  ⚠️  WARNING: /sys/kernel/debug is writable - PRIVILEGED container!"
    echo "  This container has near-root access to the host"
    echo "  Detection rule: Alert on privileged: true in pod spec"
else
    echo "  ✓ /sys/kernel/debug is not writable - not privileged (good)"
fi

# ======================================================
# DETECTION CHECK 2: Docker socket exposure
# ======================================================
echo ""
echo "[CHECK 2] Checking for Docker socket exposure..."

if [ -S /var/run/docker.sock ]; then
    echo "  ⚠️  WARNING: Docker socket is mounted inside container!"
    echo "  An attacker can use docker.sock to escape to host:"
    echo "    docker -H unix:///var/run/docker.sock run -v /:/host ubuntu chroot /host"
    echo "  Detection: Alert on volume mount of /var/run/docker.sock"
else
    echo "  ✓ Docker socket not exposed (good)"
fi

# ======================================================
# DETECTION CHECK 3: Sensitive host mounts
# ======================================================
echo ""
echo "[CHECK 3] Checking for sensitive host path mounts..."

sensitive_paths=("/etc/shadow" "/etc/sudoers" "/root/.ssh" "/proc/sysrq-trigger")
found_sensitive=0

for path in "${sensitive_paths[@]}"; do
    if [ -f "$path" ] || [ -d "$path" ]; then
        echo "  ⚠️  WARNING: Sensitive host path accessible: $path"
        found_sensitive=1
    fi
done

if [ $found_sensitive -eq 0 ]; then
    echo "  ✓ No sensitive host paths detected (good)"
fi

# ======================================================
# DETECTION CHECK 4: Kernel capabilities
# ======================================================
echo ""
echo "[CHECK 4] Checking Linux capabilities..."

if command -v capsh &>/dev/null; then
    current_caps=$(capsh --print 2>/dev/null | grep "Current:" | head -1)
    echo "  $current_caps"
    
    dangerous_caps=("cap_sys_admin" "cap_sys_ptrace" "cap_net_admin" "cap_sys_module")
    for cap in "${dangerous_caps[@]}"; do
        if echo "$current_caps" | grep -qi "$cap"; then
            echo "  ⚠️  WARNING: Dangerous capability detected: $cap"
        fi
    done
else
    echo "  [capsh not available, run: apt-get install libcap2-bin]"
fi

# ======================================================
# SUMMARY
# ======================================================
echo ""
echo "=============================================="
echo "  Container Security Assessment Summary"
echo "=============================================="
echo ""
echo "Detection Rules to Implement:"
echo "  1. OPA/Gatekeeper: Deny privileged: true"
echo "  2. OPA/Gatekeeper: Deny hostPath mounts"
echo "  3. OPA/Gatekeeper: Deny docker.sock mounts"
echo "  4. OPA/Gatekeeper: Restrict Linux capabilities"
echo "  5. Falco: Alert on unexpected privilege escalation"
echo ""
echo "For detailed Kubernetes security policies, see:"
echo "  ../../k8s-manifest-injection/malicious-pod.yaml"
echo ""
echo "MITRE ATT&CK Reference:"
echo "  T1611 - Escape to Host: https://attack.mitre.org/techniques/T1611/"
echo ""
echo "[INFO] This is a detection reference script, not a real escape tool"
