from typing import List, Dict, Any

CIS_BENCHMARK_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "CIS-1.1.1",
        "section": "System Configuration",
        "title": "Ensure core dumps are restricted",
        "severity": "MEDIUM",
        "config_key": "fs.suid_dumpable",
        "expected_value": "0",
        "remediation_cmd": "sysctl -w fs.suid_dumpable=0 && echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-security.conf"
    },
    {
        "rule_id": "CIS-1.1.2",
        "section": "System Configuration",
        "title": "Ensure sticky bit is set on world-writable directories",
        "severity": "HIGH",
        "config_key": "sticky_bit_world_writable",
        "expected_value": "true",
        "remediation_cmd": "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \\( -perm -0002 -a ! -perm -1000 \\) 2>/dev/null | xargs -I '{}' chmod +t '{}'"
    },
    {
        "rule_id": "CIS-2.1.1",
        "section": "Network Hardening",
        "title": "Ensure IP forwarding is disabled",
        "severity": "HIGH",
        "config_key": "net.ipv4.ip_forward",
        "expected_value": "0",
        "remediation_cmd": "sysctl -w net.ipv4.ip_forward=0 && echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.d/99-security.conf"
    },
    {
        "rule_id": "CIS-2.1.2",
        "section": "Network Hardening",
        "title": "Ensure ICMP redirects are not accepted",
        "severity": "MEDIUM",
        "config_key": "net.ipv4.conf.all.accept_redirects",
        "expected_value": "0",
        "remediation_cmd": "sysctl -w net.ipv4.conf.all.accept_redirects=0 && echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.d/99-security.conf"
    },
    {
        "rule_id": "CIS-2.1.3",
        "section": "Network Hardening",
        "title": "Ensure source routed packets are rejected",
        "severity": "HIGH",
        "config_key": "net.ipv4.conf.all.accept_source_route",
        "expected_value": "0",
        "remediation_cmd": "sysctl -w net.ipv4.conf.all.accept_source_route=0 && echo 'net.ipv4.conf.all.accept_source_route = 0' >> /etc/sysctl.d/99-security.conf"
    },
    {
        "rule_id": "CIS-3.1.1",
        "section": "Logging & Auditing",
        "title": "Ensure auditd daemon is active and enabled",
        "severity": "HIGH",
        "config_key": "service.auditd.active",
        "expected_value": "true",
        "remediation_cmd": "systemctl enable auditd && systemctl start auditd"
    },
    {
        "rule_id": "CIS-3.1.2",
        "section": "File Permissions",
        "title": "Ensure permissions on /etc/shadow are 0600 or 0640",
        "severity": "CRITICAL",
        "config_key": "file.etc_shadow.perm",
        "expected_value": "0600",
        "remediation_cmd": "chmod 0600 /etc/shadow && chown root:root /etc/shadow"
    },
    {
        "rule_id": "CIS-4.1.1",
        "section": "Access Control & SSH",
        "title": "Ensure SSH root login is disabled",
        "severity": "CRITICAL",
        "config_key": "sshd.PermitRootLogin",
        "expected_value": "no",
        "remediation_cmd": "sed -i 's/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd"
    },
    {
        "rule_id": "CIS-4.1.2",
        "section": "Access Control & SSH",
        "title": "Ensure SSH password authentication is disabled",
        "severity": "HIGH",
        "config_key": "sshd.PasswordAuthentication",
        "expected_value": "no",
        "remediation_cmd": "sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload sshd"
    },
    {
        "rule_id": "CIS-4.1.3",
        "section": "Access Control & SSH",
        "title": "Ensure SSH MaxAuthTries is 4 or less",
        "severity": "MEDIUM",
        "config_key": "sshd.MaxAuthTries",
        "expected_value": "4",
        "remediation_cmd": "sed -i 's/^#*MaxAuthTries.*/MaxAuthTries 4/' /etc/ssh/sshd_config && systemctl reload sshd"
    }
]
