from typing import Dict, Any, List
from backend.app.engine.cis_rules import CIS_BENCHMARK_RULES

class CISEvaluator:
    @staticmethod
    def evaluate_configuration(config: Dict[str, str]) -> Dict[str, Any]:
        findings = []
        passed_count = 0
        failed_count = 0
        remediation_cmds = []

        for rule in CIS_BENCHMARK_RULES:
            key = rule["config_key"]
            expected = rule["expected_value"].strip().lower()
            actual = str(config.get(key, "NOT_SET")).strip().lower()

            passed = False
            if key == "sshd.MaxAuthTries":
                try:
                    passed = int(actual) <= int(expected)
                except ValueError:
                    passed = False
            elif key == "file.etc_shadow.perm":
                passed = actual in ["0600", "0640", "600", "640"]
            else:
                passed = (actual == expected)

            if passed:
                passed_count += 1
                status = "PASS"
            else:
                failed_count += 1
                status = "FAIL"
                remediation_cmds.append(f"# {rule['rule_id']}: {rule['title']}\n{rule['remediation_cmd']}")

            findings.append({
                "rule_id": rule["rule_id"],
                "section": rule["section"],
                "title": rule["title"],
                "severity": rule["severity"],
                "status": status,
                "expected_value": rule["expected_value"],
                "actual_value": config.get(key, "NOT_CONFIGURED"),
                "remediation": rule["remediation_cmd"]
            })

        total = len(CIS_BENCHMARK_RULES)
        score_pct = round((passed_count / total) * 100, 1)

        # Build automated shell remediation script
        script_header = (
            "#!/usr/bin/env bash\n"
            "# ===================================================================\n"
            "# LinuxSecure - Automated CIS Benchmark Hardening Script\n"
            "# Generated automatically based on failed compliance findings\n"
            "# ===================================================================\n\n"
            "set -euo pipefail\n\n"
            "echo '[+] Starting Linux CIS Hardening Protocol...'\n\n"
        )
        script_body = script_header + "\n\n".join(remediation_cmds) + "\n\necho '[+] CIS Hardening Applied Successfully.'\n"

        return {
            "score_percentage": score_pct,
            "passed_rules": passed_count,
            "failed_rules": failed_count,
            "total_rules": total,
            "findings": findings,
            "remediation_script": script_body
        }
