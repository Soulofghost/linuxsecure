import pytest
from backend.app.engine.evaluator import CISEvaluator
from backend.app.engine.cis_rules import CIS_BENCHMARK_RULES

def test_evaluator_all_pass():
    hardened_config = {
        "fs.suid_dumpable": "0",
        "sticky_bit_world_writable": "true",
        "net.ipv4.ip_forward": "0",
        "net.ipv4.conf.all.accept_redirects": "0",
        "net.ipv4.conf.all.accept_source_route": "0",
        "service.auditd.active": "true",
        "file.etc_shadow.perm": "0600",
        "sshd.PermitRootLogin": "no",
        "sshd.PasswordAuthentication": "no",
        "sshd.MaxAuthTries": "3"
    }

    res = CISEvaluator.evaluate_configuration(hardened_config)
    assert res["score_percentage"] == 100.0
    assert res["passed_rules"] == len(CIS_BENCHMARK_RULES)
    assert res["failed_rules"] == 0

def test_evaluator_all_fail():
    unhardened_config = {
        "fs.suid_dumpable": "1",
        "sticky_bit_world_writable": "false",
        "net.ipv4.ip_forward": "1",
        "net.ipv4.conf.all.accept_redirects": "1",
        "net.ipv4.conf.all.accept_source_route": "1",
        "service.auditd.active": "false",
        "file.etc_shadow.perm": "0777",
        "sshd.PermitRootLogin": "yes",
        "sshd.PasswordAuthentication": "yes",
        "sshd.MaxAuthTries": "10"
    }

    res = CISEvaluator.evaluate_configuration(unhardened_config)
    assert res["score_percentage"] == 0.0
    assert res["failed_rules"] == len(CIS_BENCHMARK_RULES)
    assert "sysctl -w fs.suid_dumpable=0" in res["remediation_script"]
    assert "chmod 0600 /etc/shadow" in res["remediation_script"]
