import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)

def test_healthcheck():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["service"] == "LinuxSecure"

def test_stats_endpoint():
    res = client.get("/api/stats")
    assert res.status_code == 200
    data = res.json()
    assert "benchmarksCount" in data
    assert data["benchmarksCount"] >= 10

def test_rules_listing():
    res = client.get("/api/rules")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 10
    assert len(data["rules"]) >= 10

def test_assess_endpoint_default():
    payload = {
        "target_host": "bastion-host.secops.internal"
    }
    res = client.post("/api/assess", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["target_host"] == "bastion-host.secops.internal"
    assert "score_percentage" in data
    assert len(data["findings"]) >= 10
    assert "remediation_script" in data

    # Check script retrieval endpoint
    assessment_id = data["id"]
    script_res = client.get(f"/api/assessments/{assessment_id}/remediation")
    assert script_res.status_code == 200
    assert "script_body" in script_res.json()

def test_assess_endpoint_hardened():
    payload = {
        "target_host": "hardened-db.internal",
        "configuration": {
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
    }
    res = client.post("/api/assess", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["score_percentage"] == 100.0
    assert data["failed_rules"] == 0
