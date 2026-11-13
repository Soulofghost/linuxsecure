import uuid
import datetime
from fastapi import APIRouter, HTTPException, status
from typing import List, Dict, Any

from backend.app.database import get_connection
from backend.app.schemas import AuditHostRequest, AuditResponse, AssessmentSummary, RemediationResponse
from backend.app.engine.cis_rules import CIS_BENCHMARK_RULES
from backend.app.engine.evaluator import CISEvaluator

router = APIRouter(prefix="/api", tags=["cis"])

@router.get("/health")
def healthcheck():
    return {
        "status": "ok",
        "service": "LinuxSecure",
        "version": "1.0.0",
        "engine": "Center for Internet Security (CIS) Linux Benchmark Compliance Evaluator"
    }

@router.get("/stats")
def get_stats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as c FROM cis_assessments;")
    total_assessments = cursor.fetchone()["c"]

    cursor.execute("SELECT AVG(score_percentage) as a FROM cis_assessments;")
    avg_score_row = cursor.fetchone()["a"]
    avg_score = round(avg_score_row, 1) if avg_score_row else 0.0

    cursor.execute("SELECT COUNT(*) as c FROM cis_findings WHERE status = 'FAIL' AND severity = 'CRITICAL';")
    critical_fails = cursor.fetchone()["c"]

    conn.close()

    return {
        "totalAssessments": total_assessments,
        "averageComplianceScore": avg_score,
        "criticalFailures": critical_fails,
        "benchmarksCount": len(CIS_BENCHMARK_RULES)
    }

@router.get("/rules")
def get_benchmark_rules():
    return {
        "total": len(CIS_BENCHMARK_RULES),
        "rules": CIS_BENCHMARK_RULES
    }

@router.post("/assess", response_model=AuditResponse, status_code=status.HTTP_201_CREATED)
def assess_host(payload: AuditHostRequest):
    # If no configuration provided, simulate a standard default unhardened distribution
    config = payload.configuration
    if not config:
        config = {
            "fs.suid_dumpable": "1", # Fails
            "sticky_bit_world_writable": "true", # Passes
            "net.ipv4.ip_forward": "1", # Fails
            "net.ipv4.conf.all.accept_redirects": "0", # Passes
            "net.ipv4.conf.all.accept_source_route": "1", # Fails
            "service.auditd.active": "true", # Passes
            "file.etc_shadow.perm": "0644", # Fails
            "sshd.PermitRootLogin": "yes", # Fails
            "sshd.PasswordAuthentication": "yes", # Fails
            "sshd.MaxAuthTries": "6" # Fails
        }

    eval_result = CISEvaluator.evaluate_configuration(config)

    assessment_id = "cis-" + str(uuid.uuid4())[:8]
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO cis_assessments (id, target_host, score_percentage, passed_rules, failed_rules, total_rules, evaluated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?);
    """, (
        assessment_id,
        payload.target_host,
        eval_result["score_percentage"],
        eval_result["passed_rules"],
        eval_result["failed_rules"],
        eval_result["total_rules"],
        now_iso
    ))

    for f in eval_result["findings"]:
        finding_id = "fnd-" + str(uuid.uuid4())[:8]
        cursor.execute("""
        INSERT INTO cis_findings (id, assessment_id, rule_id, section, title, status, severity, actual_value, expected_value, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """, (
            finding_id,
            assessment_id,
            f["rule_id"],
            f["section"],
            f["title"],
            f["status"],
            f["severity"],
            str(f["actual_value"]),
            str(f["expected_value"]),
            f["remediation"]
        ))

    cursor.execute("""
    INSERT INTO remediation_scripts (assessment_id, script_body, generated_at)
    VALUES (?, ?, ?);
    """, (assessment_id, eval_result["remediation_script"], now_iso))

    conn.commit()
    conn.close()

    return {
        "id": assessment_id,
        "target_host": payload.target_host,
        "score_percentage": eval_result["score_percentage"],
        "passed_rules": eval_result["passed_rules"],
        "failed_rules": eval_result["failed_rules"],
        "total_rules": eval_result["total_rules"],
        "evaluated_at": now_iso,
        "findings": eval_result["findings"],
        "remediation_script": eval_result["remediation_script"]
    }

@router.get("/assessments", response_model=List[AssessmentSummary])
def list_assessments():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cis_assessments ORDER BY evaluated_at DESC;")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

@router.get("/assessments/{assessment_id}/remediation", response_model=RemediationResponse)
def get_remediation_script(assessment_id: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM remediation_scripts WHERE assessment_id = ?;", (assessment_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Remediation script not found")

    return dict(row)
