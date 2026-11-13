from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any

class AuditHostRequest(BaseModel):
    target_host: str = Field(..., description="Target hostname or IP address, e.g. prod-db-01.internal")
    configuration: Optional[Dict[str, str]] = Field(default=None, description="Key-value mapping of sysctl and sshd configuration parameters")

class CISFindingItem(BaseModel):
    rule_id: str
    section: str
    title: str
    severity: str
    status: str
    expected_value: str
    actual_value: str
    remediation: str

class AuditResponse(BaseModel):
    id: str
    target_host: str
    score_percentage: float
    passed_rules: int
    failed_rules: int
    total_rules: int
    evaluated_at: str
    findings: List[CISFindingItem]
    remediation_script: str

class AssessmentSummary(BaseModel):
    id: str
    target_host: str
    score_percentage: float
    passed_rules: int
    failed_rules: int
    total_rules: int
    evaluated_at: str

class RemediationResponse(BaseModel):
    assessment_id: str
    script_body: str
    generated_at: str
