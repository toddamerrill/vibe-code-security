"""
Security Grader — A through F Grade Computation
=================================================

Computes an overall security grade (A–F) from individual scan category results.
Aligned with SSAP 5-Dimension Risk Scorecard methodology.

Category Weights:
- Security Headers: 15%
- Exposed Secrets: 25%
- BaaS Configuration: 30% (primary differentiator)
- Authentication Security: 15%
- Application Security: 15%

Grade Scale:
  A: 90–100 (Excellent)
  B: 80–89  (Good) - adjusted from 75
  C: 70–79  (Fair)
  D: 60–69  (Poor)
  F: 0–59   (Failing)

Based on SecureStack Assessment Platform (SSAP) methodology.
"""

import logging
from dataclasses import dataclass
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class GradeResult:
    """Complete grading result with dimension breakdown."""
    category_scores: Dict[str, int]
    overall_score: int
    overall_grade: str
    has_deal_breakers: bool
    deal_breakers: List[Dict[str, Any]]
    findings_by_severity: Dict[str, int]
    recommendation: str

CATEGORY_WEIGHTS = {
    "headers": 0.15,
    "secrets": 0.25,
    "baas": 0.30,
    "auth": 0.15,
    "app_security": 0.15,
}

GRADE_THRESHOLDS = [
    (90, "A"),
    (80, "B"),
    (70, "C"),
    (60, "D"),
    (0, "F"),
]


# Severity penalties for findings
SEVERITY_PENALTIES = {
    'critical': 25,
    'high': 15,
    'medium': 5,
    'low': 1,
    'info': 0,
}


def compute_grade(scan_result) -> dict:
    """
    Compute weighted grade from scan category results.
    Aligned with SSAP 5-Dimension Risk Scorecard methodology.

    Returns:
        {
            "category_scores": {"headers": 85, "secrets": 40, ...},
            "overall_score": 62,
            "overall_grade": "C",
            "has_deal_breakers": False,
            "deal_breakers": [],
            "findings_by_severity": {"critical": 0, "high": 1, ...},
            "recommendation": "...",
        }
    """
    scores = {}
    deal_breakers = []
    findings_by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    # --- Headers Score (0–100) ---
    if scan_result.header_result:
        scores["headers"] = scan_result.header_result.score
        # Count header findings by severity
        if hasattr(scan_result.header_result, 'findings'):
            for finding in scan_result.header_result.findings:
                sev = finding.get('severity', 'info').lower()
                if sev in findings_by_severity:
                    findings_by_severity[sev] += 1
    else:
        scores["headers"] = 50  # Neutral if not scanned

    # --- Secrets Score (0–100) ---
    scores["secrets"] = _score_secrets(scan_result.secret_result)

    # Track critical secrets as deal-breakers
    if scan_result.secret_result:
        if scan_result.secret_result.has_critical_secrets:
            findings_by_severity["critical"] += 1
            deal_breakers.append({
                "title": "Critical secrets exposed in client-side code",
                "severity": "critical",
                "category": "secrets",
            })
        if scan_result.secret_result.supabase_service_role:
            findings_by_severity["critical"] += 1
            deal_breakers.append({
                "title": "Supabase service_role key exposed — complete RLS bypass",
                "severity": "critical",
                "category": "secrets",
            })
        if scan_result.secret_result.has_high_secrets:
            findings_by_severity["high"] += 1

    # --- BaaS Score (0–100) ---
    scores["baas"] = _score_baas(scan_result.baas_result)

    # Track BaaS issues as deal-breakers
    if scan_result.baas_result:
        if scan_result.baas_result.pii_types_found:
            findings_by_severity["critical"] += 1
            deal_breakers.append({
                "title": f"PII exposed via missing RLS: {', '.join(str(t) for t in scan_result.baas_result.pii_types_found[:3])}",
                "severity": "critical",
                "category": "baas",
            })
        if scan_result.baas_result.tables_with_rls_failure > 0:
            if scan_result.baas_result.tables_with_rls_failure >= 3:
                findings_by_severity["high"] += 1
            else:
                findings_by_severity["medium"] += 1

    # --- Auth Score (0–100) ---
    scores["auth"] = _score_auth(scan_result.auth_result)

    # --- App Security Score (0–100) ---
    scores["app_security"] = _score_app_security(scan_result.app_sec_result)

    # Weighted average
    overall = sum(scores[cat] * CATEGORY_WEIGHTS[cat] for cat in CATEGORY_WEIGHTS)
    overall = round(overall)

    # Override: Any critical secret = cap at D
    if scan_result.secret_result and scan_result.secret_result.has_critical_secrets:
        overall = min(overall, 59)

    # Override: Service role key exposed = automatic F
    if scan_result.secret_result and scan_result.secret_result.supabase_service_role:
        overall = min(overall, 25)

    # Override: BaaS data exposure with PII = cap at F
    if scan_result.baas_result and scan_result.baas_result.pii_types_found:
        overall = min(overall, 35)

    # Map to letter grade
    grade = "F"
    for threshold, letter in GRADE_THRESHOLDS:
        if overall >= threshold:
            grade = letter
            break

    has_deal_breakers = len(deal_breakers) > 0

    # Generate recommendation
    recommendation = _generate_recommendation(overall, has_deal_breakers, scores)

    return {
        "category_scores": scores,
        "overall_score": overall,
        "overall_grade": grade,
        "has_deal_breakers": has_deal_breakers,
        "deal_breakers": deal_breakers,
        "findings_by_severity": findings_by_severity,
        "recommendation": recommendation,
    }


def _score_auth(auth_result) -> int:
    """Score the authentication security category 0-100."""
    if not auth_result or not isinstance(auth_result, dict):
        return 70  # Default — full auth scanning is Phase 2

    score = 100

    # Deduct for auth issues
    if auth_result.get("open_signup"):
        score -= 10
    if auth_result.get("no_rate_limiting"):
        score -= 15
    if auth_result.get("user_enumeration"):
        score -= 20
    if auth_result.get("weak_password_policy"):
        score -= 10

    return max(0, score)


def _generate_recommendation(overall: int, has_deal_breakers: bool, scores: dict) -> str:
    """Generate a recommendation based on the overall score and deal-breakers."""
    if has_deal_breakers:
        return "CRITICAL: Immediate remediation required. Critical vulnerabilities detected that expose user data or credentials."

    if overall >= 90:
        return "EXCELLENT: Strong security posture. Minor improvements may enhance defense-in-depth."
    elif overall >= 80:
        return "GOOD: Solid security foundation. Address missing security headers for improvement."
    elif overall >= 70:
        return "FAIR: Security gaps present. Prioritize CSP implementation and BaaS configuration review."
    elif overall >= 60:
        return "POOR: Significant security issues. Recommend security audit before production use."
    else:
        return "FAILING: Critical security deficiencies. Immediate remediation required."


def _score_secrets(secret_result) -> int:
    """Score the secrets category 0-100."""
    if not secret_result:
        return 75  # Neutral if not scanned
    
    if not secret_result.secrets_found:
        return 100  # No secrets found = perfect score
    
    score = 100
    for secret in secret_result.secrets_found:
        if not secret.appears_active:
            continue  # Don't penalize test keys
        
        sev = secret.severity.value if hasattr(secret.severity, 'value') else str(secret.severity)
        if sev == "critical":
            score -= 40
        elif sev == "high":
            score -= 25
        elif sev == "medium":
            score -= 10
        elif sev == "low":
            score -= 5
    
    return max(0, score)


def _score_baas(baas_result) -> int:
    """Score the BaaS configuration category 0-100."""
    if not baas_result:
        return 80  # No BaaS detected = generally fine (slight deduction for unknown)
    
    if baas_result.tables_tested == 0:
        return 70  # Couldn't test
    
    # Start at 100 and deduct
    score = 100
    
    total_tested = baas_result.tables_tested
    failures = baas_result.tables_with_rls_failure
    
    if total_tested > 0:
        failure_rate = failures / total_tested
        
        if failure_rate == 0:
            score = 100
        elif failure_rate < 0.1:
            score = 80
        elif failure_rate < 0.25:
            score = 60
        elif failure_rate < 0.5:
            score = 40
        else:
            score = 15
    
    # PII exposure drops score further
    if baas_result.pii_types_found:
        score = min(score, 20)
    
    # Secrets in database = critical
    if baas_result.secrets_found > 0:
        score = min(score, 10)
    
    return max(0, score)


def _score_app_security(app_sec_result) -> int:
    """Score application security findings 0-100."""
    if not app_sec_result or not isinstance(app_sec_result, dict):
        return 75
    
    score = 100
    for finding_name, finding in app_sec_result.items():
        sev = finding.get("severity", "info")
        if sev == "critical":
            score -= 30
        elif sev == "high":
            score -= 20
        elif sev == "medium":
            score -= 10
    
    return max(0, score)
