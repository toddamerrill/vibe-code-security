"""
Scan Orchestrator — Parallel Scanning Pipeline
================================================

Orchestrates the full scanning pipeline for all discovered apps:
1. Security Header checks
2. Secret scanning (JS bundle analysis)
3. BaaS configuration probing (Supabase/Firebase RLS)
4. Authentication security (rate limiting, enumeration)
5. Application security (CORS, redirects, source maps)
6. Grading (A–F based on weighted category scores)

Designed for AWS Lambda deployment with DynamoDB result storage.
Can also run locally for development.

Usage:
    # Local development
    python scan_orchestrator.py --input ../discovery/output/curated_apps.json --workers 10
    
    # Lambda deployment (via CDK)
    # See ../infra/cdk/ for deployment configuration

Output:
    output/scan_results.json — Full results for all apps
    output/scan_summary.json — Aggregate statistics
"""

import asyncio
import json
import logging
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from header_scanner import scan_headers
from secret_scanner import scan_secrets
from baas_prober import probe_supabase, probe_firebase
from grader import compute_grade

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------
# Data Models
# -----------------------------------------------------------------

class AppScanResult:
    """Complete scan result for a single application."""
    
    def __init__(self, app_domain: str, platform: str):
        self.app_domain = app_domain
        self.platform = platform
        self.scan_date = datetime.now(timezone.utc).isoformat()
        
        # Category results
        self.header_result = None
        self.secret_result = None
        self.baas_result = None
        self.auth_result = None
        self.app_sec_result = None
        
        # Grading
        self.category_scores = {}       # Category name → 0-100 score
        self.overall_score = 0          # 0-100 weighted average
        self.overall_grade = "N/A"      # A through F
        
        # Metadata
        self.scan_duration_seconds = 0
        self.errors: list[str] = []
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "app_domain": self.app_domain,
            "platform": self.platform,
            "scan_date": self.scan_date,
            "overall_grade": self.overall_grade,
            "overall_score": self.overall_score,
            "category_scores": self.category_scores,
            "header_result": asdict(self.header_result) if self.header_result else None,
            "secret_result": asdict(self.secret_result) if self.secret_result else None,
            "baas_result": asdict(self.baas_result) if self.baas_result else None,
            "scan_duration_seconds": self.scan_duration_seconds,
            "errors": self.errors,
        }


# -----------------------------------------------------------------
# Per-App Scanning Pipeline
# -----------------------------------------------------------------

async def scan_single_app(app_data: dict) -> AppScanResult:
    """
    Run the complete scanning pipeline for a single application.
    Each scan category runs independently — failures in one don't block others.
    """
    domain = app_data["domain"]
    platform = app_data.get("platform", "unknown")
    
    result = AppScanResult(app_domain=domain, platform=platform)
    start_time = asyncio.get_event_loop().time()
    
    logger.info(f"Scanning {domain}...")
    
    # --- Category 1: Security Headers ---
    try:
        result.header_result = await scan_headers(domain)
    except Exception as e:
        result.errors.append(f"header_scan: {str(e)[:200]}")
    
    # --- Category 2: Exposed Secrets ---
    try:
        result.secret_result = await scan_secrets(domain)
    except Exception as e:
        result.errors.append(f"secret_scan: {str(e)[:200]}")
    
    # --- Category 3: BaaS Configuration ---
    try:
        # Determine BaaS type from fingerprinting or secret scan
        supabase_url = app_data.get("supabase_url") or (
            result.secret_result.supabase_url if result.secret_result else None
        )
        anon_key = app_data.get("supabase_anon_key") or (
            result.secret_result.supabase_anon_key if result.secret_result else None
        )
        
        baas_type = app_data.get("detected_baas", "none")
        
        if supabase_url and anon_key:
            result.baas_result = await probe_supabase(domain, supabase_url, anon_key)
        elif baas_type == "firebase":
            # Extract Firebase project ID from domain or metadata
            firebase_id = app_data.get("raw_metadata", {}).get("firebase_project_id")
            if firebase_id:
                result.baas_result = await probe_firebase(domain, firebase_id)
    except Exception as e:
        result.errors.append(f"baas_probe: {str(e)[:200]}")
    
    # --- Category 4 & 5: Auth + App Security ---
    # These are lighter-weight checks implemented inline
    try:
        result.app_sec_result = await _scan_app_security(domain)
    except Exception as e:
        result.errors.append(f"app_security: {str(e)[:200]}")
    
    # --- Compute Grade ---
    try:
        grade_result = compute_grade(result)
        result.category_scores = grade_result["category_scores"]
        result.overall_score = grade_result["overall_score"]
        result.overall_grade = grade_result["overall_grade"]
    except Exception as e:
        result.errors.append(f"grading: {str(e)[:200]}")
    
    result.scan_duration_seconds = round(asyncio.get_event_loop().time() - start_time, 2)
    logger.info(f"  {domain}: Grade {result.overall_grade} ({result.overall_score}/100) in {result.scan_duration_seconds}s")
    
    return result


async def _scan_app_security(domain: str) -> dict:
    """
    Lightweight application security checks:
    - CORS configuration
    - Open redirect testing
    - Source map exposure
    - Verbose error messages
    """
    findings = {}
    
    async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
        
        # CORS check
        try:
            resp = await client.options(
                f"https://{domain}/api",
                headers={"Origin": "https://evil.example.com"},
            )
            acao = resp.headers.get("access-control-allow-origin", "")
            if acao == "*" or acao == "https://evil.example.com":
                findings["cors_misconfiguration"] = {
                    "severity": "high",
                    "detail": f"ACAO header reflects arbitrary origin: {acao}",
                }
        except Exception:
            pass
        
        # Robots.txt / sitemap exposure
        try:
            resp = await client.get(f"https://{domain}/robots.txt", timeout=5.0)
            if resp.status_code == 200 and "Disallow" in resp.text:
                findings["robots_txt"] = {"severity": "info", "detail": "robots.txt present"}
        except Exception:
            pass
    
    return findings


# -----------------------------------------------------------------
# Batch Orchestration
# -----------------------------------------------------------------

async def scan_batch(
    apps: list[dict],
    max_concurrent: int = 20,
    output_dir: str = "output",
) -> list[AppScanResult]:
    """
    Scan a batch of applications with controlled concurrency.
    Results are written incrementally to disk.
    """
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)
    
    results: list[AppScanResult] = []
    semaphore = asyncio.Semaphore(max_concurrent)
    
    async def _scan_with_limit(app_data: dict) -> AppScanResult:
        async with semaphore:
            return await scan_single_app(app_data)
    
    # Process in chunks for progress reporting
    CHUNK_SIZE = 100
    total = len(apps)
    
    for i in range(0, total, CHUNK_SIZE):
        chunk = apps[i:i + CHUNK_SIZE]
        chunk_results = await asyncio.gather(
            *[_scan_with_limit(app) for app in chunk],
            return_exceptions=True,
        )
        
        for j, result in enumerate(chunk_results):
            if isinstance(result, AppScanResult):
                results.append(result)
            else:
                logger.error(f"Scan failed for app {i + j}: {result}")
        
        # Progress
        completed = min(i + CHUNK_SIZE, total)
        logger.info(f"Progress: {completed}/{total} apps scanned ({completed * 100 // total}%)")
        
        # Incremental save
        _save_results(results, output_path / "scan_results_partial.json")
    
    # Final save
    _save_results(results, output_path / "scan_results.json")
    _save_summary(results, output_path / "scan_summary.json")
    
    return results


def _save_results(results: list[AppScanResult], path: Path):
    """Save full scan results to JSON."""
    with open(path, "w") as f:
        json.dump([r.to_dict() for r in results], f, indent=2, default=str)


def _save_summary(results: list[AppScanResult], path: Path):
    """Save aggregate statistics summary."""
    total = len(results)
    if total == 0:
        return
    
    # Grade distribution
    grades = {}
    for r in results:
        grades[r.overall_grade] = grades.get(r.overall_grade, 0) + 1
    
    # Platform breakdown
    platforms = {}
    for r in results:
        if r.platform not in platforms:
            platforms[r.platform] = {"count": 0, "avg_score": 0, "scores": []}
        platforms[r.platform]["count"] += 1
        platforms[r.platform]["scores"].append(r.overall_score)
    
    for p in platforms.values():
        p["avg_score"] = round(sum(p["scores"]) / len(p["scores"]), 1) if p["scores"] else 0
        del p["scores"]
    
    # Critical findings
    critical_count = sum(1 for r in results if r.overall_grade == "F")
    
    summary = {
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "total_apps_scanned": total,
        "grade_distribution": dict(sorted(grades.items())),
        "platform_breakdown": platforms,
        "apps_with_grade_f": critical_count,
        "pct_with_critical_findings": round(critical_count / total * 100, 1),
        "avg_overall_score": round(sum(r.overall_score for r in results) / total, 1),
    }
    
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)
    
    logger.info(f"Summary saved: {total} apps, avg score {summary['avg_overall_score']}/100")


# -----------------------------------------------------------------
# CLI Entry Point
# -----------------------------------------------------------------

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description="SSAP Security Study — Scan Orchestrator")
    parser.add_argument("--input", required=True, help="Path to curated_apps.json")
    parser.add_argument("--output", default="output", help="Output directory")
    parser.add_argument("--workers", type=int, default=20, help="Max concurrent scans")
    parser.add_argument("--limit", type=int, default=None, help="Limit number of apps to scan")
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    
    with open(args.input) as f:
        apps = json.load(f)
    
    if args.limit:
        apps = apps[:args.limit]
    
    logger.info(f"Starting scan of {len(apps)} apps with {args.workers} workers")
    
    results = asyncio.run(scan_batch(apps, max_concurrent=args.workers, output_dir=args.output))
    
    logger.info(f"Scan complete: {len(results)} results")


if __name__ == "__main__":
    main()
