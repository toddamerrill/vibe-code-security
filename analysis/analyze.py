"""
SSAP Security Study — Analysis Pipeline
========================================

Analyzes scan results and generates:
1. Statistical summaries
2. Grade distribution analysis
3. Platform comparison
4. Vulnerability prevalence
5. Security header adoption rates
6. Recommendations

Usage:
    python analyze.py --input ../scanner/output/scan_results.json

Output:
    output/analysis_report.json — Full statistical analysis
    output/analysis_report.md  — Human-readable report
"""

import argparse
import json
import logging
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AnalysisReport:
    """Container for all analysis results."""
    scan_date: str
    analysis_date: str
    total_apps: int

    # Grade analysis
    grade_distribution: dict[str, int]
    grade_percentages: dict[str, float]
    avg_score: float
    median_score: float
    score_std_dev: float

    # Platform analysis
    platform_stats: dict[str, dict]

    # Category analysis
    category_stats: dict[str, dict]

    # Header analysis
    header_adoption: dict[str, dict]

    # Secret findings
    secret_stats: dict[str, Any]

    # Top vulnerabilities
    top_vulnerabilities: list[dict]

    # Worst performers
    worst_apps: list[dict]

    def to_dict(self) -> dict:
        return {
            "scan_date": self.scan_date,
            "analysis_date": self.analysis_date,
            "total_apps": self.total_apps,
            "grade_distribution": self.grade_distribution,
            "grade_percentages": self.grade_percentages,
            "avg_score": self.avg_score,
            "median_score": self.median_score,
            "score_std_dev": self.score_std_dev,
            "platform_stats": self.platform_stats,
            "category_stats": self.category_stats,
            "header_adoption": self.header_adoption,
            "secret_stats": self.secret_stats,
            "top_vulnerabilities": self.top_vulnerabilities,
            "worst_apps": self.worst_apps,
        }


def analyze_results(results: list[dict]) -> AnalysisReport:
    """Run full analysis on scan results."""

    total = len(results)
    if total == 0:
        raise ValueError("No results to analyze")

    # --- Grade Distribution ---
    grades = Counter(r["overall_grade"] for r in results)
    grade_pct = {g: round(c / total * 100, 1) for g, c in grades.items()}

    # --- Score Statistics ---
    scores = [r["overall_score"] for r in results]
    avg_score = sum(scores) / total
    sorted_scores = sorted(scores)
    median_score = sorted_scores[total // 2]
    variance = sum((s - avg_score) ** 2 for s in scores) / total
    std_dev = variance ** 0.5

    # --- Platform Analysis ---
    platform_data = defaultdict(lambda: {"scores": [], "grades": []})
    for r in results:
        p = r["platform"]
        platform_data[p]["scores"].append(r["overall_score"])
        platform_data[p]["grades"].append(r["overall_grade"])

    platform_stats = {}
    for platform, data in platform_data.items():
        pscores = data["scores"]
        pgrades = Counter(data["grades"])
        platform_stats[platform] = {
            "count": len(pscores),
            "avg_score": round(sum(pscores) / len(pscores), 1),
            "min_score": min(pscores),
            "max_score": max(pscores),
            "grade_distribution": dict(pgrades),
            "pct_grade_c_or_below": round(
                sum(1 for g in data["grades"] if g in ("C", "D", "F")) / len(pscores) * 100, 1
            ),
        }

    # --- Category Analysis ---
    category_names = ["headers", "secrets", "baas", "auth", "app_security"]
    category_stats = {}

    for cat in category_names:
        cat_scores = [
            r["category_scores"].get(cat, 0)
            for r in results
            if r.get("category_scores")
        ]
        if cat_scores:
            category_stats[cat] = {
                "avg_score": round(sum(cat_scores) / len(cat_scores), 1),
                "min_score": min(cat_scores),
                "max_score": max(cat_scores),
                "pct_below_50": round(sum(1 for s in cat_scores if s < 50) / len(cat_scores) * 100, 1),
                "pct_perfect_100": round(sum(1 for s in cat_scores if s == 100) / len(cat_scores) * 100, 1),
            }

    # --- Header Adoption Analysis ---
    header_counts = defaultdict(lambda: {"present": 0, "missing": 0})

    for r in results:
        hr = r.get("header_result")
        if hr and hr.get("checks"):
            for check in hr["checks"]:
                hname = check["header_name"]
                if check["present"]:
                    header_counts[hname]["present"] += 1
                else:
                    header_counts[hname]["missing"] += 1

    header_adoption = {}
    for hname, counts in header_counts.items():
        total_checked = counts["present"] + counts["missing"]
        if total_checked > 0:
            header_adoption[hname] = {
                "adoption_rate": round(counts["present"] / total_checked * 100, 1),
                "missing_count": counts["missing"],
            }

    # Sort by adoption rate (lowest first = most common vulnerability)
    header_adoption = dict(sorted(header_adoption.items(), key=lambda x: x[1]["adoption_rate"]))

    # --- Secret Analysis ---
    apps_with_supabase = sum(
        1 for r in results
        if r.get("secret_result") and r["secret_result"].get("supabase_url")
    )
    apps_with_critical_secrets = sum(
        1 for r in results
        if r.get("secret_result") and r["secret_result"].get("has_critical_secrets")
    )
    apps_with_high_secrets = sum(
        1 for r in results
        if r.get("secret_result") and r["secret_result"].get("has_high_secrets")
    )
    apps_with_service_role = sum(
        1 for r in results
        if r.get("secret_result") and r["secret_result"].get("supabase_service_role")
    )

    secret_stats = {
        "apps_using_supabase": apps_with_supabase,
        "pct_using_supabase": round(apps_with_supabase / total * 100, 1),
        "apps_with_critical_secrets": apps_with_critical_secrets,
        "apps_with_high_secrets": apps_with_high_secrets,
        "apps_exposing_service_role": apps_with_service_role,
        "pct_exposing_service_role": round(apps_with_service_role / total * 100, 1) if total else 0,
    }

    # --- Top Vulnerabilities ---
    vulnerability_counts = Counter()

    # Count missing headers as vulnerabilities
    for hname, stats in header_adoption.items():
        if stats["adoption_rate"] < 50:  # Less than 50% adoption
            vulnerability_counts[f"Missing {hname}"] = stats["missing_count"]

    # Add secret-related vulnerabilities
    if apps_with_service_role > 0:
        vulnerability_counts["Exposed Supabase Service Role Key"] = apps_with_service_role
    if apps_with_critical_secrets > 0:
        vulnerability_counts["Critical Secrets in JS Bundles"] = apps_with_critical_secrets

    top_vulnerabilities = [
        {"vulnerability": vuln, "affected_apps": count, "pct_affected": round(count / total * 100, 1)}
        for vuln, count in vulnerability_counts.most_common(10)
    ]

    # --- Worst Performers ---
    worst_apps = sorted(results, key=lambda x: x["overall_score"])[:10]
    worst_apps = [
        {
            "domain": a["app_domain"],
            "platform": a["platform"],
            "grade": a["overall_grade"],
            "score": a["overall_score"],
            "weakest_category": min(
                a.get("category_scores", {}).items(),
                key=lambda x: x[1],
                default=("unknown", 0)
            )[0] if a.get("category_scores") else "unknown",
        }
        for a in worst_apps
    ]

    return AnalysisReport(
        scan_date=results[0].get("scan_date", "unknown") if results else "unknown",
        analysis_date=datetime.now(timezone.utc).isoformat(),
        total_apps=total,
        grade_distribution=dict(grades),
        grade_percentages=grade_pct,
        avg_score=round(avg_score, 1),
        median_score=median_score,
        score_std_dev=round(std_dev, 1),
        platform_stats=platform_stats,
        category_stats=category_stats,
        header_adoption=header_adoption,
        secret_stats=secret_stats,
        top_vulnerabilities=top_vulnerabilities,
        worst_apps=worst_apps,
    )


def generate_markdown_report(report: AnalysisReport) -> str:
    """Generate human-readable markdown report."""

    lines = [
        "# SSAP Security Study — Analysis Report",
        "",
        f"**Analysis Date:** {report.analysis_date}",
        f"**Total Apps Analyzed:** {report.total_apps}",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"- **Average Security Score:** {report.avg_score}/100",
        f"- **Median Score:** {report.median_score}/100",
        f"- **Standard Deviation:** {report.score_std_dev}",
        "",
        "### Grade Distribution",
        "",
        "| Grade | Count | Percentage |",
        "|-------|-------|------------|",
    ]

    for grade in ["A", "B", "C", "D", "F"]:
        count = report.grade_distribution.get(grade, 0)
        pct = report.grade_percentages.get(grade, 0)
        lines.append(f"| {grade} | {count} | {pct}% |")

    lines.extend([
        "",
        "---",
        "",
        "## Platform Comparison",
        "",
        "| Platform | Apps | Avg Score | % Grade C or Below |",
        "|----------|------|-----------|-------------------|",
    ])

    for platform, stats in sorted(report.platform_stats.items(), key=lambda x: -x[1]["count"]):
        lines.append(
            f"| {platform} | {stats['count']} | {stats['avg_score']} | {stats['pct_grade_c_or_below']}% |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## Category Analysis",
        "",
        "| Category | Avg Score | % Below 50 | % Perfect 100 |",
        "|----------|-----------|------------|---------------|",
    ])

    for cat, stats in report.category_stats.items():
        lines.append(
            f"| {cat} | {stats['avg_score']} | {stats['pct_below_50']}% | {stats['pct_perfect_100']}% |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## Security Header Adoption",
        "",
        "| Header | Adoption Rate | Missing Count |",
        "|--------|--------------|---------------|",
    ])

    for header, stats in report.header_adoption.items():
        lines.append(f"| {header} | {stats['adoption_rate']}% | {stats['missing_count']} |")

    lines.extend([
        "",
        "---",
        "",
        "## Secret Exposure",
        "",
        f"- **Apps using Supabase:** {report.secret_stats['apps_using_supabase']} ({report.secret_stats['pct_using_supabase']}%)",
        f"- **Apps exposing service role key:** {report.secret_stats['apps_exposing_service_role']}",
        f"- **Apps with critical secrets:** {report.secret_stats['apps_with_critical_secrets']}",
        f"- **Apps with high-severity secrets:** {report.secret_stats['apps_with_high_secrets']}",
        "",
        "---",
        "",
        "## Top Vulnerabilities",
        "",
        "| Vulnerability | Affected Apps | % Affected |",
        "|--------------|---------------|------------|",
    ])

    for vuln in report.top_vulnerabilities:
        lines.append(f"| {vuln['vulnerability']} | {vuln['affected_apps']} | {vuln['pct_affected']}% |")

    lines.extend([
        "",
        "---",
        "",
        "## Worst Performing Apps",
        "",
        "| Domain | Platform | Grade | Score | Weakest Area |",
        "|--------|----------|-------|-------|--------------|",
    ])

    for app in report.worst_apps:
        lines.append(
            f"| {app['domain']} | {app['platform']} | {app['grade']} | {app['score']} | {app['weakest_category']} |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## Key Findings",
        "",
        "1. **Header Security:** Content-Security-Policy and other security headers have low adoption rates.",
        "2. **BaaS Configuration:** Supabase is widely used; service role key exposure should be monitored.",
        "3. **Platform Trends:** Security posture varies by platform, with some showing consistent patterns.",
        "",
        "---",
        "",
        "*Generated by SSAP Security Study Analysis Pipeline*",
    ])

    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="SSAP Security Study — Analysis")
    parser.add_argument("--input", required=True, help="Path to scan_results.json")
    parser.add_argument("--output", default="output", help="Output directory")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    # Load results
    logger.info(f"Loading results from {args.input}")
    with open(args.input) as f:
        results = json.load(f)

    logger.info(f"Analyzing {len(results)} scan results...")

    # Run analysis
    report = analyze_results(results)

    # Save outputs
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    # JSON report
    json_path = output_dir / "analysis_report.json"
    with open(json_path, "w") as f:
        json.dump(report.to_dict(), f, indent=2)
    logger.info(f"JSON report saved: {json_path}")

    # Markdown report
    md_path = output_dir / "analysis_report.md"
    md_content = generate_markdown_report(report)
    with open(md_path, "w") as f:
        f.write(md_content)
    logger.info(f"Markdown report saved: {md_path}")

    # Print summary
    print("\n" + "=" * 60)
    print("ANALYSIS COMPLETE")
    print("=" * 60)
    print(f"\nTotal Apps: {report.total_apps}")
    print(f"Average Score: {report.avg_score}/100")
    print(f"\nGrade Distribution:")
    for grade in ["A", "B", "C", "D", "F"]:
        count = report.grade_distribution.get(grade, 0)
        pct = report.grade_percentages.get(grade, 0)
        bar = "#" * int(pct / 2)
        print(f"  {grade}: {count:4d} ({pct:5.1f}%) {bar}")

    print(f"\nTop Vulnerabilities:")
    for i, vuln in enumerate(report.top_vulnerabilities[:5], 1):
        print(f"  {i}. {vuln['vulnerability']}: {vuln['affected_apps']} apps ({vuln['pct_affected']}%)")

    print(f"\nReports saved to: {output_dir}/")
    print("=" * 60)


if __name__ == "__main__":
    main()
