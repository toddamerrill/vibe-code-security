"""
SSAP Security Study — Visualizations
=====================================

Generates publication-quality charts for the security study:
1. Grade distribution (pie + bar)
2. Platform comparison
3. Category scores breakdown
4. Security header adoption rates
5. Top vulnerabilities
6. Score distribution histogram

Usage:
    python visualizations.py --input output/analysis_report.json

Output:
    figures/ — PNG and SVG files for each chart
"""

import argparse
import json
import logging
from pathlib import Path

import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import seaborn as sns
import pandas as pd
import numpy as np

logger = logging.getLogger(__name__)

# Color palette - professional and accessible
COLORS = {
    "A": "#2ecc71",  # Green
    "B": "#3498db",  # Blue
    "C": "#f39c12",  # Orange
    "D": "#e74c3c",  # Red
    "F": "#8e44ad",  # Purple
    "primary": "#2c3e50",
    "secondary": "#7f8c8d",
    "accent": "#e74c3c",
    "background": "#ecf0f1",
}

PLATFORM_COLORS = {
    "lovable": "#FF6B9D",
    "replit": "#F26207",
    "create_xyz": "#00D4AA",
    "bolt": "#FFD700",
    "v0": "#000000",
    "unknown": "#95a5a6",
}

# Set style
plt.style.use('seaborn-v0_8-whitegrid')
sns.set_palette("husl")


def setup_figure(figsize=(10, 6)):
    """Create a figure with consistent styling."""
    fig, ax = plt.subplots(figsize=figsize)
    fig.patch.set_facecolor('white')
    return fig, ax


def save_figure(fig, output_dir: Path, name: str):
    """Save figure in multiple formats."""
    for fmt in ["png", "svg"]:
        path = output_dir / f"{name}.{fmt}"
        fig.savefig(path, format=fmt, dpi=300, bbox_inches='tight', facecolor='white')
    logger.info(f"Saved: {name}.png/.svg")
    plt.close(fig)


def plot_grade_distribution(report: dict, output_dir: Path):
    """Create grade distribution charts (bar + pie)."""

    grades = ["A", "B", "C", "D", "F"]
    counts = [report["grade_distribution"].get(g, 0) for g in grades]
    percentages = [report["grade_percentages"].get(g, 0) for g in grades]
    colors = [COLORS[g] for g in grades]

    # Bar chart
    fig, ax = setup_figure((10, 6))
    bars = ax.bar(grades, counts, color=colors, edgecolor='white', linewidth=2)

    # Add value labels on bars
    for bar, count, pct in zip(bars, counts, percentages):
        if count > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 5,
                   f'{count}\n({pct}%)', ha='center', va='bottom', fontsize=12, fontweight='bold')

    ax.set_xlabel('Security Grade', fontsize=14)
    ax.set_ylabel('Number of Apps', fontsize=14)
    ax.set_title('Security Grade Distribution\nAcross 603 Vibe-Coded Applications', fontsize=16, fontweight='bold')
    ax.set_ylim(0, max(counts) * 1.2)

    # Remove top and right spines
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    save_figure(fig, output_dir, "grade_distribution_bar")

    # Pie chart (only show non-zero grades)
    non_zero = [(g, c, p, COLORS[g]) for g, c, p in zip(grades, counts, percentages) if c > 0]
    if non_zero:
        fig, ax = setup_figure((8, 8))
        labels = [f"{g}: {c} ({p}%)" for g, c, p, _ in non_zero]
        sizes = [c for _, c, _, _ in non_zero]
        pie_colors = [col for _, _, _, col in non_zero]

        wedges, texts, autotexts = ax.pie(
            sizes, labels=labels, colors=pie_colors,
            autopct='', startangle=90,
            wedgeprops={'edgecolor': 'white', 'linewidth': 2}
        )

        ax.set_title('Security Grade Distribution', fontsize=16, fontweight='bold')
        save_figure(fig, output_dir, "grade_distribution_pie")


def plot_platform_comparison(report: dict, output_dir: Path):
    """Create platform comparison chart."""

    platforms = list(report["platform_stats"].keys())
    counts = [report["platform_stats"][p]["count"] for p in platforms]
    avg_scores = [report["platform_stats"][p]["avg_score"] for p in platforms]
    pct_poor = [report["platform_stats"][p]["pct_grade_c_or_below"] for p in platforms]

    # Sort by count
    sorted_data = sorted(zip(platforms, counts, avg_scores, pct_poor), key=lambda x: -x[1])
    platforms, counts, avg_scores, pct_poor = zip(*sorted_data)

    colors = [PLATFORM_COLORS.get(p, "#95a5a6") for p in platforms]

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # Left: App count by platform
    ax1 = axes[0]
    bars = ax1.barh(platforms, counts, color=colors, edgecolor='white', linewidth=2)
    ax1.set_xlabel('Number of Apps', fontsize=12)
    ax1.set_title('Apps by Platform', fontsize=14, fontweight='bold')
    ax1.invert_yaxis()

    for bar, count in zip(bars, counts):
        ax1.text(bar.get_width() + 5, bar.get_y() + bar.get_height()/2,
                f'{count}', va='center', fontsize=11)

    # Right: Average score by platform
    ax2 = axes[1]
    bars = ax2.barh(platforms, avg_scores, color=colors, edgecolor='white', linewidth=2)
    ax2.set_xlabel('Average Security Score', fontsize=12)
    ax2.set_title('Average Score by Platform', fontsize=14, fontweight='bold')
    ax2.set_xlim(0, 100)
    ax2.invert_yaxis()

    for bar, score in zip(bars, avg_scores):
        ax2.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
                f'{score}', va='center', fontsize=11)

    # Add reference line at 70 (B grade threshold)
    ax2.axvline(x=70, color='gray', linestyle='--', alpha=0.5, label='B Grade Threshold')

    plt.suptitle('Platform Security Comparison', fontsize=16, fontweight='bold', y=1.02)
    plt.tight_layout()
    save_figure(fig, output_dir, "platform_comparison")


def plot_category_scores(report: dict, output_dir: Path):
    """Create category score breakdown chart."""

    categories = list(report["category_stats"].keys())
    avg_scores = [report["category_stats"][c]["avg_score"] for c in categories]
    pct_below_50 = [report["category_stats"][c]["pct_below_50"] for c in categories]

    # Clean up category names for display
    display_names = {
        "headers": "Security\nHeaders",
        "secrets": "Secret\nExposure",
        "baas": "BaaS\nConfig",
        "auth": "Auth\nSecurity",
        "app_security": "App\nSecurity"
    }
    labels = [display_names.get(c, c) for c in categories]

    fig, ax = setup_figure((12, 6))

    x = np.arange(len(categories))
    width = 0.6

    # Color bars by score (green = good, red = bad)
    colors = ['#e74c3c' if s < 50 else '#f39c12' if s < 70 else '#2ecc71' for s in avg_scores]

    bars = ax.bar(x, avg_scores, width, color=colors, edgecolor='white', linewidth=2)

    # Add score labels
    for bar, score, pct in zip(bars, avg_scores, pct_below_50):
        ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 2,
               f'{score}', ha='center', va='bottom', fontsize=14, fontweight='bold')
        if pct > 0:
            ax.text(bar.get_x() + bar.get_width()/2, bar.get_height()/2,
                   f'{pct}%\nbelow 50', ha='center', va='center', fontsize=10, color='white')

    ax.set_ylabel('Average Score', fontsize=14)
    ax.set_title('Security Category Scores\n(Higher is Better)', fontsize=16, fontweight='bold')
    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=12)
    ax.set_ylim(0, 110)

    # Add threshold lines
    ax.axhline(y=50, color='#e74c3c', linestyle='--', alpha=0.5, label='Poor (< 50)')
    ax.axhline(y=70, color='#f39c12', linestyle='--', alpha=0.5, label='Fair (< 70)')
    ax.axhline(y=90, color='#2ecc71', linestyle='--', alpha=0.5, label='Good (> 90)')

    ax.legend(loc='upper right')
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    save_figure(fig, output_dir, "category_scores")


def plot_header_adoption(report: dict, output_dir: Path):
    """Create security header adoption rate chart."""

    headers = list(report["header_adoption"].keys())
    adoption_rates = [report["header_adoption"][h]["adoption_rate"] for h in headers]
    missing_counts = [report["header_adoption"][h]["missing_count"] for h in headers]

    # Sort by adoption rate (ascending - worst first)
    sorted_data = sorted(zip(headers, adoption_rates, missing_counts), key=lambda x: x[1])
    headers, adoption_rates, missing_counts = zip(*sorted_data)

    fig, ax = setup_figure((12, 8))

    # Color by adoption rate
    colors = ['#e74c3c' if r < 20 else '#f39c12' if r < 50 else '#2ecc71' for r in adoption_rates]

    y_pos = np.arange(len(headers))
    bars = ax.barh(y_pos, adoption_rates, color=colors, edgecolor='white', linewidth=2)

    # Add percentage labels
    for bar, rate, missing in zip(bars, adoption_rates, missing_counts):
        # Label on bar
        if rate > 10:
            ax.text(bar.get_width() - 3, bar.get_y() + bar.get_height()/2,
                   f'{rate}%', va='center', ha='right', fontsize=11, color='white', fontweight='bold')
        else:
            ax.text(bar.get_width() + 2, bar.get_y() + bar.get_height()/2,
                   f'{rate}%', va='center', ha='left', fontsize=11, fontweight='bold')

        # Missing count on right
        ax.text(102, bar.get_y() + bar.get_height()/2,
               f'({missing} missing)', va='center', ha='left', fontsize=9, color='gray')

    ax.set_yticks(y_pos)
    ax.set_yticklabels(headers, fontsize=11)
    ax.set_xlabel('Adoption Rate (%)', fontsize=14)
    ax.set_title('Security Header Adoption Rates\n(Lower = More Vulnerable)', fontsize=16, fontweight='bold')
    ax.set_xlim(0, 130)

    # Add legend
    legend_elements = [
        mpatches.Patch(facecolor='#e74c3c', label='Critical (< 20%)'),
        mpatches.Patch(facecolor='#f39c12', label='Poor (< 50%)'),
        mpatches.Patch(facecolor='#2ecc71', label='Good (> 50%)'),
    ]
    ax.legend(handles=legend_elements, loc='lower right')

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    save_figure(fig, output_dir, "header_adoption")


def plot_top_vulnerabilities(report: dict, output_dir: Path):
    """Create top vulnerabilities chart."""

    vulns = report["top_vulnerabilities"][:8]  # Top 8

    names = [v["vulnerability"].replace("Missing ", "") for v in vulns]
    affected = [v["affected_apps"] for v in vulns]
    percentages = [v["pct_affected"] for v in vulns]

    fig, ax = setup_figure((12, 7))

    y_pos = np.arange(len(names))
    colors = ['#e74c3c' if p > 90 else '#f39c12' if p > 50 else '#3498db' for p in percentages]

    bars = ax.barh(y_pos, percentages, color=colors, edgecolor='white', linewidth=2)

    # Add labels
    for bar, count, pct in zip(bars, affected, percentages):
        ax.text(bar.get_width() + 1, bar.get_y() + bar.get_height()/2,
               f'{pct}% ({count} apps)', va='center', ha='left', fontsize=11)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(names, fontsize=11)
    ax.set_xlabel('Percentage of Apps Affected', fontsize=14)
    ax.set_title('Top Security Vulnerabilities\nin Vibe-Coded Applications', fontsize=16, fontweight='bold')
    ax.set_xlim(0, 115)
    ax.invert_yaxis()

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    save_figure(fig, output_dir, "top_vulnerabilities")


def plot_score_distribution(report: dict, scan_results: list, output_dir: Path):
    """Create score distribution histogram."""

    scores = [r["overall_score"] for r in scan_results]

    fig, ax = setup_figure((10, 6))

    # Histogram
    n, bins, patches = ax.hist(scores, bins=20, color='#3498db', edgecolor='white', linewidth=1.5)

    # Color bins by grade ranges
    for patch, left_edge in zip(patches, bins[:-1]):
        if left_edge < 60:
            patch.set_facecolor('#e74c3c')  # D/F
        elif left_edge < 70:
            patch.set_facecolor('#f39c12')  # C
        elif left_edge < 90:
            patch.set_facecolor('#3498db')  # B
        else:
            patch.set_facecolor('#2ecc71')  # A

    # Add mean and median lines
    mean_score = report["avg_score"]
    median_score = report["median_score"]

    ax.axvline(x=mean_score, color='#2c3e50', linestyle='-', linewidth=2, label=f'Mean: {mean_score}')
    ax.axvline(x=median_score, color='#8e44ad', linestyle='--', linewidth=2, label=f'Median: {median_score}')

    ax.set_xlabel('Security Score', fontsize=14)
    ax.set_ylabel('Number of Apps', fontsize=14)
    ax.set_title('Distribution of Security Scores', fontsize=16, fontweight='bold')
    ax.legend(loc='upper left')

    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)

    save_figure(fig, output_dir, "score_distribution")


def plot_supabase_analysis(report: dict, output_dir: Path):
    """Create Supabase usage and security chart."""

    stats = report["secret_stats"]
    total = report["total_apps"]

    # Data
    categories = ['Using Supabase', 'Not Using Supabase']
    values = [stats["apps_using_supabase"], total - stats["apps_using_supabase"]]
    colors = ['#3498db', '#ecf0f1']

    fig, axes = plt.subplots(1, 2, figsize=(14, 6))

    # Left: Supabase usage pie
    ax1 = axes[0]
    wedges, texts, autotexts = ax1.pie(
        values, labels=categories, colors=colors,
        autopct='%1.1f%%', startangle=90,
        wedgeprops={'edgecolor': 'white', 'linewidth': 2}
    )
    ax1.set_title('Supabase Usage', fontsize=14, fontweight='bold')

    # Right: Security metrics for Supabase apps
    ax2 = axes[1]
    metrics = ['Service Role\nExposed', 'Critical\nSecrets', 'High-Severity\nSecrets']
    metric_values = [
        stats["apps_exposing_service_role"],
        stats["apps_with_critical_secrets"],
        stats["apps_with_high_secrets"]
    ]

    bar_colors = ['#2ecc71' if v == 0 else '#e74c3c' for v in metric_values]
    bars = ax2.bar(metrics, metric_values, color=bar_colors, edgecolor='white', linewidth=2)

    for bar, val in zip(bars, metric_values):
        label = "None!" if val == 0 else str(val)
        ax2.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.2,
                label, ha='center', va='bottom', fontsize=12, fontweight='bold')

    ax2.set_ylabel('Number of Apps', fontsize=12)
    ax2.set_title('Secret Exposure\n(Among Supabase Apps)', fontsize=14, fontweight='bold')
    ax2.set_ylim(0, max(max(metric_values) * 1.3, 5))

    plt.suptitle('Backend-as-a-Service (BaaS) Security', fontsize=16, fontweight='bold', y=1.02)
    plt.tight_layout()
    save_figure(fig, output_dir, "supabase_analysis")


def plot_summary_dashboard(report: dict, output_dir: Path):
    """Create a summary dashboard with key metrics."""

    fig = plt.figure(figsize=(16, 10))

    # Create grid
    gs = fig.add_gridspec(2, 3, hspace=0.3, wspace=0.3)

    # 1. Overall score gauge (top left)
    ax1 = fig.add_subplot(gs[0, 0])
    score = report["avg_score"]

    # Simple bar showing score
    ax1.barh([0], [score], color='#3498db', height=0.5)
    ax1.barh([0], [100-score], left=[score], color='#ecf0f1', height=0.5)
    ax1.set_xlim(0, 100)
    ax1.set_ylim(-0.5, 0.5)
    ax1.set_yticks([])
    ax1.text(50, -0.35, f'Average Score: {score}/100', ha='center', fontsize=14, fontweight='bold')
    ax1.set_title('Overall Security Score', fontsize=12, fontweight='bold')
    ax1.spines['top'].set_visible(False)
    ax1.spines['right'].set_visible(False)
    ax1.spines['left'].set_visible(False)

    # 2. Grade distribution (top center)
    ax2 = fig.add_subplot(gs[0, 1])
    grades = ["A", "B", "C", "D", "F"]
    counts = [report["grade_distribution"].get(g, 0) for g in grades]
    colors = [COLORS[g] for g in grades]
    ax2.bar(grades, counts, color=colors)
    ax2.set_title('Grade Distribution', fontsize=12, fontweight='bold')
    ax2.set_ylabel('Count')

    # 3. Key stats (top right)
    ax3 = fig.add_subplot(gs[0, 2])
    ax3.axis('off')
    stats_text = f"""
    KEY METRICS

    Total Apps: {report['total_apps']}
    Average Score: {report['avg_score']}/100
    Median Score: {report['median_score']}/100
    Std Deviation: {report['score_std_dev']}

    Apps with Grade B+: {report['grade_distribution'].get('A', 0) + report['grade_distribution'].get('B', 0)}
    Apps with Grade C-: {report['grade_distribution'].get('C', 0) + report['grade_distribution'].get('D', 0) + report['grade_distribution'].get('F', 0)}
    """
    ax3.text(0.1, 0.5, stats_text, transform=ax3.transAxes, fontsize=11,
            verticalalignment='center', fontfamily='monospace',
            bbox=dict(boxstyle='round', facecolor='#ecf0f1', alpha=0.8))

    # 4. Category scores (bottom left)
    ax4 = fig.add_subplot(gs[1, 0])
    cats = list(report["category_stats"].keys())
    cat_scores = [report["category_stats"][c]["avg_score"] for c in cats]
    cat_colors = ['#e74c3c' if s < 50 else '#f39c12' if s < 70 else '#2ecc71' for s in cat_scores]
    ax4.barh(cats, cat_scores, color=cat_colors)
    ax4.set_xlim(0, 100)
    ax4.set_title('Category Scores', fontsize=12, fontweight='bold')
    ax4.set_xlabel('Score')

    # 5. Header adoption (bottom center + right)
    ax5 = fig.add_subplot(gs[1, 1:])
    headers = list(report["header_adoption"].keys())[:6]  # Top 6
    rates = [report["header_adoption"][h]["adoption_rate"] for h in headers]
    header_colors = ['#e74c3c' if r < 20 else '#f39c12' if r < 50 else '#2ecc71' for r in rates]
    ax5.barh(headers, rates, color=header_colors)
    ax5.set_xlim(0, 110)
    ax5.set_title('Security Header Adoption Rates', fontsize=12, fontweight='bold')
    ax5.set_xlabel('Adoption %')

    plt.suptitle('SSAP Security Study — Dashboard', fontsize=18, fontweight='bold', y=0.98)

    save_figure(fig, output_dir, "summary_dashboard")


def main():
    parser = argparse.ArgumentParser(description="SSAP Security Study — Visualizations")
    parser.add_argument("--input", default="output/analysis_report.json", help="Path to analysis_report.json")
    parser.add_argument("--scan-results", default=None, help="Path to scan_results.json (for histogram)")
    parser.add_argument("--output", default="figures", help="Output directory for figures")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    # Load analysis report
    logger.info(f"Loading analysis from {args.input}")
    with open(args.input) as f:
        report = json.load(f)

    # Load scan results if provided (for histogram)
    scan_results = None
    if args.scan_results:
        with open(args.scan_results) as f:
            scan_results = json.load(f)
    else:
        # Try default path
        default_scan = Path(args.input).parent.parent / "scanner" / "output" / "scan_results.json"
        if default_scan.exists():
            with open(default_scan) as f:
                scan_results = json.load(f)

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Generating visualizations...")

    # Generate all charts
    plot_grade_distribution(report, output_dir)
    plot_platform_comparison(report, output_dir)
    plot_category_scores(report, output_dir)
    plot_header_adoption(report, output_dir)
    plot_top_vulnerabilities(report, output_dir)
    plot_supabase_analysis(report, output_dir)
    plot_summary_dashboard(report, output_dir)

    if scan_results:
        plot_score_distribution(report, scan_results, output_dir)

    logger.info(f"\nAll visualizations saved to: {output_dir}/")

    # List generated files
    files = sorted(output_dir.glob("*.png"))
    print("\nGenerated figures:")
    for f in files:
        print(f"  - {f.name}")


if __name__ == "__main__":
    main()
