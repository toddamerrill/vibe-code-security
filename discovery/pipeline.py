"""
SSAP Security Study — Master Discovery Pipeline
=================================================

Orchestrates the full app discovery process across all sources:
1. Platform directory scraping (Lovable, Bolt, Replit, etc.)
2. Certificate Transparency log mining
3. GitHub/social media mining
4. Fingerprinting and classification
5. Dataset curation (dedup, sampling, exclusions)

Usage:
    python pipeline.py --phase discover     # Run all discovery sources
    python pipeline.py --phase fingerprint  # Apply vibe-code heuristics
    python pipeline.py --phase curate       # Deduplicate, filter, sample
    python pipeline.py --phase all          # Full pipeline

Output:
    output/raw_discovered.json      — All discovered URLs with source attribution
    output/fingerprinted.json       — URLs with vibe-code confidence scores
    output/curated_apps.json        — Final dataset ready for scanning

Requirements:
    pip install httpx beautifulsoup4 pyjwt tldextract shodan
    Environment variables:
        SHODAN_API_KEY (optional, for Shodan queries)
        GITHUB_TOKEN (optional, for higher API rate limits)
"""

import argparse
import asyncio
import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx

# -----------------------------------------------------------------
# Data Model
# -----------------------------------------------------------------

@dataclass
class DiscoveredApp:
    """Represents a single discovered vibe-coded application."""
    url: str                                # Canonical URL (https://app.lovable.app)
    domain: str                             # Extracted domain
    platform: str                           # lovable | bolt | replit | v0 | create_xyz | base44 | cursor_vercel | unknown
    discovery_source: str                   # Which scraper/source found it
    discovery_date: str                     # ISO timestamp
    raw_metadata: dict = field(default_factory=dict)  # Platform-specific metadata
    
    # Populated during fingerprinting phase
    vibe_confidence_score: int = 0          # 0-100 confidence this is vibe-coded
    detected_baas: Optional[str] = None     # supabase | firebase | convex | replit_db | none
    detected_framework: Optional[str] = None # react | next | svelte | vue | etc
    supabase_url: Optional[str] = None      # Extracted Supabase project URL
    supabase_anon_key: Optional[str] = None # Extracted anon key (public by design)
    has_custom_domain: bool = False          # Using custom domain vs platform subdomain
    
    # Populated during curation
    is_live: bool = True                    # HTTP 200 check
    is_excluded: bool = False               # Healthcare/edu/gov exclusion
    exclusion_reason: Optional[str] = None
    
    @property
    def app_id(self) -> str:
        """Deterministic hash ID for deduplication."""
        return hashlib.sha256(self.domain.encode()).hexdigest()[:16]


# -----------------------------------------------------------------
# Phase 1: Discovery — Collect URLs from all sources
# -----------------------------------------------------------------

async def discover_all(output_dir: Path) -> list[DiscoveredApp]:
    """
    Run all discovery sources in parallel and collect results.
    Each scraper module returns a list of DiscoveredApp instances.
    """
    logging.info("=== Phase 1: Discovery ===")
    
    all_apps: list[DiscoveredApp] = []
    
    # Import scrapers
    from scrapers.lovable_scraper import scrape_lovable
    from scrapers.bolt_scraper import scrape_bolt
    from scrapers.replit_scraper import scrape_replit
    from scrapers.social_scraper import scrape_social
    from scrapers.github_miner import mine_github
    from ct_logs.ct_log_miner import mine_ct_logs
    
    # Run all scrapers
    # Note: Each scraper handles its own rate limiting and error handling
    scrapers = [
        ("lovable", scrape_lovable),
        ("bolt", scrape_bolt),
        ("replit", scrape_replit),
        ("social", scrape_social),
        ("github", mine_github),
        ("ct_logs", mine_ct_logs),
    ]
    
    for name, scraper_fn in scrapers:
        logging.info(f"Running {name} scraper...")
        try:
            apps = await scraper_fn()
            logging.info(f"  → {name}: discovered {len(apps)} apps")
            all_apps.extend(apps)
        except Exception as e:
            logging.error(f"  → {name} failed: {e}")
    
    # Save raw results
    raw_path = output_dir / "raw_discovered.json"
    with open(raw_path, "w") as f:
        json.dump([asdict(a) for a in all_apps], f, indent=2)
    
    logging.info(f"Total raw discovered: {len(all_apps)} → {raw_path}")
    return all_apps


# -----------------------------------------------------------------
# Phase 2: Fingerprinting — Score each app as vibe-coded or not
# -----------------------------------------------------------------

async def fingerprint_all(apps: list[DiscoveredApp], output_dir: Path) -> list[DiscoveredApp]:
    """
    For each discovered app, fetch its homepage and analyze for vibe-code signals.
    Apps on known vibe-coding subdomains (*.lovable.app, *.replit.app) get auto-scored.
    Apps on shared platforms (Vercel, Netlify) need heuristic fingerprinting.
    """
    logging.info("=== Phase 2: Fingerprinting ===")
    
    from fingerprinting.vibe_fingerprint import fingerprint_app
    
    # Auto-score known platform domains
    PLATFORM_DOMAINS = {
        "lovable.app": ("lovable", 100),
        "replit.app": ("replit", 90),  # 90 because some Replit apps aren't vibe-coded
        "repl.co": ("replit", 90),
        "create.xyz": ("create_xyz", 100),
    }
    
    fingerprinted: list[DiscoveredApp] = []
    
    # Process in batches of 50 concurrent requests
    BATCH_SIZE = 50
    
    for i in range(0, len(apps), BATCH_SIZE):
        batch = apps[i:i + BATCH_SIZE]
        tasks = []
        
        for app in batch:
            # Check if domain matches known platform
            auto_scored = False
            for domain_suffix, (platform, score) in PLATFORM_DOMAINS.items():
                if app.domain.endswith(domain_suffix):
                    app.vibe_confidence_score = score
                    app.platform = platform
                    auto_scored = True
                    break
            
            if not auto_scored:
                # Need to fetch and fingerprint
                tasks.append(fingerprint_app(app))
            else:
                fingerprinted.append(app)
        
        # Run fingerprinting tasks concurrently
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, DiscoveredApp):
                    fingerprinted.append(result)
                else:
                    logging.warning(f"Fingerprint failed: {result}")
        
        logging.info(f"  Fingerprinted {min(i + BATCH_SIZE, len(apps))}/{len(apps)}")
    
    # Save fingerprinted results
    fp_path = output_dir / "fingerprinted.json"
    with open(fp_path, "w") as f:
        json.dump([asdict(a) for a in fingerprinted], f, indent=2)
    
    # Summary stats
    confirmed = [a for a in fingerprinted if a.vibe_confidence_score >= 50]
    logging.info(f"Fingerprinted: {len(fingerprinted)} total, {len(confirmed)} confirmed vibe-coded")
    
    return fingerprinted


# -----------------------------------------------------------------
# Phase 3: Curation — Deduplicate, filter, sample
# -----------------------------------------------------------------

async def curate_dataset(apps: list[DiscoveredApp], output_dir: Path) -> list[DiscoveredApp]:
    """
    Final dataset curation:
    1. Remove duplicates (same domain)
    2. Remove apps with vibe_confidence_score < 50
    3. Verify apps are live (HTTP 200)
    4. Exclude healthcare, education, government domains
    5. Balance platform distribution via stratified sampling
    """
    logging.info("=== Phase 3: Curation ===")
    
    # 1. Deduplicate by domain
    seen_domains: set[str] = set()
    deduped: list[DiscoveredApp] = []
    for app in apps:
        if app.domain not in seen_domains:
            seen_domains.add(app.domain)
            deduped.append(app)
    logging.info(f"  After dedup: {len(deduped)} (removed {len(apps) - len(deduped)} duplicates)")
    
    # 2. Filter by confidence score
    confident = [a for a in deduped if a.vibe_confidence_score >= 50]
    logging.info(f"  After confidence filter (≥50): {len(confident)}")
    
    # 3. Verify live (batch HTTP HEAD requests)
    logging.info("  Checking liveness...")
    live_apps = await _check_liveness(confident)
    logging.info(f"  After liveness check: {len(live_apps)}")
    
    # 4. Exclude sensitive categories
    EXCLUDED_TLDS_PATTERNS = [
        ".edu", ".gov", ".mil",
        "health", "medical", "hospital", "clinic", "patient",
        "school", "university", "college", "student",
    ]
    
    curated: list[DiscoveredApp] = []
    excluded_count = 0
    for app in live_apps:
        domain_lower = app.domain.lower()
        excluded = False
        for pattern in EXCLUDED_TLDS_PATTERNS:
            if pattern in domain_lower:
                app.is_excluded = True
                app.exclusion_reason = f"Matched exclusion pattern: {pattern}"
                excluded = True
                excluded_count += 1
                break
        if not excluded:
            curated.append(app)
    
    logging.info(f"  After exclusions: {len(curated)} (excluded {excluded_count})")
    
    # 5. Platform distribution summary
    platform_counts: dict[str, int] = {}
    for app in curated:
        platform_counts[app.platform] = platform_counts.get(app.platform, 0) + 1
    
    logging.info("  Platform distribution:")
    for platform, count in sorted(platform_counts.items(), key=lambda x: -x[1]):
        logging.info(f"    {platform}: {count}")
    
    # Save curated dataset
    curated_path = output_dir / "curated_apps.json"
    with open(curated_path, "w") as f:
        json.dump([asdict(a) for a in curated], f, indent=2)
    
    logging.info(f"Final curated dataset: {len(curated)} apps → {curated_path}")
    return curated


async def _check_liveness(apps: list[DiscoveredApp], timeout: float = 10.0) -> list[DiscoveredApp]:
    """Check which apps return HTTP 200 (or 301/302 redirect to live page)."""
    live: list[DiscoveredApp] = []
    
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=True,
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    ) as client:
        BATCH = 100
        for i in range(0, len(apps), BATCH):
            batch = apps[i:i + BATCH]
            tasks = [_head_check(client, app) for app in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for app, result in zip(batch, results):
                if isinstance(result, bool) and result:
                    app.is_live = True
                    live.append(app)
                else:
                    app.is_live = False
    
    return live


async def _head_check(client: httpx.AsyncClient, app: DiscoveredApp) -> bool:
    """Single liveness check."""
    try:
        resp = await client.head(f"https://{app.domain}", follow_redirects=True)
        return resp.status_code < 400
    except Exception:
        try:
            resp = await client.get(f"https://{app.domain}", follow_redirects=True)
            return resp.status_code < 400
        except Exception:
            return False


# -----------------------------------------------------------------
# Main CLI
# -----------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="SSAP Security Study — Discovery Pipeline")
    parser.add_argument("--phase", choices=["discover", "fingerprint", "curate", "all"], default="all")
    parser.add_argument("--output", default="output", help="Output directory")
    parser.add_argument("--input", default=None, help="Input file for fingerprint/curate phases")
    args = parser.parse_args()
    
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    if args.phase in ("discover", "all"):
        apps = asyncio.run(discover_all(output_dir))
    else:
        # Load from previous phase output
        input_file = args.input or str(output_dir / "raw_discovered.json")
        with open(input_file) as f:
            data = json.load(f)
        apps = [DiscoveredApp(**d) for d in data]
    
    if args.phase in ("fingerprint", "all"):
        apps = asyncio.run(fingerprint_all(apps, output_dir))
    
    if args.phase in ("curate", "all"):
        if args.phase == "curate" and not args.input:
            fp_file = output_dir / "fingerprinted.json"
            if fp_file.exists():
                with open(fp_file) as f:
                    data = json.load(f)
                apps = [DiscoveredApp(**d) for d in data]
        asyncio.run(curate_dataset(apps, output_dir))


if __name__ == "__main__":
    main()
