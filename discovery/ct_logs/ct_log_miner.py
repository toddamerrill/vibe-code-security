"""
Certificate Transparency Log Miner
====================================

Query CT logs for all SSL certificates issued to vibe-coding platform domains.
This is the most scalable discovery method, yielding thousands of domains per platform.

Sources:
- crt.sh (Comodo CT search)
- Censys (certificate search)
- Certstream (real-time CT monitoring)

For Vercel/Netlify (shared platforms), CT mining produces millions of results.
These must be filtered through the fingerprinting pipeline to identify vibe-coded apps.

CLAUDE CODE NOTES:
- crt.sh can be slow for broad queries (*.vercel.app) — use pagination
- Results contain duplicates across certificate renewals — deduplicate on domain
- Prioritize recently-issued certs (last 12 months) for vibe-coding era
- Consider Censys as backup if crt.sh is rate-limited
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timezone, timedelta

import httpx

import sys
sys.path.append("..")
from pipeline import DiscoveredApp

logger = logging.getLogger(__name__)

# Platform domains and their corresponding vibe-coding platform
CT_TARGETS = [
    # High-confidence: these domains ARE the vibe-coding platform
    ("%.lovable.app", "lovable", 100),
    ("%.replit.app", "replit", 90),
    ("%.repl.co", "replit", 90),
    
    # Medium-confidence: shared hosting — needs fingerprinting
    # NOTE: These will return MASSIVE result sets. Consider sampling.
    # ("%.vercel.app", "unknown", 0),   # Millions of results — sample or skip
    # ("%.netlify.app", "unknown", 0),  # Millions of results — sample or skip
]

# For Vercel/Netlify, we use a targeted approach instead of full CT mining
VERCEL_SAMPLE_SIZE = 5000   # Random sample of recent Vercel certs
NETLIFY_SAMPLE_SIZE = 3000  # Random sample of recent Netlify certs


async def _query_crt_sh(
    client: httpx.AsyncClient,
    domain_pattern: str,
    platform: str,
    confidence: int,
) -> list[DiscoveredApp]:
    """
    Query crt.sh for certificates matching a domain pattern.
    Returns deduplicated list of unique subdomains.
    """
    apps = []
    
    try:
        logger.info(f"Querying crt.sh for {domain_pattern}...")
        
        resp = await client.get(
            "https://crt.sh/",
            params={"q": domain_pattern, "output": "json"},
            timeout=120.0,  # CT queries can be slow
        )
        
        if resp.status_code == 200:
            certs = resp.json()
            
            seen_domains = set()
            for cert in certs:
                names = cert.get("name_value", "").strip().split("\n")
                not_before = cert.get("not_before", "")
                
                for name in names:
                    name = name.strip().lower()
                    
                    # Skip wildcards and base domains
                    if name.startswith("*."):
                        continue
                    
                    # Deduplicate
                    if name in seen_domains:
                        continue
                    seen_domains.add(name)
                    
                    apps.append(DiscoveredApp(
                        url=f"https://{name}",
                        domain=name,
                        platform=platform,
                        discovery_source="crt.sh",
                        discovery_date=datetime.now(timezone.utc).isoformat(),
                        vibe_confidence_score=confidence,
                        raw_metadata={
                            "cert_not_before": not_before,
                            "cert_not_after": cert.get("not_after"),
                            "cert_issuer": cert.get("issuer_name"),
                            "ct_id": cert.get("id"),
                        },
                    ))
            
            logger.info(f"crt.sh {domain_pattern}: {len(apps)} unique subdomains from {len(certs)} certificates")
        
        elif resp.status_code == 429:
            logger.warning(f"crt.sh rate limited for {domain_pattern}")
        else:
            logger.warning(f"crt.sh returned {resp.status_code} for {domain_pattern}")
    
    except Exception as e:
        logger.error(f"crt.sh query failed for {domain_pattern}: {e}")
    
    return apps


async def _sample_vercel_ct(client: httpx.AsyncClient) -> list[DiscoveredApp]:
    """
    Sample recent Vercel deployments from CT logs.
    
    Full *.vercel.app CT query returns millions of results.
    Instead, we query for recent certificates only and take a random sample.
    
    CLAUDE CODE IMPLEMENTATION:
    - Use crt.sh with date filters if available
    - Alternative: Use Censys API which supports better filtering
    - Alternative: Use Certstream to collect real-time Vercel certs over 1-2 weeks
    """
    apps = []
    
    try:
        # Try crt.sh with a very recent date range to limit results
        # crt.sh doesn't support date filters natively in the URL API,
        # so we query and filter client-side
        
        # NOTE: This query may time out for *.vercel.app.
        # Claude Code should implement a Certstream-based collector instead:
        #
        # import certstream
        # def callback(message, context):
        #     if message['message_type'] == 'certificate_update':
        #         domains = message['data']['leaf_cert']['all_domains']
        #         vercel_domains = [d for d in domains if d.endswith('.vercel.app')]
        #         for d in vercel_domains:
        #             save_to_queue(d)
        #
        # certstream.listen_for_events(callback)
        #
        # Run for 7-14 days to collect a representative sample.
        
        logger.info("Vercel CT sampling: recommend using Certstream collector (see implementation notes)")
        
    except Exception as e:
        logger.error(f"Vercel CT sampling failed: {e}")
    
    return apps


async def mine_ct_logs() -> list[DiscoveredApp]:
    """Run CT log mining across all target platforms."""
    
    async with httpx.AsyncClient(
        timeout=120.0,
        follow_redirects=True,
        headers={"User-Agent": "SSAP-Research-Bot/1.0"},
    ) as client:
        
        all_apps = []
        
        # Mine high-confidence platform domains
        for domain_pattern, platform, confidence in CT_TARGETS:
            apps = await _query_crt_sh(client, domain_pattern, platform, confidence)
            all_apps.extend(apps)
            await asyncio.sleep(5)  # Be gentle with crt.sh
        
        # Sample shared platforms
        vercel_apps = await _sample_vercel_ct(client)
        all_apps.extend(vercel_apps)
        
        logger.info(f"CT log mining complete: {len(all_apps)} total domains discovered")
        return all_apps
