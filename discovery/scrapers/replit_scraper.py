"""
Replit Platform Scraper
=======================

Discovery sources for Replit-built applications:
1. Replit Community forum showcase posts
2. Replit Spotlight/Featured projects
3. CT logs for *.replit.app and *.repl.co domains
4. Replit Templates gallery (many deployed as live apps)

Replit apps deploy to:
- *.replit.app (current deployed apps)
- *.repl.co (legacy/development URLs)
- Custom domains (paid tier)

Replit Agent can generate full-stack apps with various BaaS backends.

Target: 2,000 Replit applications
"""

import asyncio
import logging
import re
from datetime import datetime, timezone

import httpx
from bs4 import BeautifulSoup

import sys
sys.path.append("..")
from pipeline import DiscoveredApp

logger = logging.getLogger(__name__)


async def _mine_replit_ct_logs(client: httpx.AsyncClient) -> list[DiscoveredApp]:
    """
    Query CT logs for *.replit.app subdomains.
    This is the highest-yield source for Replit apps.
    """
    apps = []
    try:
        for domain_pattern in ["%.replit.app", "%.repl.co"]:
            resp = await client.get(
                "https://crt.sh/",
                params={"q": domain_pattern, "output": "json"},
                timeout=60.0,
            )
            if resp.status_code == 200:
                certs = resp.json()
                seen = set()
                for cert in certs:
                    names = cert.get("name_value", "").strip().split("\n")
                    for name in names:
                        name = name.strip().lower()
                        if name.startswith("*.") or name in ("replit.app", "repl.co"):
                            continue
                        if name not in seen and (name.endswith(".replit.app") or name.endswith(".repl.co")):
                            seen.add(name)
                            apps.append(DiscoveredApp(
                                url=f"https://{name}",
                                domain=name,
                                platform="replit",
                                discovery_source="crt.sh",
                                discovery_date=datetime.now(timezone.utc).isoformat(),
                                raw_metadata={
                                    "cert_not_before": cert.get("not_before"),
                                    "cert_not_after": cert.get("not_after"),
                                },
                            ))
                logger.info(f"crt.sh {domain_pattern}: found {len(seen)} unique subdomains")
            await asyncio.sleep(2)  # Rate limit crt.sh
    except Exception as e:
        logger.error(f"Replit CT log mining failed: {e}")
    return apps


async def _scrape_replit_community(client: httpx.AsyncClient) -> list[DiscoveredApp]:
    """
    Scrape Replit community forum for shared projects.
    
    CLAUDE CODE NOTES:
    - Forum at replit.discourse.group
    - Look for posts in #showcase and #share-your-project categories
    - Extract *.replit.app URLs from post content
    - Also check replit.com/@username/project-name patterns
    """
    apps = []
    try:
        # Discourse API for topic listing
        categories = ["showcase", "share-your-project"]
        for category in categories:
            resp = await client.get(
                f"https://replit.discourse.group/c/{category}.json",
                follow_redirects=True,
            )
            if resp.status_code == 200:
                data = resp.json()
                topics = data.get("topic_list", {}).get("topics", [])
                for topic in topics[:100]:  # First 100 topics per category
                    topic_id = topic.get("id")
                    if topic_id:
                        # Fetch individual topic for URLs
                        t_resp = await client.get(
                            f"https://replit.discourse.group/t/{topic_id}.json",
                        )
                        if t_resp.status_code == 200:
                            t_data = t_resp.json()
                            posts = t_data.get("post_stream", {}).get("posts", [])
                            for post in posts[:1]:  # Just the OP
                                content = post.get("cooked", "")
                                urls = re.findall(r'https?://[a-z0-9-]+\.replit\.app[^\s"<]*', content)
                                for url in urls:
                                    domain = re.search(r'https?://([^/]+)', url)
                                    if domain:
                                        apps.append(DiscoveredApp(
                                            url=url,
                                            domain=domain.group(1).lower(),
                                            platform="replit",
                                            discovery_source="replit_community_forum",
                                            discovery_date=datetime.now(timezone.utc).isoformat(),
                                        ))
                        await asyncio.sleep(1)
        logger.info(f"Replit community forum: found {len(apps)} projects")
    except Exception as e:
        logger.error(f"Replit community scraping failed: {e}")
    return apps


async def scrape_replit() -> list[DiscoveredApp]:
    """Run all Replit discovery sources."""
    async with httpx.AsyncClient(
        timeout=30.0, follow_redirects=True,
        headers={"User-Agent": "SSAP-Research-Bot/1.0 (security-research; todd@silverbackcto.com)"},
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    ) as client:
        results = await asyncio.gather(
            _mine_replit_ct_logs(client),
            _scrape_replit_community(client),
            return_exceptions=True,
        )
        all_apps = []
        for r in results:
            if isinstance(r, list):
                all_apps.extend(r)
            else:
                logger.error(f"Replit scraper failed: {r}")
        logger.info(f"Total Replit apps discovered: {len(all_apps)}")
        return all_apps
