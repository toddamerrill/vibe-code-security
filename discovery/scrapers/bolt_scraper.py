"""
Bolt.new Platform Scraper
=========================

Discovery sources for Bolt.new-built applications:
1. bolt.new/gallery/all — Official project gallery
2. madewithbolt.com — Community directory (~hundreds of apps)
3. showmeyourbolt.io — Community showcase
4. bolters.io — Community support hub
5. CT logs for *.netlify.app (Bolt deploys primarily to Netlify)

Bolt.new apps deploy to various targets but predominantly Netlify.
Tech stack varies more than Lovable (supports Next.js, Svelte, Vue, React).
BaaS can be Supabase, Bolt DB, Firebase, or none.

Target: 2,000 Bolt.new applications
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timezone

import httpx
from bs4 import BeautifulSoup

import sys
sys.path.append("..")
from pipeline import DiscoveredApp

logger = logging.getLogger(__name__)


async def _scrape_bolt_gallery(client: httpx.AsyncClient) -> list[DiscoveredApp]:
    """
    Scrape bolt.new/gallery for published projects.
    
    CLAUDE CODE IMPLEMENTATION NOTES:
    - The gallery at bolt.new/gallery/all lists community-submitted projects
    - Each card typically contains: project name, description, live URL, screenshot
    - Gallery may use infinite scroll or pagination — handle both
    - Some projects link to bolt.new share URLs, others to deployed sites
    - Extract the DEPLOYED URL (not the bolt.new editor URL)
    """
    apps = []
    
    try:
        # Try paginated approach first
        page = 1
        max_pages = 50
        
        while page <= max_pages:
            url = f"https://bolt.new/gallery/all"
            params = {"page": str(page)} if page > 1 else {}
            
            resp = await client.get(url, params=params, follow_redirects=True)
            if resp.status_code != 200:
                break
            
            soup = BeautifulSoup(resp.text, "html.parser")
            
            # Look for project cards with external links
            # NOTE: Adapt selectors after inspecting live page
            links = soup.find_all("a", href=re.compile(r"https?://(?!bolt\.new)"))
            
            found_any = False
            for link in links:
                href = link.get("href", "")
                domain = _extract_domain(href)
                if domain and not _is_internal(domain):
                    apps.append(DiscoveredApp(
                        url=href,
                        domain=domain,
                        platform="bolt",
                        discovery_source="bolt.new/gallery",
                        discovery_date=datetime.now(timezone.utc).isoformat(),
                        raw_metadata={"gallery_page": page},
                    ))
                    found_any = True
            
            if not found_any:
                break
            
            page += 1
            await asyncio.sleep(1.5)
        
        logger.info(f"bolt.new/gallery: found {len(apps)} projects")
    
    except Exception as e:
        logger.error(f"bolt.new gallery scraping failed: {e}")
    
    return apps


async def _scrape_madewithbolt(client: httpx.AsyncClient) -> list[DiscoveredApp]:
    """
    Scrape madewithbolt.com — the largest community directory for Bolt projects.
    
    CLAUDE CODE NOTES:
    - Community-curated directory with categories
    - Each listing has: project name, URL, description, category, upvotes
    - May use API endpoints for listing data (check Network tab)
    """
    apps = []
    
    try:
        resp = await client.get("https://madewithbolt.com", follow_redirects=True)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            
            # Extract project URLs from listing cards
            project_links = soup.find_all("a", href=re.compile(r"https?://"))
            
            for link in project_links:
                href = link.get("href", "")
                domain = _extract_domain(href)
                if domain and not _is_internal(domain) and "madewithbolt" not in domain:
                    apps.append(DiscoveredApp(
                        url=href,
                        domain=domain,
                        platform="bolt",
                        discovery_source="madewithbolt.com",
                        discovery_date=datetime.now(timezone.utc).isoformat(),
                    ))
        
        logger.info(f"madewithbolt.com: found {len(apps)} projects")
    
    except Exception as e:
        logger.error(f"madewithbolt.com scraping failed: {e}")
    
    return apps


async def _scrape_showmeyourbolt(client: httpx.AsyncClient) -> list[DiscoveredApp]:
    """Scrape showmeyourbolt.io community showcase."""
    apps = []
    try:
        resp = await client.get("https://showmeyourbolt.io", follow_redirects=True)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            for link in soup.find_all("a", href=re.compile(r"https?://")):
                href = link.get("href", "")
                domain = _extract_domain(href)
                if domain and not _is_internal(domain) and "showmeyourbolt" not in domain:
                    apps.append(DiscoveredApp(
                        url=href, domain=domain, platform="bolt",
                        discovery_source="showmeyourbolt.io",
                        discovery_date=datetime.now(timezone.utc).isoformat(),
                    ))
        logger.info(f"showmeyourbolt.io: found {len(apps)} projects")
    except Exception as e:
        logger.error(f"showmeyourbolt.io scraping failed: {e}")
    return apps


def _extract_domain(url: str) -> str | None:
    match = re.search(r"https?://([^/]+)", url)
    return match.group(1).lower().rstrip(".") if match else None


def _is_internal(domain: str) -> bool:
    """Filter out non-project domains."""
    internal = [
        "bolt.new", "stackblitz.com", "github.com", "twitter.com", "x.com",
        "linkedin.com", "youtube.com", "discord.com", "discord.gg",
        "reddit.com", "producthunt.com", "facebook.com", "instagram.com",
    ]
    return any(domain.endswith(d) or domain == d for d in internal)


async def scrape_bolt() -> list[DiscoveredApp]:
    """Run all Bolt.new discovery sources."""
    async with httpx.AsyncClient(
        timeout=30.0, follow_redirects=True,
        headers={"User-Agent": "SSAP-Research-Bot/1.0 (security-research; todd@silverbackcto.com)"},
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    ) as client:
        results = await asyncio.gather(
            _scrape_bolt_gallery(client),
            _scrape_madewithbolt(client),
            _scrape_showmeyourbolt(client),
            return_exceptions=True,
        )
        all_apps = []
        for result in results:
            if isinstance(result, list):
                all_apps.extend(result)
            else:
                logger.error(f"Bolt scraper failed: {result}")
        
        logger.info(f"Total Bolt.new apps discovered: {len(all_apps)}")
        return all_apps
