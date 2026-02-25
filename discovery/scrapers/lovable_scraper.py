"""
Lovable Platform Scraper
========================

Discovery sources for Lovable-built applications:
1. launched.lovable.dev — Official showcase (note: historically had missing RLS itself)
2. Lovable community Discord/forum shared projects
3. Product Hunt launches tagged Lovable
4. Direct CT log mining for *.lovable.app subdomains

The launched.lovable.dev directory is the richest source. Per Matt Palmer's CVE-2025-48757
research, this directory itself was accessible via Supabase API manipulation, exposing
all listed projects. This may or may not still be possible post-fix.

Target: 2,000 Lovable applications
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timezone

import httpx
from bs4 import BeautifulSoup

# Import the shared data model
import sys
sys.path.append("..")
from pipeline import DiscoveredApp

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------
# Source 1: launched.lovable.dev
# -----------------------------------------------------------------

async def _scrape_launched_lovable(client: httpx.AsyncClient) -> list[DiscoveredApp]:
    """
    Scrape Lovable's official launch directory.
    
    Strategy:
    - First, try the Supabase API approach (if the directory still exposes its own data)
    - Fall back to HTML scraping of the public directory pages
    - Extract project URLs, names, and metadata
    
    IMPLEMENTATION NOTE FOR CLAUDE CODE:
    The launched.lovable.dev site is itself a Lovable-built app using Supabase.
    Check if the Supabase endpoint is still accessible:
    
    1. Load https://launched.lovable.dev in browser, open DevTools Network tab
    2. Look for Supabase REST API calls (*.supabase.co/rest/v1/*)
    3. Note the project URL and anon key from the JS bundle
    4. If accessible, query the projects/launches table directly
    5. If not, fall back to HTML scraping with pagination
    """
    apps = []
    
    try:
        # Attempt 1: HTML scraping of directory pages
        page = 1
        max_pages = 100  # Safety limit
        
        while page <= max_pages:
            url = f"https://launched.lovable.dev?page={page}"
            resp = await client.get(url, follow_redirects=True)
            
            if resp.status_code != 200:
                break
            
            soup = BeautifulSoup(resp.text, "html.parser")
            
            # Look for project cards/links
            # NOTE: Actual selectors depend on the page structure — Claude Code
            # should inspect the live page and adapt these selectors
            project_links = soup.find_all("a", href=re.compile(r"https?://.*\.lovable\.app"))
            
            if not project_links:
                # Try alternative patterns
                project_links = soup.find_all("a", href=re.compile(r"https?://[a-z0-9-]+\.[a-z]+"))
            
            if not project_links:
                break  # No more projects found
            
            for link in project_links:
                href = link.get("href", "")
                if href and "lovable" not in href.replace("lovable.app", ""):
                    # This is a project URL, not a lovable.dev internal link
                    domain = _extract_domain(href)
                    if domain:
                        apps.append(DiscoveredApp(
                            url=href,
                            domain=domain,
                            platform="lovable",
                            discovery_source="launched.lovable.dev",
                            discovery_date=datetime.now(timezone.utc).isoformat(),
                            raw_metadata={
                                "page": page,
                                "link_text": link.get_text(strip=True)[:100],
                            }
                        ))
            
            page += 1
            await asyncio.sleep(1)  # Rate limiting
        
        logger.info(f"launched.lovable.dev: found {len(apps)} projects across {page - 1} pages")
        
    except Exception as e:
        logger.error(f"launched.lovable.dev scraping failed: {e}")
    
    return apps


# -----------------------------------------------------------------
# Source 2: CT Log Mining for *.lovable.app
# -----------------------------------------------------------------

async def _mine_lovable_ct_logs(client: httpx.AsyncClient) -> list[DiscoveredApp]:
    """
    Query crt.sh for all certificates issued to *.lovable.app subdomains.
    This catches apps that may not be in any directory.
    
    crt.sh API returns JSON with certificate details including:
    - name_value: The domain name(s) on the certificate
    - not_before / not_after: Certificate validity dates
    - issuer_name: CA that issued the cert (typically Let's Encrypt for Lovable)
    """
    apps = []
    
    try:
        # crt.sh API for wildcard search
        url = "https://crt.sh/"
        params = {"q": "%.lovable.app", "output": "json"}
        
        resp = await client.get(url, params=params, timeout=60.0)
        
        if resp.status_code == 200:
            certs = resp.json()
            
            seen_domains = set()
            for cert in certs:
                # name_value can contain multiple domains separated by newlines
                names = cert.get("name_value", "").strip().split("\n")
                for name in names:
                    name = name.strip().lower()
                    # Skip wildcard entries and the base domain
                    if name.startswith("*.") or name == "lovable.app":
                        continue
                    if name.endswith(".lovable.app") and name not in seen_domains:
                        seen_domains.add(name)
                        apps.append(DiscoveredApp(
                            url=f"https://{name}",
                            domain=name,
                            platform="lovable",
                            discovery_source="crt.sh",
                            discovery_date=datetime.now(timezone.utc).isoformat(),
                            raw_metadata={
                                "cert_not_before": cert.get("not_before"),
                                "cert_not_after": cert.get("not_after"),
                                "cert_issuer": cert.get("issuer_name"),
                            }
                        ))
            
            logger.info(f"crt.sh *.lovable.app: found {len(apps)} unique subdomains from {len(certs)} certificates")
        else:
            logger.warning(f"crt.sh returned {resp.status_code}")
    
    except Exception as e:
        logger.error(f"CT log mining for lovable.app failed: {e}")
    
    return apps


# -----------------------------------------------------------------
# Source 3: Product Hunt Lovable launches
# -----------------------------------------------------------------

async def _scrape_producthunt_lovable(client: httpx.AsyncClient) -> list[DiscoveredApp]:
    """
    Search Product Hunt for products tagged with or mentioning Lovable.
    
    IMPLEMENTATION NOTE FOR CLAUDE CODE:
    Product Hunt has a GraphQL API. Use it to search for:
    - Posts mentioning "lovable" or "built with lovable"
    - Posts in the "no-code" or "AI" categories that mention Lovable
    - Extract the product website URLs
    
    Alternative: Scrape the search results page at:
    https://www.producthunt.com/search?q=lovable
    """
    apps = []
    
    try:
        search_url = "https://www.producthunt.com/search"
        params = {"q": "built with lovable"}
        
        resp = await client.get(search_url, params=params, follow_redirects=True)
        
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.text, "html.parser")
            # Extract product URLs from search results
            # NOTE: Adapt selectors to actual PH page structure
            product_links = soup.find_all("a", href=re.compile(r"/posts/"))
            
            for link in product_links:
                # Each product page contains the actual website URL
                # Would need a second fetch to get the real URL
                pass
            
            logger.info(f"ProductHunt lovable search: found {len(apps)} products")
        
    except Exception as e:
        logger.error(f"ProductHunt scraping failed: {e}")
    
    return apps


# -----------------------------------------------------------------
# Utility
# -----------------------------------------------------------------

def _extract_domain(url: str) -> str | None:
    """Extract clean domain from URL."""
    try:
        import tldextract
        ext = tldextract.extract(url)
        if ext.domain and ext.suffix:
            if ext.subdomain:
                return f"{ext.subdomain}.{ext.domain}.{ext.suffix}"
            return f"{ext.domain}.{ext.suffix}"
    except Exception:
        pass
    
    # Fallback regex
    match = re.search(r"https?://([^/]+)", url)
    return match.group(1).lower() if match else None


# -----------------------------------------------------------------
# Main entry point
# -----------------------------------------------------------------

async def scrape_lovable() -> list[DiscoveredApp]:
    """Run all Lovable discovery sources and return combined results."""
    
    async with httpx.AsyncClient(
        timeout=30.0,
        follow_redirects=True,
        headers={"User-Agent": "SSAP-Research-Bot/1.0 (security-research; contact@securestack.app)"},
        limits=httpx.Limits(max_connections=10, max_keepalive_connections=5),
    ) as client:
        
        results = await asyncio.gather(
            _scrape_launched_lovable(client),
            _mine_lovable_ct_logs(client),
            _scrape_producthunt_lovable(client),
            return_exceptions=True,
        )
        
        all_apps = []
        for result in results:
            if isinstance(result, list):
                all_apps.extend(result)
            else:
                logger.error(f"Scraper failed: {result}")
        
        logger.info(f"Total Lovable apps discovered: {len(all_apps)}")
        return all_apps
