"""
Social Media & Community Scraper
=================================

Mining Reddit, IndieHackers, Product Hunt, Twitter/X, and vibe-coding directories
for deployed app URLs.

Sources:
1. Reddit: r/SideProject, r/webdev, r/Supabase, r/nextjs — "built with [platform]"
2. Product Hunt: launches tagged AI/no-code/vibe-coding
3. Community directories: vibehub.vercel.app, vibe-hall.vercel.app
4. IndieHackers: product launches mentioning platforms
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

# Keywords indicating vibe-coded origin
VIBE_KEYWORDS = [
    "built with lovable", "made with lovable", "lovable.dev",
    "built with bolt", "bolt.new", "bolt new",
    "built with cursor", "cursor ai", "cursor ide",
    "built with replit", "replit agent",
    "built with v0", "v0.dev",
    "vibe coded", "vibe-coded", "vibe coding",
    "ai generated app", "ai built app",
    "no code app", "no-code",
]


async def _scrape_reddit(client: httpx.AsyncClient) -> list[DiscoveredApp]:
    """
    Search Reddit for posts mentioning vibe-coding platforms with deployed URLs.
    
    CLAUDE CODE NOTES:
    - Use Reddit's JSON API (append .json to any Reddit URL)
    - Search specific subreddits known for indie dev showcases
    - Extract URLs from post body (selftext) and comments
    - Rate limit: 1 request per 2 seconds
    - Consider using Pushshift API for historical data if available
    """
    apps = []
    subreddits = ["SideProject", "webdev", "Supabase", "nextjs", "reactjs", "programming"]
    search_terms = ["built+with+lovable", "bolt.new", "vibe+coded", "built+with+cursor", "replit+agent"]
    
    for subreddit in subreddits:
        for term in search_terms:
            try:
                url = f"https://www.reddit.com/r/{subreddit}/search.json"
                params = {
                    "q": term,
                    "sort": "new",
                    "t": "year",
                    "limit": "100",
                    "restrict_sr": "on",
                }
                
                resp = await client.get(url, params=params, follow_redirects=True)
                if resp.status_code == 200:
                    data = resp.json()
                    posts = data.get("data", {}).get("children", [])
                    
                    for post in posts:
                        post_data = post.get("data", {})
                        selftext = post_data.get("selftext", "")
                        post_url = post_data.get("url", "")
                        title = post_data.get("title", "")
                        
                        # Extract URLs from post body
                        urls_found = re.findall(
                            r'https?://[a-zA-Z0-9.-]+\.(vercel\.app|netlify\.app|lovable\.app|replit\.app|repl\.co|[a-z]{2,})[^\s")\]]*',
                            selftext + " " + post_url
                        )
                        
                        for found_url in urls_found:
                            full_url = found_url if found_url.startswith("http") else f"https://{found_url}"
                            domain = _extract_domain(full_url)
                            if domain and not _is_social_domain(domain):
                                platform = _detect_platform(title + " " + selftext)
                                apps.append(DiscoveredApp(
                                    url=full_url,
                                    domain=domain,
                                    platform=platform,
                                    discovery_source=f"reddit/r/{subreddit}",
                                    discovery_date=datetime.now(timezone.utc).isoformat(),
                                    raw_metadata={
                                        "reddit_title": title[:200],
                                        "reddit_subreddit": subreddit,
                                        "reddit_score": post_data.get("score", 0),
                                    },
                                ))
                
                await asyncio.sleep(2)  # Reddit rate limit
                
            except Exception as e:
                logger.debug(f"Reddit search failed for r/{subreddit} '{term}': {e}")
    
    logger.info(f"Reddit mining: found {len(apps)} app URLs")
    return apps


async def _scrape_vibe_directories(client: httpx.AsyncClient) -> list[DiscoveredApp]:
    """
    Scrape vibe-coding community directories:
    - vibehub.vercel.app — Directory of vibe-coded apps across platforms
    - vibe-hall.vercel.app — Showcase for Claude Code, Cursor, v0, Bolt
    - vibeappstore-three.vercel.app — Gemini-powered apps
    """
    apps = []
    
    directories = [
        ("https://vibehub.vercel.app", "vibehub"),
        ("https://vibe-hall.vercel.app", "vibe-hall"),
        ("https://vibeappstore-three.vercel.app", "vibeappstore"),
    ]
    
    for dir_url, source_name in directories:
        try:
            resp = await client.get(dir_url, follow_redirects=True)
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.text, "html.parser")
                
                for link in soup.find_all("a", href=re.compile(r"https?://")):
                    href = link.get("href", "")
                    domain = _extract_domain(href)
                    if domain and not _is_social_domain(domain) and source_name not in domain:
                        apps.append(DiscoveredApp(
                            url=href,
                            domain=domain,
                            platform="unknown",  # Will be fingerprinted later
                            discovery_source=source_name,
                            discovery_date=datetime.now(timezone.utc).isoformat(),
                            raw_metadata={"link_text": link.get_text(strip=True)[:100]},
                        ))
                
                logger.info(f"{source_name}: found {sum(1 for a in apps if a.discovery_source == source_name)} projects")
            
            await asyncio.sleep(1)
        
        except Exception as e:
            logger.error(f"{source_name} scraping failed: {e}")
    
    return apps


def _detect_platform(text: str) -> str:
    """Heuristic platform detection from text context."""
    text_lower = text.lower()
    if "lovable" in text_lower or "gptengineer" in text_lower:
        return "lovable"
    if "bolt.new" in text_lower or "bolt new" in text_lower:
        return "bolt"
    if "replit" in text_lower:
        return "replit"
    if "cursor" in text_lower or "windsurf" in text_lower:
        return "cursor_vercel"
    if "v0.dev" in text_lower or "v0 dev" in text_lower:
        return "v0"
    return "unknown"


def _extract_domain(url: str) -> str | None:
    match = re.search(r"https?://([^/\s]+)", url)
    return match.group(1).lower().rstrip(".") if match else None


def _is_social_domain(domain: str) -> bool:
    social = [
        "github.com", "twitter.com", "x.com", "linkedin.com", "youtube.com",
        "discord.com", "discord.gg", "reddit.com", "producthunt.com",
        "facebook.com", "instagram.com", "medium.com", "dev.to",
        "stackoverflow.com", "notion.so", "figma.com", "google.com",
    ]
    return any(domain.endswith(d) for d in social)


async def scrape_social() -> list[DiscoveredApp]:
    """Run all social/community discovery sources."""
    async with httpx.AsyncClient(
        timeout=30.0, follow_redirects=True,
        headers={"User-Agent": "SSAP-Research-Bot/1.0 (security-research; contact@securestack.app)"},
    ) as client:
        results = await asyncio.gather(
            _scrape_reddit(client),
            _scrape_vibe_directories(client),
            return_exceptions=True,
        )
        all_apps = []
        for r in results:
            if isinstance(r, list):
                all_apps.extend(r)
            else:
                logger.error(f"Social scraper failed: {r}")
        logger.info(f"Total social/community apps discovered: {len(all_apps)}")
        return all_apps
