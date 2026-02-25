"""
GitHub Repository Miner
========================

Search GitHub for repositories that were built with vibe-coding tools
and have deployed URLs in their READMEs or deployment configs.

Strategy:
1. Search repos by topic: "vibe-coding", "lovable", "bolt-new", "cursor-ai"
2. Search repos with Vercel/Netlify deployment badges
3. Extract deployed URLs from README.md
4. Extract deployed URLs from vercel.json, netlify.toml
5. Cross-reference with Vercel/Netlify deployment domains

CLAUDE CODE NOTES:
- GitHub Search API: max 1000 results per query, 30 requests/minute
- Use GITHUB_TOKEN env var for higher rate limits (5000 req/hr)
- Focus on repos created in last 12 months (vibe coding era)
"""

import asyncio
import base64
import logging
import os
import re
from datetime import datetime, timezone

import httpx

import sys
sys.path.append("..")
from pipeline import DiscoveredApp

logger = logging.getLogger(__name__)

GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITHUB_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}
if GITHUB_TOKEN:
    GITHUB_HEADERS["Authorization"] = f"Bearer {GITHUB_TOKEN}"

# Search queries that identify vibe-coded repos
SEARCH_QUERIES = [
    'topic:vibe-coding',
    'topic:lovable',
    'topic:bolt-new',
    '"built with lovable" in:readme',
    '"built with bolt" in:readme',
    '"built with cursor" in:readme',
    '"made with lovable" in:readme',
    '"replit agent" in:readme',
    '"v0.dev" in:readme created:>2025-01-01',
    '"lovable.app" in:readme',
    '"bolt.new" in:readme created:>2025-01-01',
    'filename:vercel.json "supabase" created:>2025-01-01',
]

# URL patterns to extract from READMEs
DEPLOY_URL_PATTERNS = [
    re.compile(r'https?://[a-z0-9-]+\.vercel\.app'),
    re.compile(r'https?://[a-z0-9-]+\.netlify\.app'),
    re.compile(r'https?://[a-z0-9-]+\.lovable\.app'),
    re.compile(r'https?://[a-z0-9-]+\.replit\.app'),
    re.compile(r'https?://[a-z0-9-]+\.repl\.co'),
    # Custom domains with common patterns
    re.compile(r'https?://(?:app|www|demo)\.[a-z0-9-]+\.[a-z]{2,6}'),
]


async def _search_github_repos(client: httpx.AsyncClient) -> list[dict]:
    """Search GitHub for vibe-coded repositories."""
    all_repos = []
    seen_ids = set()
    
    for query in SEARCH_QUERIES:
        try:
            page = 1
            while page <= 5:  # Max 5 pages per query (500 results)
                resp = await client.get(
                    "https://api.github.com/search/repositories",
                    params={
                        "q": query,
                        "sort": "updated",
                        "order": "desc",
                        "per_page": "100",
                        "page": str(page),
                    },
                    headers=GITHUB_HEADERS,
                )
                
                if resp.status_code == 403:
                    logger.warning("GitHub rate limit hit, pausing 60s")
                    await asyncio.sleep(60)
                    continue
                
                if resp.status_code != 200:
                    break
                
                data = resp.json()
                items = data.get("items", [])
                
                if not items:
                    break
                
                for repo in items:
                    repo_id = repo.get("id")
                    if repo_id not in seen_ids:
                        seen_ids.add(repo_id)
                        all_repos.append(repo)
                
                page += 1
                await asyncio.sleep(2)  # Rate limit
            
            logger.info(f"GitHub query '{query[:50]}...': {len([r for r in all_repos if r['id'] in seen_ids])} total repos so far")
            await asyncio.sleep(3)
        
        except Exception as e:
            logger.error(f"GitHub search failed for query '{query[:50]}': {e}")
    
    logger.info(f"GitHub total repos found: {len(all_repos)}")
    return all_repos


async def _extract_deploy_urls(client: httpx.AsyncClient, repo: dict) -> list[DiscoveredApp]:
    """Extract deployed app URLs from a GitHub repo's README."""
    apps = []
    full_name = repo.get("full_name", "")
    
    try:
        # Fetch README content via API
        resp = await client.get(
            f"https://api.github.com/repos/{full_name}/readme",
            headers=GITHUB_HEADERS,
        )
        
        if resp.status_code == 200:
            data = resp.json()
            content = data.get("content", "")
            encoding = data.get("encoding", "base64")
            
            if encoding == "base64" and content:
                readme_text = base64.b64decode(content).decode("utf-8", errors="replace")
            else:
                readme_text = content
            
            # Also check repo homepage URL
            homepage = repo.get("homepage", "") or ""
            readme_text += f"\n{homepage}"
            
            # Extract deployment URLs
            for pattern in DEPLOY_URL_PATTERNS:
                matches = pattern.findall(readme_text)
                for url in matches:
                    domain = re.search(r'https?://([^/\s]+)', url)
                    if domain:
                        d = domain.group(1).lower()
                        if not _is_github_domain(d):
                            platform = _detect_platform_from_repo(repo, readme_text)
                            apps.append(DiscoveredApp(
                                url=url,
                                domain=d,
                                platform=platform,
                                discovery_source="github",
                                discovery_date=datetime.now(timezone.utc).isoformat(),
                                raw_metadata={
                                    "github_repo": full_name,
                                    "github_stars": repo.get("stargazers_count", 0),
                                    "github_created": repo.get("created_at"),
                                    "github_language": repo.get("language"),
                                    "github_topics": repo.get("topics", []),
                                },
                            ))
        
        await asyncio.sleep(1)
    
    except Exception as e:
        logger.debug(f"Failed to extract URLs from {full_name}: {e}")
    
    return apps


def _detect_platform_from_repo(repo: dict, readme: str) -> str:
    """Detect vibe-coding platform from repo metadata and README content."""
    topics = set(t.lower() for t in repo.get("topics", []))
    text = (readme + " " + " ".join(topics)).lower()
    
    if "lovable" in text or "gptengineer" in text:
        return "lovable"
    if "bolt.new" in text or "bolt-new" in topics or "boltnew" in text:
        return "bolt"
    if "replit" in text:
        return "replit"
    if "cursor" in text or "windsurf" in text:
        return "cursor_vercel"
    if "v0.dev" in text or "v0-dev" in topics:
        return "v0"
    return "unknown"


def _is_github_domain(domain: str) -> bool:
    github_domains = [
        "github.com", "github.io", "githubusercontent.com",
        "raw.githubusercontent.com",
    ]
    return any(domain.endswith(d) for d in github_domains)


async def mine_github() -> list[DiscoveredApp]:
    """Run GitHub repository mining pipeline."""
    async with httpx.AsyncClient(
        timeout=30.0, follow_redirects=True,
        headers={"User-Agent": "SSAP-Research-Bot/1.0"},
    ) as client:
        # Step 1: Search for repos
        repos = await _search_github_repos(client)
        
        # Step 2: Extract deployed URLs from each repo's README
        all_apps = []
        for i, repo in enumerate(repos):
            apps = await _extract_deploy_urls(client, repo)
            all_apps.extend(apps)
            
            if (i + 1) % 50 == 0:
                logger.info(f"Processed {i + 1}/{len(repos)} repos, {len(all_apps)} URLs found")
        
        logger.info(f"GitHub mining complete: {len(all_apps)} app URLs from {len(repos)} repos")
        return all_apps
