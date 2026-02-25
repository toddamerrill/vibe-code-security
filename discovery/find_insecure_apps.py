#!/usr/bin/env python3
"""
SSAP Quick Discovery Scanner
Find and scan 10 vibe-coded apps for common security issues.
Run from your Mac with: python3 find_insecure_apps.py

This uses ONLY passive, read-only techniques:
- HTTP GET requests (same as any web browser)
- Reading publicly-served JavaScript bundles
- Checking security response headers
- Testing Supabase RLS with the app's own public anon key (read-only)

NO modifications, NO account creation, NO auth bypass attempts.
"""

import asyncio
import httpx
import re
import json
import sys
import base64
from datetime import datetime
from urllib.parse import urlparse

# ─── Configuration ───────────────────────────────────────────────────────────

TIMEOUT = 20.0
MAX_JS_BUNDLES = 5
MAX_CONCURRENT = 10
OUTPUT_FILE = "scan_results.json"

# ─── Discovery: Find apps from Certificate Transparency logs ─────────────────

CT_LOG_DOMAINS = [
    "%.lovable.app",
    # "%.replit.app",  # Uncomment for broader scan
]

async def discover_from_ct_logs(client: httpx.AsyncClient, domain_pattern: str, limit: int = 50) -> list[str]:
    """Query crt.sh Certificate Transparency logs for deployed apps."""
    print(f"  [CT] Querying crt.sh for {domain_pattern}...")
    try:
        resp = await client.get(
            f"https://crt.sh/?q={domain_pattern}&output=json",
            timeout=30.0
        )
        if resp.status_code != 200:
            print(f"  [CT] crt.sh returned {resp.status_code}")
            return []
        
        entries = resp.json()
        domains = set()
        for entry in entries:
            cn = entry.get('common_name', '')
            if cn and '*' not in cn and cn.endswith('.lovable.app'):
                domains.add(f"https://{cn}")
        
        print(f"  [CT] Found {len(domains)} unique domains")
        return list(domains)[:limit]
    
    except Exception as e:
        print(f"  [CT] Error: {e}")
        return []


async def discover_from_launched(client: httpx.AsyncClient, limit: int = 30) -> list[str]:
    """Scrape launched.lovable.dev for showcased apps."""
    print("  [Launched] Checking launched.lovable.dev...")
    try:
        resp = await client.get("https://launched.lovable.dev", timeout=15.0)
        if resp.status_code != 200:
            print(f"  [Launched] returned {resp.status_code}")
            return []
        
        urls = set(re.findall(r'https://[\w-]+\.lovable\.app', resp.text))
        print(f"  [Launched] Found {len(urls)} app URLs")
        return list(urls)[:limit]
    
    except Exception as e:
        print(f"  [Launched] Error: {e}")
        return []


# ─── Scanning ─────────────────────────────────────────────────────────────────

EXPECTED_HEADERS = {
    'strict-transport-security': ('HSTS', 'medium'),
    'x-content-type-options': ('X-Content-Type-Options', 'low'),
    'x-frame-options': ('X-Frame-Options', 'low'),
    'content-security-policy': ('CSP', 'medium'),
    'referrer-policy': ('Referrer-Policy', 'low'),
    'permissions-policy': ('Permissions-Policy', 'low'),
}

SUPABASE_URL_RE = re.compile(r'https://([a-z0-9]+)\.supabase\.co')
SUPABASE_JWT_RE = re.compile(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}')
SERVICE_ROLE_RE = re.compile(r'service.?role', re.IGNORECASE)
FIREBASE_KEY_RE = re.compile(r'AIza[0-9A-Za-z_-]{35}')
STRIPE_SECRET_RE = re.compile(r'sk_live_[0-9a-zA-Z]{24,}')
OPENAI_KEY_RE = re.compile(r'sk-[a-zA-Z0-9]{32,}')
AWS_KEY_RE = re.compile(r'AKIA[0-9A-Z]{16}')

JS_BUNDLE_RE = re.compile(
    r'(?:src|href)=["\']?((?:/_next/static/|/static/js/|/assets/|/build/)[^"\'>\s]+\.js)',
    re.IGNORECASE
)


async def scan_app(client: httpx.AsyncClient, url: str) -> dict:
    """Scan a single app for security issues. Read-only, passive only."""
    result = {
        'url': url,
        'scanned_at': datetime.utcnow().isoformat() + 'Z',
        'status': None,
        'platform': None,
        'framework': None,
        'baas': None,
        'supabase_project': None,
        'supabase_tables_exposed': [],
        'findings': [],
        'missing_headers': [],
        'grade': None,
        'score': None,
        'error': None,
    }
    
    try:
        # Step 1: Fetch the page
        resp = await client.get(url, follow_redirects=True)
        result['status'] = resp.status_code
        html = resp.text
        headers = {k.lower(): v for k, v in resp.headers.items()}
        
        if resp.status_code != 200:
            result['error'] = f"HTTP {resp.status_code}"
            return result
        
        # Step 2: Platform detection
        if '.lovable.app' in url:
            result['platform'] = 'Lovable'
        elif '.replit.app' in url:
            result['platform'] = 'Replit'
        if 'x-vercel-id' in headers:
            result['platform'] = (result['platform'] or '') + ' → Vercel'
        elif headers.get('server', '').lower() == 'netlify':
            result['platform'] = (result['platform'] or '') + ' → Netlify'
        
        # Step 3: Framework detection
        if '/_next/' in html or '__NEXT_DATA__' in html:
            result['framework'] = 'Next.js'
        elif '/assets/' in html and ('vite' in html.lower() or 'react' in html.lower()):
            result['framework'] = 'React+Vite'
        elif '__NUXT__' in html:
            result['framework'] = 'Nuxt'
        
        # Step 4: Security headers
        for hdr_key, (hdr_name, severity) in EXPECTED_HEADERS.items():
            if hdr_key not in headers:
                result['missing_headers'].append(hdr_name)
                result['findings'].append({
                    'severity': severity,
                    'category': 'security_headers',
                    'title': f'Missing {hdr_name} header',
                })
        
        # Step 5: Fetch JS bundles
        all_content = html
        base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        bundle_paths = JS_BUNDLE_RE.findall(html)
        
        for path in bundle_paths[:MAX_JS_BUNDLES]:
            try:
                bundle_url = path if path.startswith('http') else base + path
                br = await client.get(bundle_url)
                if br.status_code == 200:
                    all_content += "\n" + br.text
            except:
                pass
        
        # Step 6: Supabase detection
        sb_match = SUPABASE_URL_RE.search(all_content)
        if sb_match:
            result['baas'] = 'Supabase'
            project_id = sb_match.group(1)
            result['supabase_project'] = project_id
            supabase_url = f"https://{project_id}.supabase.co"
            
            jwt_matches = SUPABASE_JWT_RE.findall(all_content)
            anon_key = None
            
            if jwt_matches:
                anon_key = jwt_matches[0]
                
                # Check for service_role key
                for jwt in jwt_matches:
                    idx = all_content.find(jwt)
                    context = all_content[max(0, idx-300):idx+len(jwt)+100]
                    if SERVICE_ROLE_RE.search(context):
                        result['findings'].append({
                            'severity': 'critical',
                            'category': 'exposed_secrets',
                            'title': 'Supabase service_role key possibly exposed in client JS',
                        })
                        break
                
                result['findings'].append({
                    'severity': 'info',
                    'category': 'baas_config',
                    'title': f'Supabase anon key found (project: {project_id})',
                })
                
                # Step 7: RLS probe
                try:
                    rls_resp = await client.get(
                        f"{supabase_url}/rest/v1/",
                        headers={
                            'apikey': anon_key,
                            'Authorization': f'Bearer {anon_key}',
                        },
                        timeout=10.0
                    )
                    
                    if rls_resp.status_code == 200:
                        try:
                            schema = rls_resp.json()
                            if isinstance(schema, dict):
                                paths = schema.get('paths', {})
                                tables = [p.strip('/') for p in paths.keys() if p != '/']
                                
                                if not tables and 'definitions' in schema:
                                    tables = list(schema['definitions'].keys())
                                
                                if tables:
                                    result['findings'].append({
                                        'severity': 'medium',
                                        'category': 'baas_config',
                                        'title': f'Supabase exposes {len(tables)} table(s): {", ".join(tables[:10])}',
                                    })
                                    
                                    # Step 8: Probe each table
                                    for table in tables[:10]:
                                        try:
                                            tbl_resp = await client.get(
                                                f"{supabase_url}/rest/v1/{table}?limit=1",
                                                headers={
                                                    'apikey': anon_key,
                                                    'Authorization': f'Bearer {anon_key}',
                                                },
                                                timeout=8.0
                                            )
                                            
                                            if tbl_resp.status_code == 200:
                                                data = tbl_resp.json()
                                                if isinstance(data, list) and len(data) > 0:
                                                    columns = list(data[0].keys()) if data else []
                                                    sensitive = [c for c in columns if any(s in c.lower() for s in 
                                                        ['email', 'phone', 'password', 'token', 'secret', 'address', 
                                                         'ssn', 'credit', 'ip', 'name', 'auth'])]
                                                    
                                                    sev = 'critical' if sensitive else 'high'
                                                    result['supabase_tables_exposed'].append({
                                                        'table': table,
                                                        'columns': columns,
                                                        'sensitive_columns': sensitive,
                                                    })
                                                    result['findings'].append({
                                                        'severity': sev,
                                                        'category': 'missing_rls',
                                                        'title': f'Table "{table}" returns data with anon key (RLS missing)',
                                                        'detail': f'Columns: {", ".join(columns[:8])}' + 
                                                                  (f' | SENSITIVE: {", ".join(sensitive)}' if sensitive else ''),
                                                    })
                                        except:
                                            pass
                        except json.JSONDecodeError:
                            pass
                except Exception as e:
                    pass
        
        # Step 9: Firebase detection
        if 'firebaseConfig' in all_content or FIREBASE_KEY_RE.search(all_content):
            result['baas'] = result.get('baas') or 'Firebase'
        
        # Step 10: Dangerous secrets
        if STRIPE_SECRET_RE.search(all_content):
            result['findings'].append({
                'severity': 'critical',
                'category': 'exposed_secrets',
                'title': 'Stripe SECRET key (sk_live_) exposed in client JS',
            })
        
        if AWS_KEY_RE.search(all_content):
            result['findings'].append({
                'severity': 'critical',
                'category': 'exposed_secrets',
                'title': 'AWS Access Key (AKIA...) exposed in client JS',
            })
        
        openai_matches = OPENAI_KEY_RE.findall(all_content)
        real_openai = [m for m in openai_matches if not m.startswith('sk-eyJ')]
        if real_openai:
            result['findings'].append({
                'severity': 'high',
                'category': 'exposed_secrets',
                'title': 'Possible OpenAI API key exposed in client JS',
            })
        
        # Step 11: .env check
        try:
            env_resp = await client.get(f"{base}/.env", timeout=5.0)
            if env_resp.status_code == 200 and '=' in env_resp.text and len(env_resp.text) < 50000:
                if any(kw in env_resp.text.lower() for kw in ['key', 'secret', 'password', 'token', 'database']):
                    result['findings'].append({
                        'severity': 'critical',
                        'category': 'exposed_secrets',
                        'title': '.env file publicly accessible',
                    })
        except:
            pass
        
        # Step 12: Grade
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for f in result['findings']:
            counts[f.get('severity', 'info')] = counts.get(f.get('severity', 'info'), 0) + 1
        
        score = 100 - (counts['critical'] * 25) - (counts['high'] * 15) - (counts['medium'] * 8) - (counts['low'] * 3)
        score = max(0, min(100, score))
        
        if score >= 90: result['grade'] = 'A'
        elif score >= 80: result['grade'] = 'B'
        elif score >= 70: result['grade'] = 'C'
        elif score >= 60: result['grade'] = 'D'
        else: result['grade'] = 'F'
        
        result['score'] = score
        result['severity_counts'] = counts
    
    except httpx.ConnectError as e:
        result['error'] = f"Connection error: {e}"
    except httpx.TimeoutException:
        result['error'] = "Timeout"
    except Exception as e:
        result['error'] = str(e)
    
    return result


async def main():
    print("=" * 70)
    print("  SSAP Quick Discovery Scanner")
    print("  Finding and scanning vibe-coded apps for security issues")
    print("=" * 70)
    print()
    
    async with httpx.AsyncClient(
        timeout=TIMEOUT,
        follow_redirects=True,
        headers={'User-Agent': 'SSAP-SecurityResearch/1.0 (todd@silverbackcto.com)'}
    ) as client:
        
        # Phase 1: Discovery
        print("[Phase 1] Discovering vibe-coded apps...")
        
        all_urls = set()
        
        for pattern in CT_LOG_DOMAINS:
            urls = await discover_from_ct_logs(client, pattern, limit=100)
            all_urls.update(urls)
        
        launched_urls = await discover_from_launched(client)
        all_urls.update(launched_urls)
        
        known_urls = [
            "https://escher.lovable.app",
            "https://clinicalai.lovable.app",
            "https://enterpriseform.lovable.app",
            "https://shipped.lovable.app",
            "https://february.lovable.app",
            "https://makelovable.lovable.app",
            "https://productlaunch.lovable.app",
            "https://lovablevibe.lovable.app",
        ]
        all_urls.update(known_urls)
        
        print(f"\n  Total unique URLs discovered: {len(all_urls)}")
        
        # Phase 2: Scan
        print(f"\n[Phase 2] Scanning apps (max {MAX_CONCURRENT} concurrent)...")
        
        urls = list(all_urls)
        results = []
        sem = asyncio.Semaphore(MAX_CONCURRENT)
        
        async def scan_with_sem(url):
            async with sem:
                return await scan_app(client, url)
        
        tasks = [scan_with_sem(url) for url in urls]
        for i, coro in enumerate(asyncio.as_completed(tasks)):
            result = await coro
            results.append(result)
            
            tables = len(result.get('supabase_tables_exposed', []))
            findings = len(result.get('findings', []))
            marker = " ⚠️  DATA EXPOSED" if tables > 0 else ""
            
            print(f"  [{i+1}/{len(urls)}] {result['url']}")
            print(f"         Grade: {result.get('grade', '?')} | Findings: {findings} | BaaS: {result.get('baas', '-')}{marker}")
        
        # Phase 3: Report
        scanned = [r for r in results if r.get('status') == 200]
        with_findings = [r for r in scanned if len(r.get('findings', [])) > 0]
        with_exposed = [r for r in scanned if len(r.get('supabase_tables_exposed', [])) > 0]
        
        print(f"\n{'=' * 70}")
        print(f"  RESULTS: {len(scanned)} scanned | {len(with_findings)} with findings | {len(with_exposed)} with exposed tables")
        print(f"{'=' * 70}")
        
        worst = sorted(scanned, key=lambda r: r.get('score', 100))[:10]
        if worst:
            print(f"\n  Top 10 Most Vulnerable:")
            for r in worst:
                sc = r.get('severity_counts', {})
                tables = len(r.get('supabase_tables_exposed', []))
                print(f"    {r.get('grade', '?')} ({r.get('score', '?'):>3}) {r['url'][:55]}"
                      f"  C:{sc.get('critical',0)} H:{sc.get('high',0)} M:{sc.get('medium',0)}"
                      f"{f' | {tables} exposed tables' if tables else ''}")
        
        with open(OUTPUT_FILE, 'w') as f:
            json.dump({
                'scan_date': datetime.utcnow().isoformat() + 'Z',
                'total_discovered': len(all_urls),
                'total_scanned': len(scanned),
                'results': results,
            }, f, indent=2, default=str)
        
        print(f"\n  Full results: {OUTPUT_FILE}")


if __name__ == '__main__':
    asyncio.run(main())
