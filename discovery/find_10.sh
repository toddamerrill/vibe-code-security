#!/bin/bash
# ============================================================================
# SSAP Quick-Find: Discover 10 Insecure Vibe-Coded Apps
# Run from your Mac: chmod +x find_10.sh && ./find_10.sh
#
# Three-phase approach:
# 1. Pull app URLs from Certificate Transparency logs
# 2. Extract Supabase URLs + anon keys from their JS bundles
# 3. Test each Supabase table for missing RLS (read-only)
#
# All operations are passive GET requests (same as a web browser).
# ============================================================================

set -euo pipefail

RESULTS_DIR="$HOME/Projects/SSAP-Security-Study/scan_results"
mkdir -p "$RESULTS_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_FILE="$RESULTS_DIR/quick_scan_$TIMESTAMP.json"
TARGETS_FILE="$RESULTS_DIR/targets_$TIMESTAMP.txt"
INSECURE_FILE="$RESULTS_DIR/insecure_apps_$TIMESTAMP.json"

echo "========================================"
echo "  SSAP Quick-Find: Insecure Vibe Apps"
echo "  $(date)"
echo "========================================"

# ─── Phase 1: Discovery via Certificate Transparency ─────────────────────────

echo ""
echo "[Phase 1] Discovering lovable.app subdomains from CT logs..."
echo "  Querying crt.sh (may take 15-30 seconds)..."

# Pull from CT logs - finds all SSL certs ever issued for *.lovable.app
CT_RESULTS=$(curl -s "https://crt.sh/?q=%.lovable.app&output=json" 2>/dev/null || echo "[]")

# Extract unique subdomains
echo "$CT_RESULTS" | python3 -c "
import json, sys
try:
    entries = json.load(sys.stdin)
    domains = set()
    for e in entries:
        cn = e.get('common_name', '')
        if cn and '*' not in cn and cn.endswith('.lovable.app'):
            domains.add(cn)
    for d in sorted(domains):
        print(d)
except:
    pass
" > "$TARGETS_FILE"

CT_COUNT=$(wc -l < "$TARGETS_FILE" | tr -d ' ')
echo "  Found $CT_COUNT unique lovable.app subdomains"

# Also add known apps from madewithlovable.com directory
cat >> "$TARGETS_FILE" << 'KNOWN_APPS'
poliread.lovable.app
viewdesk.lovable.app
chatit-cloud.lovable.app
my-own-cfo.lovable.app
renameflow.lovable.app
happierinbox.lovable.app
modfii.lovable.app
archivist.lovable.app
fix-my-vibe.lovable.app
escher.lovable.app
clinicalai.lovable.app
enterpriseform.lovable.app
productlaunch.lovable.app
lovablevibe.lovable.app
february.lovable.app
KNOWN_APPS

# Deduplicate
sort -u "$TARGETS_FILE" -o "$TARGETS_FILE"
TOTAL=$(wc -l < "$TARGETS_FILE" | tr -d ' ')
echo "  Total unique targets (after adding known apps): $TOTAL"

# ─── Phase 2: Scan for Supabase + Security Issues ────────────────────────────

echo ""
echo "[Phase 2] Scanning first 50 targets for Supabase keys + security issues..."
echo "  (This runs ~50 parallel curl requests, takes ~30 seconds)"

# Take first 50 targets
head -50 "$TARGETS_FILE" > /tmp/ssap_scan_targets.txt

python3 << 'PYTHON_SCANNER'
import asyncio
import httpx
import re
import json
import sys
from datetime import datetime

TARGETS_FILE = "/tmp/ssap_scan_targets.txt"

with open(TARGETS_FILE) as f:
    targets = [f"https://{line.strip()}" for line in f if line.strip()]

SUPABASE_URL_RE = re.compile(r'https://([a-z0-9]+)\.supabase\.co')
JWT_RE = re.compile(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}')
SERVICE_ROLE_RE = re.compile(r'service.?role', re.IGNORECASE)
JS_RE = re.compile(r'(?:src|href)=["\']?((?:/_next/static/|/static/js/|/assets/|/build/)[^"\'>\s]+\.js)', re.I)

SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-content-type-options',
    'x-frame-options',
    'referrer-policy',
    'permissions-policy',
]

results = []
insecure = []

async def scan(client, url):
    r = {
        'url': url, 'status': None, 'platform': 'Lovable',
        'supabase_project': None, 'anon_key': None,
        'tables_exposed': [], 'missing_headers': [],
        'findings': [], 'grade': None, 'error': None,
    }
    try:
        resp = await client.get(url, follow_redirects=True, timeout=15)
        r['status'] = resp.status_code
        if resp.status_code != 200:
            r['error'] = f"HTTP {resp.status_code}"
            return r

        html = resp.text
        headers = {k.lower(): v for k, v in resp.headers.items()}
        base = url.rstrip('/')

        # Security headers
        for h in SECURITY_HEADERS:
            if h not in headers:
                r['missing_headers'].append(h)

        # Fetch JS bundles
        all_text = html
        for path in JS_RE.findall(html)[:5]:
            try:
                burl = path if path.startswith('http') else base + path
                br = await client.get(burl, timeout=10)
                if br.status_code == 200:
                    all_text += "\n" + br.text
            except:
                pass

        # Find Supabase
        sb = SUPABASE_URL_RE.search(all_text)
        if sb:
            r['supabase_project'] = sb.group(1)
            sb_url = f"https://{sb.group(1)}.supabase.co"

            jwts = JWT_RE.findall(all_text)
            if jwts:
                r['anon_key'] = jwts[0][:20] + '...'  # Truncate for safety

                # Check for service_role
                for jwt in jwts:
                    idx = all_text.find(jwt)
                    ctx = all_text[max(0,idx-300):idx+100]
                    if SERVICE_ROLE_RE.search(ctx):
                        r['findings'].append('CRITICAL: service_role key in client JS')

                # Probe RLS
                try:
                    api_resp = await client.get(
                        f"{sb_url}/rest/v1/",
                        headers={'apikey': jwts[0], 'Authorization': f'Bearer {jwts[0]}'},
                        timeout=10
                    )
                    if api_resp.status_code == 200:
                        schema = api_resp.json()
                        if isinstance(schema, dict):
                            paths = schema.get('paths', {})
                            tables = [p.strip('/') for p in paths.keys() if p not in ['/', '']]
                            if not tables and 'definitions' in schema:
                                tables = list(schema['definitions'].keys())

                            for table in tables[:15]:
                                try:
                                    tr = await client.get(
                                        f"{sb_url}/rest/v1/{table}?limit=1&select=*",
                                        headers={'apikey': jwts[0], 'Authorization': f'Bearer {jwts[0]}'},
                                        timeout=8
                                    )
                                    if tr.status_code == 200:
                                        data = tr.json()
                                        if isinstance(data, list) and len(data) > 0:
                                            cols = list(data[0].keys())
                                            sensitive = [c for c in cols if any(s in c.lower()
                                                for s in ['email','phone','password','token','secret','address','name','ip','auth'])]
                                            r['tables_exposed'].append({
                                                'table': table,
                                                'columns': cols,
                                                'sensitive': sensitive,
                                            })
                                            sev = 'CRITICAL' if sensitive else 'HIGH'
                                            r['findings'].append(f'{sev}: Table "{table}" returns data (RLS missing)')
                                except:
                                    pass
                except:
                    pass

        # Grade
        crit = sum(1 for f in r['findings'] if 'CRITICAL' in f)
        high = sum(1 for f in r['findings'] if 'HIGH' in f)
        missing_h = len(r['missing_headers'])
        score = 100 - crit*25 - high*15 - missing_h*3
        score = max(0, min(100, score))
        r['grade'] = 'A' if score >= 90 else 'B' if score >= 80 else 'C' if score >= 70 else 'D' if score >= 60 else 'F'
        r['score'] = score

    except Exception as e:
        r['error'] = str(e)[:100]
    return r

async def main():
    async with httpx.AsyncClient(
        follow_redirects=True,
        headers={'User-Agent': 'SSAP-SecurityResearch/1.0'}
    ) as client:
        sem = asyncio.Semaphore(10)
        async def bounded(url):
            async with sem:
                return await scan(client, url)

        tasks = [bounded(u) for u in targets]
        done = 0
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
            done += 1

            tables = len(r.get('tables_exposed', []))
            marker = " ⚠️  DATA EXPOSED" if tables > 0 else ""
            sb = f"SB:{r['supabase_project']}" if r.get('supabase_project') else "no-supabase"
            grade = r.get('grade', '?')
            findings = len(r.get('findings', []))

            print(f"  [{done}/{len(targets)}] {grade} {r['url'][:55]}  {sb}  findings:{findings}{marker}")

            if tables > 0 or any('CRITICAL' in f for f in r.get('findings', [])):
                insecure.append(r)

    return results, insecure

r, i = asyncio.run(main())

# Summary
scanned = [x for x in r if x.get('status') == 200]
with_sb = [x for x in scanned if x.get('supabase_project')]
with_tables = [x for x in scanned if x.get('tables_exposed')]
with_critical = [x for x in scanned if any('CRITICAL' in f for f in x.get('findings', []))]

print(f"\n{'='*60}")
print(f"  SCAN COMPLETE")
print(f"{'='*60}")
print(f"  Scanned successfully: {len(scanned)}/{len(r)}")
print(f"  Using Supabase:       {len(with_sb)}")
print(f"  EXPOSED TABLES:       {len(with_tables)}")
print(f"  CRITICAL findings:    {len(with_critical)}")
print(f"  Total insecure:       {len(i)}")

if i:
    print(f"\n  TOP INSECURE APPS:")
    for app in sorted(i, key=lambda x: x.get('score', 100))[:10]:
        tables = len(app.get('tables_exposed', []))
        print(f"    {app.get('grade','?')} ({app.get('score','?'):>3}) {app['url'][:50]}  tables_exposed:{tables}")
        for f in app.get('findings', []):
            print(f"          → {f}")
        for t in app.get('tables_exposed', []):
            sens = t.get('sensitive', [])
            print(f"          📋 {t['table']}: {', '.join(t['columns'][:6])}")
            if sens:
                print(f"             🚨 SENSITIVE: {', '.join(sens)}")

# Save JSON
import os
results_dir = os.environ.get('RESULTS_DIR', '.')
with open(os.path.join(results_dir, f'quick_scan_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'), 'w') as f:
    json.dump({'scan_date': datetime.utcnow().isoformat(), 'results': r, 'insecure': i}, f, indent=2, default=str)

with open(os.path.join(results_dir, f'insecure_apps_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.json'), 'w') as f:
    json.dump(i, f, indent=2, default=str)

print(f"\n  Results saved to: {results_dir}/")
PYTHON_SCANNER

echo ""
echo "Done! Check $RESULTS_DIR/ for full results."
