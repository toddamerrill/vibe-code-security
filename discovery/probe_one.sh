#!/bin/bash
# ============================================================================
# SSAP Manual Probe: Test a single lovable.app for Supabase RLS exposure
#
# Usage: ./probe_one.sh <domain>
# Example: ./probe_one.sh myapp.lovable.app
#
# What this does (all read-only GET requests):
#   1. Fetches the homepage HTML
#   2. Finds JS bundle URLs in the HTML
#   3. Downloads JS bundles and greps for Supabase URL + anon key
#   4. If found, lists tables via /rest/v1/
#   5. Probes each table with limit=1 to check for missing RLS
# ============================================================================

if [ -z "${1:-}" ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 myapp.lovable.app"
    exit 1
fi

DOMAIN="$1"
URL="https://$DOMAIN"
echo "Probing: $URL"
echo ""

# Step 1: Fetch homepage
echo "[1/5] Fetching homepage..."
HOMEPAGE=$(curl -sL "$URL" 2>/dev/null)
if [ -z "$HOMEPAGE" ]; then
    echo "  ERROR: Could not fetch $URL"
    exit 1
fi
echo "  ✅ Got homepage ($(echo "$HOMEPAGE" | wc -c | tr -d ' ') bytes)"

# Step 2: Find JS bundles
echo "[2/5] Finding JS bundles..."
JS_PATHS=$(echo "$HOMEPAGE" | grep -oE '(/assets/[^"'"'"'>\s]+\.js)' | head -5)
if [ -z "$JS_PATHS" ]; then
    JS_PATHS=$(echo "$HOMEPAGE" | grep -oE '(/_next/static/[^"'"'"'>\s]+\.js)' | head -5)
fi
JS_COUNT=$(echo "$JS_PATHS" | grep -c '\.js' || echo 0)
echo "  Found $JS_COUNT JS bundle(s)"

# Step 3: Download and search for Supabase
echo "[3/5] Searching for Supabase credentials..."
ALL_JS=""
for path in $JS_PATHS; do
    BUNDLE=$(curl -sL "${URL}${path}" 2>/dev/null)
    ALL_JS="$ALL_JS\n$BUNDLE"
done

# Search in both homepage and JS bundles
ALL_CONTENT="$HOMEPAGE\n$ALL_JS"

SB_URL=$(echo -e "$ALL_CONTENT" | grep -oE 'https://[a-z0-9]+\.supabase\.co' | head -1)
if [ -z "$SB_URL" ]; then
    echo "  No Supabase URL found. App may not use Supabase."
    echo ""
    echo "Checking security headers..."
    curl -sI "$URL" 2>/dev/null | grep -iE '(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy)' || echo "  ⚠️  No security headers found!"
    exit 0
fi

SB_PROJECT=$(echo "$SB_URL" | sed 's|https://||' | sed 's|\.supabase\.co||')
echo "  🔍 Supabase project: $SB_PROJECT"
echo "  🔍 Supabase URL: $SB_URL"

ANON_KEY=$(echo -e "$ALL_CONTENT" | grep -oE 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}' | head -1)
if [ -z "$ANON_KEY" ]; then
    echo "  No anon key found in JS bundles."
    exit 0
fi
echo "  🔑 Anon key found: ${ANON_KEY:0:30}..."

# Check for service_role
SVC_ROLE=$(echo -e "$ALL_CONTENT" | grep -i 'service.role' | head -1)
if [ -n "$SVC_ROLE" ]; then
    echo "  🔴🔴🔴 CRITICAL: service_role reference found near JWT! 🔴🔴🔴"
fi

# Step 4: List tables
echo "[4/5] Listing Supabase tables via REST API..."
SCHEMA=$(curl -s "$SB_URL/rest/v1/" \
    -H "apikey: $ANON_KEY" \
    -H "Authorization: Bearer $ANON_KEY" \
    -H "Content-Type: application/json" 2>/dev/null)

TABLES=$(echo "$SCHEMA" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    paths = d.get('paths', {})
    for p in sorted(paths.keys()):
        if p != '/':
            print(p.strip('/'))
except:
    # Try definitions instead
    try:
        for t in d.get('definitions', {}).keys():
            print(t)
    except:
        pass
" 2>/dev/null)

TBL_COUNT=$(echo "$TABLES" | grep -c . || echo 0)
if [ "$TBL_COUNT" -eq 0 ]; then
    echo "  No tables discovered (API may be locked down)."
    exit 0
fi
echo "  Found $TBL_COUNT table(s): $(echo $TABLES | tr '\n' ', ')"

# Step 5: Probe each table
echo "[5/5] Testing each table for missing RLS..."
echo ""

EXPOSED=0
for TABLE in $TABLES; do
    RESULT=$(curl -s "$SB_URL/rest/v1/$TABLE?limit=1&select=*" \
        -H "apikey: $ANON_KEY" \
        -H "Authorization: Bearer $ANON_KEY" \
        -H "Content-Type: application/json" 2>/dev/null)

    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$SB_URL/rest/v1/$TABLE?limit=1" \
        -H "apikey: $ANON_KEY" \
        -H "Authorization: Bearer $ANON_KEY" 2>/dev/null)

    if [ "$HTTP_CODE" = "200" ]; then
        # Check if we got actual data
        ROW_COUNT=$(echo "$RESULT" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    if isinstance(d, list):
        print(len(d))
    else:
        print(0)
except:
    print(0)
" 2>/dev/null)

        if [ "$ROW_COUNT" -gt 0 ]; then
            COLUMNS=$(echo "$RESULT" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    if d and isinstance(d, list):
        print(', '.join(list(d[0].keys())[:8]))
except:
    pass
" 2>/dev/null)

            SENSITIVE=$(echo "$RESULT" | python3 -c "
import json, sys
try:
    d = json.load(sys.stdin)
    if d and isinstance(d, list):
        sens = [k for k in d[0].keys() if any(s in k.lower() for s in ['email','phone','password','token','secret','address','name','ip','auth','ssn','credit'])]
        if sens: print('🚨 SENSITIVE: ' + ', '.join(sens))
except:
    pass
" 2>/dev/null)

            if [ -n "$SENSITIVE" ]; then
                echo "  🔴 $TABLE: DATA EXPOSED (RLS MISSING) - Columns: $COLUMNS"
                echo "     $SENSITIVE"
            else
                echo "  🟠 $TABLE: DATA EXPOSED (RLS MISSING) - Columns: $COLUMNS"
            fi
            EXPOSED=$((EXPOSED + 1))
        else
            echo "  ✅ $TABLE: empty response (RLS working or empty table)"
        fi
    elif [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "403" ]; then
        echo "  ✅ $TABLE: access denied (RLS active)"
    else
        echo "  ❓ $TABLE: HTTP $HTTP_CODE"
    fi
done

echo ""
echo "================================================================"
if [ "$EXPOSED" -gt 0 ]; then
    echo "  🔴 RESULT: $EXPOSED of $TBL_COUNT tables EXPOSED (insecure!)"
    echo "  This app needs SecureStack remediation."
else
    echo "  ✅ RESULT: All $TBL_COUNT tables appear protected."
fi
echo "================================================================"

# Also check security headers
echo ""
echo "Security Headers Check:"
curl -sI "$URL" 2>/dev/null | while read -r line; do
    lower=$(echo "$line" | tr '[:upper:]' '[:lower:]')
    case "$lower" in
        strict-transport-security:*) echo "  ✅ HSTS: $line" ;;
        content-security-policy:*) echo "  ✅ CSP: (present)" ;;
        x-frame-options:*) echo "  ✅ X-Frame-Options: $line" ;;
        x-content-type-options:*) echo "  ✅ X-Content-Type-Options: $line" ;;
        referrer-policy:*) echo "  ✅ Referrer-Policy: $line" ;;
        permissions-policy:*) echo "  ✅ Permissions-Policy: $line" ;;
    esac
done

for HDR in "strict-transport-security" "content-security-policy" "x-frame-options" "x-content-type-options" "referrer-policy" "permissions-policy"; do
    if ! curl -sI "$URL" 2>/dev/null | grep -qi "$HDR"; then
        echo "  ⚠️  Missing: $HDR"
    fi
done
