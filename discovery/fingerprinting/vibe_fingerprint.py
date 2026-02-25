"""
Vibe-Code Fingerprinting Engine
================================

For apps on shared hosting platforms (Vercel, Netlify, custom domains),
we need heuristics to identify whether they were built with vibe-coding tools.

Scoring signals (max 100 points):
- Supabase client in JS bundle: +30
- Anon key pattern in JS bundle: +20
- Lovable/Bolt meta tag or comment: +40
- React + Vite + Tailwind + shadcn: +15
- GitHub repo linked to vibe-coding tool: +40
- Recently created + Supabase: +10
- Pure SPA (no SSR): +5
- Default AI-generated favicon/styling: +20

Classification:
- Score >= 50: Confirmed vibe-coded
- Score 30-49: Probable (included with flag)
- Score < 30: Excluded
"""

import asyncio
import json
import logging
import re
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


# -----------------------------------------------------------------
# Signal Detectors
# -----------------------------------------------------------------

# Supabase detection patterns
SUPABASE_URL_PATTERN = re.compile(
    r'https://[a-z0-9]+\.supabase\.co',
    re.IGNORECASE
)

SUPABASE_ANON_KEY_PATTERN = re.compile(
    r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
)

# Firebase detection patterns
FIREBASE_CONFIG_PATTERN = re.compile(
    r'firebaseConfig\s*=\s*\{',
    re.IGNORECASE
)

FIREBASE_URL_PATTERN = re.compile(
    r'https://[a-z0-9-]+\.firebaseio\.com|https://[a-z0-9-]+\.firebaseapp\.com',
    re.IGNORECASE
)

# Convex detection
CONVEX_PATTERN = re.compile(r'convex\.cloud|convex\.dev', re.IGNORECASE)

# Platform-specific signatures
LOVABLE_SIGNATURES = [
    re.compile(r'lovable', re.IGNORECASE),
    re.compile(r'gptengineer', re.IGNORECASE),  # Lovable's original name
    re.compile(r'built\s+with\s+lovable', re.IGNORECASE),
]

BOLT_SIGNATURES = [
    re.compile(r'bolt\.new', re.IGNORECASE),
    re.compile(r'stackblitz', re.IGNORECASE),
    re.compile(r'built\s+with\s+bolt', re.IGNORECASE),
]

REPLIT_SIGNATURES = [
    re.compile(r'replit', re.IGNORECASE),
    re.compile(r'repl\.co', re.IGNORECASE),
]

# Framework detection
REACT_PATTERN = re.compile(r'react|__NEXT_DATA__|_next/static|createRoot', re.IGNORECASE)
VITE_PATTERN = re.compile(r'/@vite/|vite/modulepreload', re.IGNORECASE)
TAILWIND_PATTERN = re.compile(r'tailwindcss|tw-[a-z]', re.IGNORECASE)
SHADCN_PATTERN = re.compile(r'@radix-ui|lucide-react|class-variance-authority', re.IGNORECASE)

# Secret patterns (for later scanning, detected during fingerprinting)
SECRET_PATTERNS = {
    "stripe_secret": re.compile(r'sk_live_[a-zA-Z0-9]{20,}'),
    "stripe_publishable": re.compile(r'pk_live_[a-zA-Z0-9]{20,}'),
    "openai_key": re.compile(r'sk-[a-zA-Z0-9]{20,}'),
    "anthropic_key": re.compile(r'sk-ant-[a-zA-Z0-9]{20,}'),
    "aws_access_key": re.compile(r'AKIA[A-Z0-9]{16}'),
    "google_api_key": re.compile(r'AIza[A-Za-z0-9_-]{35}'),
    "service_role_key": re.compile(r'service_role'),
}

# AI-generated styling heuristics (from the Vibe Chrome extension research)
AI_STYLING_PATTERNS = [
    re.compile(r'from-purple|to-purple|bg-gradient|purple-\d00', re.IGNORECASE),  # Purple gradients
    re.compile(r'✨|🚀|💡|⚡|🎉', re.IGNORECASE),  # Excessive emoji
]


async def fingerprint_app(app) -> 'DiscoveredApp':
    """
    Fetch an app's homepage and JavaScript bundles, then score it
    for vibe-coding signals.
    
    Returns the app with updated fingerprinting fields.
    """
    score = 0
    detected_signals: list[str] = []
    
    try:
        async with httpx.AsyncClient(
            timeout=20.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SSAP-Research/1.0)"},
        ) as client:
            
            # Fetch homepage HTML
            resp = await client.get(f"https://{app.domain}")
            
            if resp.status_code >= 400:
                app.is_live = False
                return app
            
            html = resp.text
            
            # --- Signal 1: Platform-specific signatures in HTML ---
            for pattern in LOVABLE_SIGNATURES:
                if pattern.search(html):
                    score += 40
                    app.platform = "lovable"
                    detected_signals.append("lovable_signature")
                    break
            
            for pattern in BOLT_SIGNATURES:
                if pattern.search(html):
                    score += 40
                    app.platform = "bolt"
                    detected_signals.append("bolt_signature")
                    break
            
            for pattern in REPLIT_SIGNATURES:
                if pattern.search(html):
                    score += 40
                    app.platform = "replit"
                    detected_signals.append("replit_signature")
                    break
            
            # --- Signal 2: Supabase client detection ---
            supabase_match = SUPABASE_URL_PATTERN.search(html)
            if supabase_match:
                score += 30
                app.detected_baas = "supabase"
                app.supabase_url = supabase_match.group(0)
                detected_signals.append("supabase_client")
            
            # --- Signal 3: Supabase anon key ---
            anon_match = SUPABASE_ANON_KEY_PATTERN.search(html)
            if anon_match and supabase_match:
                score += 20
                app.supabase_anon_key = anon_match.group(0)
                detected_signals.append("supabase_anon_key")
            
            # --- Signal 4: Firebase detection ---
            if FIREBASE_CONFIG_PATTERN.search(html) or FIREBASE_URL_PATTERN.search(html):
                score += 25
                app.detected_baas = app.detected_baas or "firebase"
                detected_signals.append("firebase_client")
            
            # --- Signal 5: Convex detection ---
            if CONVEX_PATTERN.search(html):
                score += 20
                app.detected_baas = app.detected_baas or "convex"
                detected_signals.append("convex_client")
            
            # --- Signal 6: React + Vite + Tailwind + shadcn stack ---
            stack_score = 0
            if REACT_PATTERN.search(html):
                stack_score += 4
            if VITE_PATTERN.search(html):
                stack_score += 4
            if TAILWIND_PATTERN.search(html):
                stack_score += 4
            if SHADCN_PATTERN.search(html):
                stack_score += 3
            
            if stack_score >= 8:  # At least React + Vite + Tailwind
                score += 15
                detected_signals.append("vibe_stack")
            
            # --- Signal 7: AI-generated styling ---
            ai_style_hits = sum(1 for p in AI_STYLING_PATTERNS if p.search(html))
            if ai_style_hits >= 2:
                score += 10
                detected_signals.append("ai_styling")
            
            # --- Signal 8: Pure SPA (no SSR) ---
            if '<div id="root"></div>' in html or '<div id="app"></div>' in html:
                if len(html) < 5000:  # Very minimal HTML = SPA shell
                    score += 5
                    detected_signals.append("pure_spa")
            
            # --- Detect framework ---
            if '__NEXT_DATA__' in html or '_next/static' in html:
                app.detected_framework = "next"
            elif VITE_PATTERN.search(html):
                app.detected_framework = "react-vite"
            elif 'svelte' in html.lower():
                app.detected_framework = "svelte"
            elif 'vue' in html.lower():
                app.detected_framework = "vue"
            else:
                app.detected_framework = "react"  # Default for vibe-coded
            
            # --- JS Bundle deep scan (if needed for borderline scores) ---
            if 30 <= score < 50:
                # Fetch JS bundles for deeper analysis
                bundle_score = await _scan_js_bundles(client, app.domain, html)
                score += bundle_score
                if bundle_score > 0:
                    detected_signals.append("js_bundle_signals")
    
    except Exception as e:
        logger.debug(f"Fingerprinting failed for {app.domain}: {e}")
    
    # Cap score at 100
    app.vibe_confidence_score = min(score, 100)
    app.raw_metadata["fingerprint_signals"] = detected_signals
    app.raw_metadata["fingerprint_score_breakdown"] = score
    
    # Detect custom domain usage
    platform_domains = [".lovable.app", ".replit.app", ".repl.co", ".vercel.app", ".netlify.app"]
    app.has_custom_domain = not any(app.domain.endswith(d) for d in platform_domains)
    
    return app


async def _scan_js_bundles(client: httpx.AsyncClient, domain: str, html: str) -> int:
    """
    Download and scan JavaScript bundles for additional vibe-coding signals.
    Only called for borderline-scored apps where the HTML alone isn't definitive.
    
    Returns additional score points (0-20).
    """
    additional_score = 0
    
    # Extract JS bundle URLs from HTML
    js_urls = re.findall(r'src="(/[^"]*\.js)"', html)
    js_urls += re.findall(r'src="(https?://[^"]*\.js)"', html)
    
    for js_url in js_urls[:5]:  # Limit to first 5 bundles
        try:
            if js_url.startswith("/"):
                js_url = f"https://{domain}{js_url}"
            
            resp = await client.get(js_url, timeout=15.0)
            if resp.status_code == 200:
                content = resp.text
                
                # Check for Supabase in bundles (might not be in initial HTML)
                if SUPABASE_URL_PATTERN.search(content):
                    additional_score += 15
                
                # Check for platform signatures in bundles
                for pattern in LOVABLE_SIGNATURES + BOLT_SIGNATURES:
                    if pattern.search(content):
                        additional_score += 10
                        break
                
                if additional_score > 0:
                    break  # Found enough signals
        
        except Exception:
            continue
    
    return min(additional_score, 20)
