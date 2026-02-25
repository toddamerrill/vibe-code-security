"""
Secret Scanner — JavaScript Bundle Analysis
=============================================

Downloads and analyzes JavaScript bundles served by vibe-coded apps to detect:
1. Supabase service_role keys (CRITICAL — full database bypass)
2. Stripe secret keys (CRITICAL — payment compromise)
3. OpenAI/Anthropic API keys (HIGH — financial exposure)
4. AWS credentials (CRITICAL — cloud infrastructure)
5. Firebase admin SDK keys (CRITICAL)
6. Google Maps / other API keys (MEDIUM)
7. JWT secrets / signing keys (CRITICAL)
8. Database connection strings (CRITICAL)
9. .env file contents (CRITICAL)
10. Generic high-entropy secrets (MEDIUM)

Uses TruffleHog-style regex patterns plus custom BaaS-specific patterns.
Results are classified by severity and type for grading.

ETHICAL NOTE: We do NOT test or use any discovered keys.
We only record: (1) key type found, (2) severity, (3) whether it appears active
(based on format validation, NOT actual API calls with the key).
"""

import asyncio
import hashlib
import logging
import re
from dataclasses import dataclass, field
from enum import Enum

import httpx

logger = logging.getLogger(__name__)


class SecretSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class DetectedSecret:
    """A secret found in a JS bundle. The actual value is NEVER stored."""
    secret_type: str
    severity: SecretSeverity
    location: str               # e.g. "main.abc123.js" — NOT the full URL
    key_prefix: str             # First 8 chars only, for dedup (e.g. "sk_live_")
    key_hash: str               # SHA256 hash of full key for dedup without storing
    appears_active: bool        # Format looks valid (not test/example key)
    context: str                # e.g. "found in Supabase client initialization"


@dataclass
class SecretScanResult:
    """Complete secret scan result for one app."""
    app_domain: str
    bundles_scanned: int = 0
    total_bundle_size_kb: int = 0
    secrets_found: list[DetectedSecret] = field(default_factory=list)
    supabase_url: str | None = None
    supabase_anon_key: str | None = None      # This is public by design
    supabase_service_role: bool = False        # True = CRITICAL finding
    has_critical_secrets: bool = False
    has_high_secrets: bool = False


# -----------------------------------------------------------------
# Secret Detection Patterns
# -----------------------------------------------------------------

SECRET_PATTERNS: list[tuple[str, SecretSeverity, re.Pattern, str]] = [
    # BaaS — Supabase
    ("supabase_service_role", SecretSeverity.CRITICAL,
     re.compile(r'service[_-]?role["\s:=]+["\']?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)'),
     "Supabase service_role key bypasses all RLS policies"),
    
    # Payment
    ("stripe_secret_key", SecretSeverity.CRITICAL,
     re.compile(r'(sk_live_[a-zA-Z0-9]{24,})'),
     "Stripe live secret key — can create charges, refunds, read customer data"),
    
    ("stripe_restricted_key", SecretSeverity.HIGH,
     re.compile(r'(rk_live_[a-zA-Z0-9]{24,})'),
     "Stripe restricted key — limited access to Stripe API"),
    
    # AI/ML API Keys
    ("openai_key", SecretSeverity.HIGH,
     re.compile(r'(sk-[a-zA-Z0-9]{20,}T3BlbkFJ[a-zA-Z0-9]{20,})'),
     "OpenAI API key — financial exposure, usage charges"),
    
    ("openai_project_key", SecretSeverity.HIGH,
     re.compile(r'(sk-proj-[a-zA-Z0-9_-]{40,})'),
     "OpenAI project-scoped API key"),
    
    ("anthropic_key", SecretSeverity.HIGH,
     re.compile(r'(sk-ant-[a-zA-Z0-9_-]{40,})'),
     "Anthropic API key — financial exposure"),
    
    # Cloud Infrastructure
    ("aws_access_key", SecretSeverity.CRITICAL,
     re.compile(r'(AKIA[A-Z0-9]{16})'),
     "AWS access key ID — cloud infrastructure access"),
    
    ("aws_secret_key", SecretSeverity.CRITICAL,
     re.compile(r'aws[_-]?secret[_-]?access[_-]?key["\s:=]+["\']?([a-zA-Z0-9/+=]{40})'),
     "AWS secret access key"),
    
    ("gcp_service_account", SecretSeverity.CRITICAL,
     re.compile(r'"type"\s*:\s*"service_account"'),
     "GCP service account JSON key"),
    
    # Firebase
    ("firebase_admin_key", SecretSeverity.CRITICAL,
     re.compile(r'(AIza[A-Za-z0-9_-]{35})'),  # Note: Firebase web API keys are public
     "Google API key (may include Firebase admin access)"),
    
    # Database
    ("postgres_connection", SecretSeverity.CRITICAL,
     re.compile(r'(postgres(?:ql)?://[a-zA-Z0-9:@._-]+/[a-zA-Z0-9_-]+)'),
     "PostgreSQL connection string with credentials"),
    
    ("mongodb_connection", SecretSeverity.CRITICAL,
     re.compile(r'(mongodb(?:\+srv)?://[a-zA-Z0-9:@._-]+/[a-zA-Z0-9_-]+)'),
     "MongoDB connection string"),
    
    # Auth/Session
    ("jwt_secret", SecretSeverity.HIGH,
     re.compile(r'jwt[_-]?secret["\s:=]+["\']?([a-zA-Z0-9_-]{20,})'),
     "JWT signing secret — enables token forgery"),
    
    ("session_secret", SecretSeverity.HIGH,
     re.compile(r'session[_-]?secret["\s:=]+["\']?([a-zA-Z0-9_-]{20,})'),
     "Session secret — enables session hijacking"),
    
    # Third-party services
    ("twilio_auth_token", SecretSeverity.HIGH,
     re.compile(r'(AC[a-f0-9]{32})'),
     "Twilio Account SID"),
    
    ("sendgrid_key", SecretSeverity.HIGH,
     re.compile(r'(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})'),
     "SendGrid API key"),
    
    ("mailgun_key", SecretSeverity.MEDIUM,
     re.compile(r'(key-[a-f0-9]{32})'),
     "Mailgun API key"),
    
    ("github_pat", SecretSeverity.HIGH,
     re.compile(r'(ghp_[a-zA-Z0-9]{36})'),
     "GitHub personal access token"),
    
    ("github_oauth", SecretSeverity.HIGH,
     re.compile(r'(gho_[a-zA-Z0-9]{36})'),
     "GitHub OAuth access token"),
    
    # Google Maps (lower severity — financial but limited impact)
    ("google_maps_key", SecretSeverity.MEDIUM,
     re.compile(r'maps["\s:=]+["\']?(AIza[A-Za-z0-9_-]{35})'),
     "Google Maps API key — rate abuse risk"),
]

# Patterns that indicate a key is a test/example (NOT a real secret)
FALSE_POSITIVE_PATTERNS = [
    re.compile(r'sk_test_'),
    re.compile(r'pk_test_'),
    re.compile(r'example|placeholder|your[_-]?key|xxx|000|test', re.IGNORECASE),
    re.compile(r'AKIA[A-Z]{16}'),  # All uppercase = likely placeholder
]


async def scan_secrets(app_domain: str) -> SecretScanResult:
    """
    Scan an app's JavaScript bundles for exposed secrets.
    
    Process:
    1. Fetch the homepage HTML
    2. Extract all JS bundle URLs
    3. Download each bundle
    4. Scan for secret patterns
    5. Classify and aggregate findings
    """
    result = SecretScanResult(app_domain=app_domain)
    
    try:
        async with httpx.AsyncClient(
            timeout=20.0,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SSAP-Research/1.0)"},
        ) as client:
            
            # Fetch homepage
            resp = await client.get(f"https://{app_domain}")
            if resp.status_code >= 400:
                return result
            
            html = resp.text
            
            # Also scan the HTML itself (inline scripts)
            _scan_content(html, "inline_html", result)
            
            # Extract JS bundle URLs
            js_urls = set()
            
            # Standard script tags
            for match in re.finditer(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html):
                js_urls.add(match.group(1))
            
            # Vite/Webpack module preload hints
            for match in re.finditer(r'<link[^>]+href=["\']([^"\']+\.js[^"\']*)["\']', html):
                js_urls.add(match.group(1))
            
            # Download and scan each bundle
            for js_url in list(js_urls)[:15]:  # Limit to 15 bundles max
                try:
                    if js_url.startswith("/"):
                        js_url = f"https://{app_domain}{js_url}"
                    elif not js_url.startswith("http"):
                        js_url = f"https://{app_domain}/{js_url}"
                    
                    js_resp = await client.get(js_url, timeout=15.0)
                    if js_resp.status_code == 200:
                        content = js_resp.text
                        result.bundles_scanned += 1
                        result.total_bundle_size_kb += len(content) // 1024
                        
                        filename = js_url.split("/")[-1].split("?")[0]
                        _scan_content(content, filename, result)
                
                except Exception:
                    continue
            
            # Also check for exposed source maps
            for js_url in list(js_urls)[:5]:
                try:
                    map_url = js_url + ".map" if not js_url.endswith(".map") else js_url
                    if map_url.startswith("/"):
                        map_url = f"https://{app_domain}{map_url}"
                    
                    map_resp = await client.head(map_url, timeout=5.0)
                    if map_resp.status_code == 200:
                        # Source map exists — this is itself a finding (info level)
                        result.secrets_found.append(DetectedSecret(
                            secret_type="exposed_source_map",
                            severity=SecretSeverity.MEDIUM,
                            location=map_url.split("/")[-1],
                            key_prefix="",
                            key_hash="",
                            appears_active=True,
                            context="Source map file is publicly accessible — exposes full source code",
                        ))
                except Exception:
                    continue
    
    except Exception as e:
        logger.debug(f"Secret scan failed for {app_domain}: {e}")
    
    # Set summary flags
    result.has_critical_secrets = any(s.severity == SecretSeverity.CRITICAL for s in result.secrets_found)
    result.has_high_secrets = any(s.severity == SecretSeverity.HIGH for s in result.secrets_found)
    
    return result


def _scan_content(content: str, filename: str, result: SecretScanResult):
    """Scan a text content block for secret patterns."""
    
    # Extract Supabase URL and anon key (these are public by design but important metadata)
    supabase_match = re.search(r'https://([a-z0-9]+)\.supabase\.co', content)
    if supabase_match:
        result.supabase_url = supabase_match.group(0)
    
    anon_match = re.search(r'(eyJ[A-Za-z0-9_-]{100,})', content)
    if anon_match and result.supabase_url:
        result.supabase_anon_key = anon_match.group(1)
    
    # Scan for each secret pattern
    for secret_type, severity, pattern, context in SECRET_PATTERNS:
        matches = pattern.finditer(content)
        for match in matches:
            key_value = match.group(1) if match.lastindex else match.group(0)
            
            # Check for false positives
            if _is_false_positive(key_value):
                continue
            
            key_hash = hashlib.sha256(key_value.encode()).hexdigest()
            
            # Deduplicate within this scan
            if any(s.key_hash == key_hash for s in result.secrets_found):
                continue
            
            # Special handling for service_role
            if secret_type == "supabase_service_role":
                result.supabase_service_role = True
            
            result.secrets_found.append(DetectedSecret(
                secret_type=secret_type,
                severity=severity,
                location=filename,
                key_prefix=key_value[:8] if len(key_value) > 8 else key_value[:4],
                key_hash=key_hash,
                appears_active=not _looks_like_test_key(key_value),
                context=context,
            ))


def _is_false_positive(value: str) -> bool:
    """Check if a detected secret is likely a false positive."""
    for pattern in FALSE_POSITIVE_PATTERNS:
        if pattern.search(value):
            return True
    # Very short values are likely false positives
    if len(value) < 10:
        return True
    return False


def _looks_like_test_key(value: str) -> bool:
    """Check if key appears to be a test/development key."""
    test_indicators = ["test", "demo", "example", "sandbox", "dev", "staging"]
    return any(indicator in value.lower() for indicator in test_indicators)
