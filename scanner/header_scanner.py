"""
Security Header Scanner — Aligned with SSAP Methodology
========================================================

Analyzes HTTP response headers for security best practices:
- Security header presence and configuration
- CSP weakness detection (unsafe-inline, unsafe-eval)
- CORS misconfiguration detection
- Service detection from CSP headers
- Technology fingerprinting

Based on SecureStack Assessment Platform (SSAP) methodology.
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

HTTP_TIMEOUT = 15.0


# Expected security headers
EXPECTED_SECURITY_HEADERS = [
    'strict-transport-security',
    'content-security-policy',
    'x-frame-options',
    'x-content-type-options',
    'referrer-policy',
    'permissions-policy',
    'cache-control',
]

# CSP Service Map for detecting third-party services
CSP_SERVICE_MAP = {
    # Auth
    'clerk.com': {'name': 'Clerk', 'category': 'auth'},
    'auth0.com': {'name': 'Auth0', 'category': 'auth'},
    'cognito-idp.': {'name': 'AWS Cognito', 'category': 'auth'},
    'accounts.google.com': {'name': 'Google OAuth', 'category': 'auth'},
    # Payments
    'js.stripe.com': {'name': 'Stripe', 'category': 'payments'},
    'stripe.com': {'name': 'Stripe', 'category': 'payments'},
    'paddle.com': {'name': 'Paddle', 'category': 'payments'},
    # Analytics
    'google-analytics.com': {'name': 'Google Analytics', 'category': 'analytics'},
    'googletagmanager.com': {'name': 'Google Tag Manager', 'category': 'analytics'},
    'plausible.io': {'name': 'Plausible', 'category': 'analytics'},
    'mixpanel.com': {'name': 'Mixpanel', 'category': 'analytics'},
    'posthog.com': {'name': 'PostHog', 'category': 'analytics'},
    'segment.com': {'name': 'Segment', 'category': 'analytics'},
    'hotjar.com': {'name': 'Hotjar', 'category': 'analytics'},
    # Monitoring
    'sentry.io': {'name': 'Sentry', 'category': 'monitoring'},
    'sentry-cdn.com': {'name': 'Sentry', 'category': 'monitoring'},
    'datadoghq.com': {'name': 'Datadog', 'category': 'monitoring'},
    'logrocket.com': {'name': 'LogRocket', 'category': 'monitoring'},
    # Communication
    'intercom.io': {'name': 'Intercom', 'category': 'communication'},
    'crisp.chat': {'name': 'Crisp', 'category': 'communication'},
    'zendesk.com': {'name': 'Zendesk', 'category': 'communication'},
    # Database
    'supabase.co': {'name': 'Supabase', 'category': 'database'},
    'firebaseio.com': {'name': 'Firebase', 'category': 'database'},
    # CDN
    'cloudflare.com': {'name': 'Cloudflare', 'category': 'cdn'},
    'googleapis.com': {'name': 'Google APIs', 'category': 'cdn'},
    'jsdelivr.net': {'name': 'jsDelivr', 'category': 'cdn'},
    # AI
    'openai.com': {'name': 'OpenAI', 'category': 'ai'},
    'anthropic.com': {'name': 'Anthropic', 'category': 'ai'},
}


@dataclass
class HeaderCheck:
    """Result of a single header check."""
    header_name: str
    present: bool
    value: str = ""
    severity: str = "info"  # critical, high, medium, low, info
    recommendation: str = ""
    finding_type: str = ""


@dataclass
class HeaderScanResult:
    """Complete header scan result for an app."""
    app_domain: str
    checks: List[HeaderCheck] = field(default_factory=list)
    findings: List[Dict[str, Any]] = field(default_factory=list)
    total_headers_checked: int = 0
    headers_present: int = 0
    headers_missing: int = 0
    score: int = 0
    csp_issues: List[str] = field(default_factory=list)
    cors_issues: List[str] = field(default_factory=list)
    detected_services: List[Dict[str, str]] = field(default_factory=list)
    auth_provider: Optional[str] = None
    payment_provider: Optional[str] = None


async def scan_headers(domain: str) -> HeaderScanResult:
    """
    Scan security headers for a domain.
    Returns HeaderScanResult with detailed findings.
    """
    result = HeaderScanResult(app_domain=domain)

    try:
        async with httpx.AsyncClient(
            timeout=HTTP_TIMEOUT,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (compatible; SSAP-Research/1.0)"},
        ) as client:
            # Fetch headers
            resp = await client.get(f"https://{domain}")
            headers = {k.lower(): v for k, v in resp.headers.items()}
            html_content = resp.text if resp.status_code == 200 else ""

            # Analyze security headers
            header_analysis = analyze_security_headers(headers)
            result.findings.extend(header_analysis['findings'])
            result.csp_issues = header_analysis['csp_issues']
            result.cors_issues = header_analysis['cors_issues']

            # Run individual header checks
            result.checks = _run_header_checks(headers)

            # Calculate statistics
            result.total_headers_checked = len(result.checks)
            result.headers_present = sum(1 for c in result.checks if c.present)
            result.headers_missing = sum(1 for c in result.checks if not c.present)

            # Detect services from CSP
            csp = headers.get('content-security-policy', '')
            result.detected_services = extract_services_from_csp(csp)

            # Detect auth and payment providers
            result.auth_provider = detect_auth_provider(headers, html_content)
            result.payment_provider = detect_payment_provider(headers, html_content)

            # Analyze page content for additional issues
            if html_content:
                page_findings = analyze_page_security(domain, html_content, headers)
                result.findings.extend(page_findings)

            # Calculate score
            result.score = _calculate_header_score(result)

    except httpx.TimeoutException:
        logger.warning(f"Timeout scanning headers for {domain}")
        result.score = 0
    except Exception as e:
        logger.debug(f"Error scanning headers for {domain}: {e}")
        result.score = 0

    return result


def _run_header_checks(headers: Dict[str, str]) -> List[HeaderCheck]:
    """Run individual header presence checks."""
    checks = []

    # Strict-Transport-Security
    hsts = headers.get('strict-transport-security', '')
    checks.append(HeaderCheck(
        header_name='Strict-Transport-Security',
        present=bool(hsts),
        value=hsts,
        severity='info' if hsts else 'medium',
        recommendation='' if hsts else "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
        finding_type='missing_hsts' if not hsts else '',
    ))

    # Content-Security-Policy
    csp = headers.get('content-security-policy', '')
    csp_severity = 'info'
    csp_recommendation = ''
    csp_finding_type = ''
    if not csp:
        csp_severity = 'high'
        csp_recommendation = 'Add a Content-Security-Policy header to prevent XSS attacks'
        csp_finding_type = 'missing_csp'
    elif "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
        csp_severity = 'medium'
        csp_recommendation = "CSP contains 'unsafe-inline' or 'unsafe-eval' which weakens protection"
        csp_finding_type = 'weak_csp'

    checks.append(HeaderCheck(
        header_name='Content-Security-Policy',
        present=bool(csp),
        value=csp[:200] if csp else '',
        severity=csp_severity,
        recommendation=csp_recommendation,
        finding_type=csp_finding_type,
    ))

    # X-Frame-Options
    xfo = headers.get('x-frame-options', '')
    checks.append(HeaderCheck(
        header_name='X-Frame-Options',
        present=bool(xfo),
        value=xfo,
        severity='info' if xfo else 'medium',
        recommendation='' if xfo else "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'",
        finding_type='missing_x_frame_options' if not xfo else '',
    ))

    # X-Content-Type-Options
    xcto = headers.get('x-content-type-options', '')
    checks.append(HeaderCheck(
        header_name='X-Content-Type-Options',
        present=bool(xcto),
        value=xcto,
        severity='info' if xcto else 'low',
        recommendation='' if xcto else "Add 'X-Content-Type-Options: nosniff'",
        finding_type='missing_x_content_type_options' if not xcto else '',
    ))

    # Referrer-Policy
    rp = headers.get('referrer-policy', '')
    checks.append(HeaderCheck(
        header_name='Referrer-Policy',
        present=bool(rp),
        value=rp,
        severity='info' if rp else 'low',
        recommendation='' if rp else "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
        finding_type='missing_referrer_policy' if not rp else '',
    ))

    # Permissions-Policy
    pp = headers.get('permissions-policy', '')
    checks.append(HeaderCheck(
        header_name='Permissions-Policy',
        present=bool(pp),
        value=pp[:200] if pp else '',
        severity='info' if pp else 'low',
        recommendation='' if pp else "Add 'Permissions-Policy: camera=(), microphone=(), geolocation=()'",
        finding_type='missing_permissions_policy' if not pp else '',
    ))

    # Cache-Control
    cc = headers.get('cache-control', '')
    checks.append(HeaderCheck(
        header_name='Cache-Control',
        present=bool(cc),
        value=cc,
        severity='info' if cc else 'medium',
        recommendation='' if cc else "Add 'Cache-Control: no-store, no-cache' for sensitive pages",
        finding_type='missing_cache_control' if not cc else '',
    ))

    # X-XSS-Protection (legacy but still tracked)
    xxp = headers.get('x-xss-protection', '')
    checks.append(HeaderCheck(
        header_name='X-XSS-Protection',
        present=bool(xxp),
        value=xxp,
        severity='info',
        recommendation='',
        finding_type='',
    ))

    return checks


def analyze_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """
    Analyze HTTP response headers for security best practices.
    Returns findings, csp_issues, cors_issues.
    """
    findings = []
    csp_issues = []
    cors_issues = []

    # Analyze CSP for weaknesses
    csp = headers.get('content-security-policy', '')
    if csp:
        if "'unsafe-inline'" in csp:
            csp_issues.append('unsafe-inline')
            findings.append({
                'severity': 'medium',
                'title': "CSP allows 'unsafe-inline' scripts",
                'description': (
                    "The Content-Security-Policy header contains 'unsafe-inline' in script-src, "
                    "which weakens XSS protection by allowing inline script execution."
                ),
                'remediation': "Remove 'unsafe-inline' from script-src and use nonces or hashes.",
                'finding_type': 'csp_unsafe_inline',
                'affected_resource': 'Content-Security-Policy header',
            })
        if "'unsafe-eval'" in csp:
            csp_issues.append('unsafe-eval')
            findings.append({
                'severity': 'medium',
                'title': "CSP allows 'unsafe-eval' scripts",
                'description': (
                    "The Content-Security-Policy header contains 'unsafe-eval' in script-src, "
                    "which allows dynamic code execution via eval(), Function(), etc."
                ),
                'remediation': "Remove 'unsafe-eval' from script-src. Refactor code using eval().",
                'finding_type': 'csp_unsafe_eval',
                'affected_resource': 'Content-Security-Policy header',
            })

    # Check CORS
    cors = headers.get('access-control-allow-origin', '')
    if cors == '*':
        cors_issues.append('wildcard')
        findings.append({
            'severity': 'medium',
            'title': 'Wildcard CORS policy (Access-Control-Allow-Origin: *)',
            'description': 'The server allows requests from any origin, exposing APIs to cross-origin attacks.',
            'remediation': "Set Access-Control-Allow-Origin to specific trusted domains.",
            'finding_type': 'cors_misconfiguration',
            'affected_resource': 'Access-Control-Allow-Origin header',
        })

    # Server header information disclosure
    server = headers.get('server', '')
    if server and server.lower() not in ('', 'cloudflare'):
        findings.append({
            'severity': 'info',
            'title': f'Server header discloses technology: {server}',
            'description': f'The Server header reveals "{server}", helping attackers identify vulnerabilities.',
            'remediation': "Remove or obfuscate the Server header.",
            'finding_type': 'server_info_disclosure',
            'affected_resource': 'Server header',
        })

    # X-Powered-By disclosure
    powered_by = headers.get('x-powered-by', '')
    if powered_by:
        findings.append({
            'severity': 'info',
            'title': f'X-Powered-By header exposes technology: {powered_by}',
            'description': f'The X-Powered-By header reveals "{powered_by}".',
            'remediation': "Remove the X-Powered-By header.",
            'finding_type': 'technology_fingerprint',
            'affected_resource': 'X-Powered-By header',
        })

    return {
        'findings': findings,
        'csp_issues': csp_issues,
        'cors_issues': cors_issues,
    }


def extract_services_from_csp(csp_header: str) -> List[Dict[str, str]]:
    """Parse CSP header domains and match against known service map."""
    if not csp_header:
        return []

    seen = set()
    services = []

    for domain_pattern, service_info in CSP_SERVICE_MAP.items():
        if domain_pattern in csp_header and service_info['name'] not in seen:
            seen.add(service_info['name'])
            services.append({
                'name': service_info['name'],
                'category': service_info['category'],
            })

    return services


def analyze_page_security(domain: str, content: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Analyze page content for security issues beyond headers."""
    findings = []

    # Source map exposure
    source_map_refs = re.findall(r'//[#@]\s*sourceMappingURL=(\S+)', content)
    if source_map_refs:
        findings.append({
            'severity': 'medium',
            'title': f'JavaScript source maps exposed ({len(source_map_refs)} found)',
            'description': (
                'Source map files allow anyone to reconstruct original source code, '
                'revealing business logic and potentially hardcoded credentials.'
            ),
            'remediation': 'Disable source maps in production builds.',
            'finding_type': 'exposed_source_map',
            'affected_resource': f'{len(source_map_refs)} source map reference(s)',
        })

    return findings


def detect_auth_provider(headers: Dict[str, str], html: str) -> Optional[str]:
    """Detect authentication provider from CSP headers and HTML content."""
    csp = headers.get('content-security-policy', '')
    combined = csp + ' ' + html

    if 'clerk.com' in combined or 'clerk.' in csp:
        return 'clerk'
    if 'auth0.com' in combined:
        return 'auth0'
    if 'cognito-idp.' in combined:
        return 'cognito'
    if 'firebaseauth.' in combined:
        return 'firebase_auth'
    if 'supabase' in combined.lower() and 'auth' in combined.lower():
        return 'supabase_auth'
    return None


def detect_payment_provider(headers: Dict[str, str], html: str) -> Optional[str]:
    """Detect payment provider from CSP headers and HTML content."""
    csp = headers.get('content-security-policy', '')
    combined = csp + ' ' + html

    if 'js.stripe.com' in combined or 'stripe.com' in csp:
        return 'stripe'
    if 'paddle.com' in combined:
        return 'paddle'
    if 'lemonsqueezy.com' in combined:
        return 'lemon_squeezy'
    return None


def _calculate_header_score(result: HeaderScanResult) -> int:
    """
    Calculate header security score (0-100).

    Scoring weights:
    - CSP present and strong: 30 points
    - HSTS present: 15 points
    - X-Frame-Options: 10 points
    - X-Content-Type-Options: 10 points
    - Referrer-Policy: 10 points
    - Permissions-Policy: 10 points
    - Cache-Control: 10 points
    - No CSP issues: 5 points bonus
    """
    score = 0

    for check in result.checks:
        if check.present:
            if check.header_name == 'Content-Security-Policy':
                score += 20
                if not result.csp_issues:
                    score += 10
            elif check.header_name == 'Strict-Transport-Security':
                score += 15
            elif check.header_name == 'X-Frame-Options':
                score += 10
            elif check.header_name == 'X-Content-Type-Options':
                score += 10
            elif check.header_name == 'Referrer-Policy':
                score += 10
            elif check.header_name == 'Permissions-Policy':
                score += 10
            elif check.header_name == 'Cache-Control':
                score += 10

    if result.cors_issues:
        score -= 5

    return max(0, min(100, score))
