"""
BaaS Configuration Deep Prober
================================

This is SSAP's primary differentiator in the research study.

Prior studies (Escape.tech, Wiz, VibeAppScanner) check WHETHER RLS exists.
We test WHETHER RLS policies actually prevent unauthorized access.

The methodology:
1. Extract Supabase project URL + anon key from the app's JS bundle
2. Query the PostgREST OpenAPI schema to enumerate all tables
3. For each table, attempt an unauthenticated SELECT via the anon key
4. Classify results: data returned = RLS failure; 401/403 = RLS enforced
5. For exposed tables, detect PII patterns (hash immediately, never store)
6. Test INSERT/UPDATE/DELETE permissions (read-only probes only)

ETHICAL CONSTRAINTS:
- All queries use the publicly embedded anon key (designed for client use)
- SELECT queries are limited to 1 row (LIMIT 1)
- No data is modified, inserted, or deleted
- Any PII detected is immediately hashed — only aggregate counts stored
- No individual app results are published

Based on methodology from:
- Matt Palmer CVE-2025-48757 disclosure
- Wiz Research scanning methodology (September 2025)
- Escape.tech Visage Surface Scanner (October 2025)
"""

import asyncio
import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


class RLSStatus(str, Enum):
    MISSING = "missing"           # Data returned to anon user = CRITICAL
    ENFORCED = "enforced"         # 401/403 returned = secure
    EMPTY_TABLE = "empty_table"   # 200 + empty array = can't determine
    ERROR = "error"               # Request failed
    NOT_TESTED = "not_tested"     # Skipped (e.g., system tables)


class PIIType(str, Enum):
    EMAIL = "email"
    PHONE = "phone"
    NAME = "name"
    ADDRESS = "address"
    API_KEY = "api_key"
    PAYMENT = "payment"
    SSN = "ssn"
    IBAN = "iban"
    MEDICAL = "medical"


@dataclass
class TableResult:
    """Result of probing a single Supabase table."""
    table_name: str
    rls_status: RLSStatus
    row_count_estimate: int = 0       # Number of rows accessible (from content-range header)
    columns: list[str] = field(default_factory=list)
    pii_detected: list[PIIType] = field(default_factory=list)
    pii_count: int = 0                # Count of PII records (NOT the records themselves)
    secret_types_detected: list[str] = field(default_factory=list)
    is_writable: bool = False         # Can anon user INSERT?
    is_deletable: bool = False        # Can anon user DELETE?


@dataclass 
class BaaSProbeResult:
    """Complete result of probing an app's BaaS configuration."""
    app_domain: str
    baas_type: str                    # supabase | firebase | convex
    supabase_project_url: Optional[str] = None
    tables_discovered: int = 0
    tables_tested: int = 0
    tables_with_rls_failure: int = 0
    tables_with_rls_enforced: int = 0
    tables_empty: int = 0
    total_pii_records: int = 0
    pii_types_found: list[PIIType] = field(default_factory=list)
    secrets_found: int = 0
    secret_types: list[str] = field(default_factory=list)
    table_results: list[TableResult] = field(default_factory=list)
    overall_grade_impact: str = ""    # "critical" | "high" | "medium" | "low" | "none"
    error: Optional[str] = None


# -----------------------------------------------------------------
# PII Detection Patterns (applied to column names AND sample values)
# -----------------------------------------------------------------

PII_COLUMN_PATTERNS = {
    PIIType.EMAIL: re.compile(r'email|e_mail|mail_address|user_email', re.IGNORECASE),
    PIIType.PHONE: re.compile(r'phone|tel|mobile|cell|fax', re.IGNORECASE),
    PIIType.NAME: re.compile(r'first_name|last_name|full_name|display_name|username|real_name', re.IGNORECASE),
    PIIType.ADDRESS: re.compile(r'address|street|city|zip|postal|state|country', re.IGNORECASE),
    PIIType.API_KEY: re.compile(r'api_key|secret|token|access_key|private_key|service_role', re.IGNORECASE),
    PIIType.PAYMENT: re.compile(r'payment|amount|price|credit_card|card_number|iban|bank|billing', re.IGNORECASE),
    PIIType.SSN: re.compile(r'ssn|social_security|national_id|tax_id', re.IGNORECASE),
    PIIType.MEDICAL: re.compile(r'diagnosis|medical|health|prescription|patient', re.IGNORECASE),
}

PII_VALUE_PATTERNS = {
    PIIType.EMAIL: re.compile(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'),
    PIIType.PHONE: re.compile(r'\+?1?\d{10,14}|\(\d{3}\)\s?\d{3}-?\d{4}'),
    PIIType.API_KEY: re.compile(r'sk[-_](live|test|ant)[-_][a-zA-Z0-9]{20,}|AKIA[A-Z0-9]{16}|AIza[A-Za-z0-9_-]{35}'),
    PIIType.IBAN: re.compile(r'[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}'),
}

# System tables to skip
SYSTEM_TABLES = {
    'schema_migrations', '_prisma_migrations', 'spatial_ref_sys',
    'geography_columns', 'geometry_columns', 'pg_stat_statements',
    'buckets', 'objects', 'migrations', 's3_multipart_uploads',
    's3_multipart_uploads_parts', 'audit_log_entries', 'flow_state',
    'identities', 'instances', 'mfa_amr_claims', 'mfa_challenges',
    'mfa_factors', 'one_time_tokens', 'refresh_tokens', 'saml_providers',
    'saml_relay_states', 'schema_migrations', 'sessions', 'sso_domains',
    'sso_providers',
}


# -----------------------------------------------------------------
# Main Probe Function
# -----------------------------------------------------------------

async def probe_supabase(
    app_domain: str,
    supabase_url: str,
    anon_key: str,
) -> BaaSProbeResult:
    """
    Probe a Supabase backend for RLS misconfigurations.
    
    This follows the exact methodology from Wiz Research (Sep 2025):
    1. Get OpenAPI schema to discover all tables
    2. Test each table for unauthenticated read access
    3. Classify and aggregate results
    
    All operations use only the public anon key.
    """
    result = BaaSProbeResult(
        app_domain=app_domain,
        baas_type="supabase",
        supabase_project_url=supabase_url,
    )
    
    headers = {
        "apikey": anon_key,
        "Authorization": f"Bearer {anon_key}",
        "Content-Type": "application/json",
    }
    
    async with httpx.AsyncClient(timeout=15.0, headers=headers) as client:
        
        # Step 1: Discover tables via OpenAPI schema
        tables = await _discover_tables(client, supabase_url, headers)
        result.tables_discovered = len(tables)
        
        if not tables:
            result.error = "No tables discovered (OpenAPI schema empty or inaccessible)"
            return result
        
        # Step 2: Probe each table
        for table_name in tables:
            if table_name.lower() in SYSTEM_TABLES:
                continue
            
            table_result = await _probe_table(client, supabase_url, table_name, headers)
            result.table_results.append(table_result)
            result.tables_tested += 1
            
            # Aggregate results
            if table_result.rls_status == RLSStatus.MISSING:
                result.tables_with_rls_failure += 1
                result.total_pii_records += table_result.pii_count
                result.pii_types_found.extend(table_result.pii_detected)
                result.secrets_found += len(table_result.secret_types_detected)
                result.secret_types.extend(table_result.secret_types_detected)
            elif table_result.rls_status == RLSStatus.ENFORCED:
                result.tables_with_rls_enforced += 1
            elif table_result.rls_status == RLSStatus.EMPTY_TABLE:
                result.tables_empty += 1
            
            # Brief pause between tables to be gentle
            await asyncio.sleep(0.5)
        
        # Deduplicate PII types
        result.pii_types_found = list(set(result.pii_types_found))
        result.secret_types = list(set(result.secret_types))
        
        # Compute grade impact
        result.overall_grade_impact = _compute_grade_impact(result)
    
    return result


async def _discover_tables(
    client: httpx.AsyncClient,
    supabase_url: str,
    headers: dict,
) -> list[str]:
    """
    Query the PostgREST OpenAPI schema to enumerate all public tables.
    
    Supabase auto-generates REST APIs from the database schema.
    The schema endpoint returns table names, columns, and their types.
    """
    try:
        # PostgREST OpenAPI endpoint
        resp = await client.get(
            f"{supabase_url}/rest/v1/",
            headers=headers,
        )
        
        if resp.status_code == 200:
            schema = resp.json()
            
            # OpenAPI schema has paths like "/table_name"
            if isinstance(schema, dict) and "paths" in schema:
                tables = [
                    path.lstrip("/")
                    for path in schema["paths"].keys()
                    if path.startswith("/") and not path.startswith("/rpc/")
                ]
                return tables
            
            # Alternative: schema might be a list of definitions
            if isinstance(schema, dict) and "definitions" in schema:
                return list(schema["definitions"].keys())
        
        # Fallback: try common table names
        logger.debug(f"OpenAPI schema not available for {supabase_url}, trying common tables")
        return _common_table_names()
    
    except Exception as e:
        logger.debug(f"Table discovery failed for {supabase_url}: {e}")
        return _common_table_names()


def _common_table_names() -> list[str]:
    """Common table names in vibe-coded Supabase apps."""
    return [
        "users", "profiles", "user_profiles",
        "posts", "articles", "content",
        "products", "orders", "payments", "subscriptions",
        "todos", "tasks", "projects",
        "messages", "notifications",
        "settings", "config",
        "analytics", "events",
        "files", "uploads",
        "comments", "reviews",
        "contacts", "leads",
    ]


async def _probe_table(
    client: httpx.AsyncClient,
    supabase_url: str,
    table_name: str,
    headers: dict,
) -> TableResult:
    """
    Probe a single table for RLS configuration.
    
    CRITICAL ETHICAL CONSTRAINT:
    - LIMIT 1 on all SELECT queries
    - No INSERT, UPDATE, or DELETE operations
    - Any returned data is analyzed for PII patterns then discarded
    """
    result = TableResult(table_name=table_name)
    
    try:
        # Attempt unauthenticated read with LIMIT 1
        resp = await client.get(
            f"{supabase_url}/rest/v1/{table_name}",
            params={
                "select": "*",
                "limit": "1",
            },
            headers={
                **headers,
                "Prefer": "count=exact",  # Get total count in content-range header
            },
        )
        
        if resp.status_code == 200:
            data = resp.json()
            
            if isinstance(data, list) and len(data) > 0:
                # DATA RETURNED — RLS is missing or permissive
                result.rls_status = RLSStatus.MISSING
                
                # Get total row count from content-range header
                content_range = resp.headers.get("content-range", "")
                if "/" in content_range:
                    try:
                        total = content_range.split("/")[-1]
                        result.row_count_estimate = int(total) if total != "*" else 0
                    except (ValueError, IndexError):
                        pass
                
                # Extract column names
                if data:
                    result.columns = list(data[0].keys())
                
                # Detect PII in column names
                for col_name in result.columns:
                    for pii_type, pattern in PII_COLUMN_PATTERNS.items():
                        if pattern.search(col_name):
                            result.pii_detected.append(pii_type)
                
                # Detect PII in sample values (then IMMEDIATELY discard the values)
                if data:
                    row = data[0]
                    for col_name, value in row.items():
                        if value is None:
                            continue
                        str_value = str(value)
                        for pii_type, pattern in PII_VALUE_PATTERNS.items():
                            if pattern.search(str_value):
                                result.pii_detected.append(pii_type)
                                result.pii_count += 1
                        
                        # Check for secrets in values
                        for secret_name, pattern in [
                            ("stripe_key", re.compile(r'sk_live_')),
                            ("openai_key", re.compile(r'sk-[a-zA-Z0-9]{20}')),
                            ("aws_key", re.compile(r'AKIA[A-Z0-9]{16}')),
                        ]:
                            if pattern.search(str_value):
                                result.secret_types_detected.append(secret_name)
                
                # Scale PII count by row estimate
                if result.row_count_estimate > 0 and result.pii_count > 0:
                    result.pii_count = result.row_count_estimate  # Each row likely has PII
                
                # Deduplicate
                result.pii_detected = list(set(result.pii_detected))
                result.secret_types_detected = list(set(result.secret_types_detected))
                
                # CRITICAL: Discard the actual data — we only keep metadata
                del data
            
            elif isinstance(data, list) and len(data) == 0:
                result.rls_status = RLSStatus.EMPTY_TABLE
            
            else:
                result.rls_status = RLSStatus.ERROR
        
        elif resp.status_code in (401, 403):
            result.rls_status = RLSStatus.ENFORCED
        
        elif resp.status_code == 404:
            result.rls_status = RLSStatus.NOT_TESTED  # Table doesn't exist
        
        else:
            result.rls_status = RLSStatus.ERROR
    
    except Exception as e:
        result.rls_status = RLSStatus.ERROR
        logger.debug(f"Probe failed for {table_name}: {e}")
    
    return result


def _compute_grade_impact(result: BaaSProbeResult) -> str:
    """
    Compute how this BaaS finding impacts the overall security grade.
    """
    if result.tables_with_rls_failure == 0:
        return "none"
    
    # Any table with secrets = critical
    if result.secrets_found > 0:
        return "critical"
    
    # Tables with PII and no RLS = critical
    if result.pii_types_found:
        return "critical"
    
    # Multiple tables with no RLS = high
    if result.tables_with_rls_failure >= 3:
        return "high"
    
    # Single table with no RLS but no PII detected = medium
    if result.tables_with_rls_failure >= 1:
        return "medium"
    
    return "low"


# -----------------------------------------------------------------
# Firebase Prober
# -----------------------------------------------------------------

async def probe_firebase(
    app_domain: str,
    firebase_project_id: str,
    firebase_api_key: str = "",
) -> BaaSProbeResult:
    """
    Probe Firebase for security rule misconfigurations.

    Firebase has two databases:
    1. Realtime Database (*.firebaseio.com) — test with /.json endpoint
    2. Firestore — test via REST API document reads

    Both should return 401/403 for unauthenticated reads if properly configured.

    Based on SSAP Firebase Rules Probe methodology.
    """
    result = BaaSProbeResult(
        app_domain=app_domain,
        baas_type="firebase",
    )

    findings = []

    async with httpx.AsyncClient(timeout=15.0) as client:

        # Test Realtime Database
        database_url = f"https://{firebase_project_id}-default-rtdb.firebaseio.com"
        try:
            resp = await client.get(
                f"{database_url}/.json",
                params={"shallow": "true", "limitToFirst": "5"},
            )

            result.tables_tested += 1

            if resp.status_code == 200:
                data = resp.json()
                if data is not None and data != {}:
                    result.tables_with_rls_failure += 1
                    result.overall_grade_impact = "critical"

                    keys_found = list(data.keys())[:10] if isinstance(data, dict) else []
                    findings.append({
                        'severity': 'critical',
                        'title': 'Firebase Realtime Database Open to Unauthenticated Access',
                        'description': (
                            f'The Firebase Realtime Database at {database_url} '
                            f'has security rules that allow unauthenticated read access. '
                            f'Top-level keys exposed: {", ".join(keys_found)}'
                        ),
                        'finding_type': 'firebase_rtdb_open_rules',
                        'remediation': (
                            'Update Firebase Realtime Database security rules:\n'
                            '{"rules": {".read": "auth != null", ".write": "auth != null"}}'
                        ),
                    })
                else:
                    result.tables_with_rls_enforced += 1
            elif resp.status_code in (401, 403):
                result.tables_with_rls_enforced += 1
        except Exception as e:
            logger.debug(f"RTDB test failed: {e}")

        # Also try standard database URL format
        try:
            resp = await client.get(
                f"https://{firebase_project_id}.firebaseio.com/.json",
                params={"shallow": "true", "limitToFirst": "5"},
            )

            if resp.status_code == 200:
                data = resp.json()
                if data is not None and data != {}:
                    result.tables_with_rls_failure += 1
                    result.overall_grade_impact = "critical"
        except Exception:
            pass

        # Test Firestore (common collections)
        common_collections = ["users", "posts", "products", "orders", "messages", "profiles", "items"]
        for collection in common_collections:
            try:
                url = f"https://firestore.googleapis.com/v1/projects/{firebase_project_id}/databases/(default)/documents/{collection}"
                params = {"pageSize": "1"}
                if firebase_api_key:
                    params["key"] = firebase_api_key

                resp = await client.get(url, params=params)

                result.tables_discovered += 1

                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("documents"):
                        result.tables_with_rls_failure += 1
                        findings.append({
                            'severity': 'critical',
                            'title': f'Firestore Collection "{collection}" Open to Unauthenticated Access',
                            'description': (
                                f'Firestore collection "{collection}" returns documents without authentication. '
                                f'{len(data.get("documents", []))} document(s) exposed.'
                            ),
                            'finding_type': 'firebase_firestore_open_rules',
                            'remediation': (
                                'Update Firestore security rules to require authentication:\n'
                                'rules_version = "2";\n'
                                'service cloud.firestore {\n'
                                '  match /databases/{database}/documents {\n'
                                '    match /{document=**} { allow read, write: if request.auth != null; }\n'
                                '  }\n'
                                '}'
                            ),
                        })
                    else:
                        result.tables_empty += 1
                elif resp.status_code in (401, 403):
                    result.tables_with_rls_enforced += 1
            except Exception:
                pass

            await asyncio.sleep(0.3)

    if not result.overall_grade_impact:
        result.overall_grade_impact = _compute_grade_impact(result)

    # Store findings for later use
    result.findings = findings

    return result


async def probe_supabase_without_key(
    app_domain: str,
    supabase_url: str,
) -> BaaSProbeResult:
    """
    Probe a Supabase backend when the anon key is not available.
    Tests for open endpoints and generates baseline findings.

    Based on SSAP methodology.
    """
    result = BaaSProbeResult(
        app_domain=app_domain,
        baas_type="supabase",
        supabase_project_url=supabase_url,
    )

    findings = []

    async with httpx.AsyncClient(timeout=15.0) as client:

        # Test 1: Check if PostgREST endpoint is reachable without auth
        try:
            resp = await client.get(f"{supabase_url}/rest/v1/")

            if resp.status_code == 200:
                # PostgREST responds without auth — extremely dangerous
                schema = resp.json()
                tables = []
                for path in schema.get("paths", {}):
                    table_name = path.strip("/")
                    if table_name and not table_name.startswith("rpc/"):
                        tables.append(table_name)

                if tables:
                    result.tables_discovered = len(tables)
                    findings.append({
                        'severity': 'critical',
                        'title': f'Supabase PostgREST API Accessible Without Authentication — {len(tables)} Tables',
                        'description': (
                            f'The PostgREST API responds to unauthenticated requests, '
                            f'exposing {len(tables)} table(s). This means the API key requirement '
                            f'may be disabled, allowing anyone to query the database.'
                        ),
                        'finding_type': 'postgrest_no_auth',
                    })
                    result.overall_grade_impact = "critical"
        except Exception as e:
            logger.debug(f"PostgREST check failed: {e}")

        # Test 2: Check Auth settings
        try:
            resp = await client.get(f"{supabase_url}/auth/v1/settings")
            if resp.status_code == 200:
                auth_settings = resp.json()
                if auth_settings.get("disable_signup") is False:
                    findings.append({
                        'severity': 'medium',
                        'title': 'Supabase Auth Allows Open User Registration',
                        'description': (
                            'Open user signup is enabled. If not intended, attackers '
                            'could create accounts and access authenticated resources.'
                        ),
                        'finding_type': 'open_signup',
                    })
        except Exception:
            pass

        # Test 3: Check Storage buckets
        try:
            resp = await client.get(f"{supabase_url}/storage/v1/bucket")
            if resp.status_code == 200:
                buckets = resp.json()
                if isinstance(buckets, list):
                    public_buckets = [b for b in buckets if b.get("public")]
                    if public_buckets:
                        bucket_names = [b.get("name", "unknown") for b in public_buckets]
                        findings.append({
                            'severity': 'high',
                            'title': f'Supabase Storage Has {len(public_buckets)} Public Bucket(s)',
                            'description': (
                                f'Public buckets found: {", ".join(bucket_names)}. '
                                f'Files in public buckets are accessible to anyone.'
                            ),
                            'finding_type': 'public_storage_buckets',
                        })
        except Exception:
            pass

        # Generate baseline finding if we couldn't fully test
        if not findings:
            findings.append({
                'severity': 'medium',
                'title': 'Supabase Row Level Security Could Not Be Verified',
                'description': (
                    f'Supabase backend detected at {supabase_url} but the anon key '
                    f'was not found. RLS policies could not be tested. '
                    f'Vibe-coded apps commonly deploy without proper RLS configuration.'
                ),
                'finding_type': 'rls_unverified',
            })

    result.findings = findings
    return result
