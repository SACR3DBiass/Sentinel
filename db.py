"""
SENTINEL Database Layer
Cloud-first with Supabase PostgreSQL. Falls back to SQLite + JSON for local dev.
"""

import os
import json
import threading
import uuid
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any

_supabase_client = None
_supabase_available = False
_store_lock = threading.Lock()

# ============================================================================
# SUPABASE CONNECTION
# ============================================================================

_SUPABASE_ACCESS_TOKEN = os.getenv("SUPABASE_ACCESS_TOKEN", "")

_MIGRATION_SQL = """
-- SENTINEL Combined Migration: All tables (idempotent)

-- ============================================================================
-- 1. ORGANIZATIONS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    domain TEXT UNIQUE NOT NULL,
    sla_status TEXT NOT NULL DEFAULT 'active' CHECK (sla_status IN ('active', 'suspended', 'trial')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 2. USERS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    org_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_users_username ON public.users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON public.users(email);
CREATE INDEX IF NOT EXISTS idx_users_org ON public.users(org_id);

-- ============================================================================
-- 3. REPORTED EMAILS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.reported_emails (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    sender TEXT NOT NULL,
    subject TEXT NOT NULL DEFAULT '(no subject)',
    raw_body TEXT NOT NULL DEFAULT '',
    ai_risk_score REAL NOT NULL DEFAULT 0 CHECK (ai_risk_score >= 0 AND ai_risk_score <= 100),
    ai_analysis JSONB NOT NULL DEFAULT '{}',
    urls TEXT[] DEFAULT '{}',
    has_attachments BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_reported_emails_org ON public.reported_emails(org_id);
CREATE INDEX IF NOT EXISTS idx_reported_emails_user ON public.reported_emails(user_id);
CREATE INDEX IF NOT EXISTS idx_reported_emails_created ON public.reported_emails(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reported_emails_risk ON public.reported_emails(ai_risk_score DESC);

-- ============================================================================
-- 4. FEEDBACK LOGS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.feedback_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id UUID NOT NULL REFERENCES public.reported_emails(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    original_verdict TEXT NOT NULL,
    corrected_verdict TEXT NOT NULL CHECK (corrected_verdict IN ('safe', 'suspicious', 'malicious')),
    reason TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_feedback_email ON public.feedback_logs(email_id);
CREATE INDEX IF NOT EXISTS idx_feedback_org ON public.feedback_logs(org_id);

-- ============================================================================
-- 5. WHITELIST
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.whitelist (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    pattern_type TEXT NOT NULL CHECK (pattern_type IN ('domain', 'sender', 'subject_regex')),
    pattern_value TEXT NOT NULL,
    added_by TEXT NOT NULL,
    source TEXT NOT NULL DEFAULT 'manual' CHECK (source IN ('manual', 'feedback_auto')),
    hit_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE(org_id, pattern_type, pattern_value)
);
CREATE INDEX IF NOT EXISTS idx_whitelist_org ON public.whitelist(org_id);
ALTER TABLE whitelist ADD COLUMN IF NOT EXISTS last_hit_at TIMESTAMPTZ;
ALTER TABLE whitelist ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT '';

-- ============================================================================
-- 6. EMAIL CONNECTIONS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.email_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL,
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    label TEXT NOT NULL DEFAULT 'My Email',
    provider TEXT NOT NULL DEFAULT 'custom' CHECK (provider IN ('gmail', 'outlook', 'yahoo', 'custom')),
    imap_host TEXT NOT NULL,
    imap_port INTEGER NOT NULL DEFAULT 993,
    imap_username TEXT NOT NULL,
    imap_password_enc TEXT NOT NULL,
    imap_folder TEXT NOT NULL DEFAULT 'INBOX',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    last_scan_at TIMESTAMPTZ,
    last_scan_count INTEGER DEFAULT 0,
    scan_interval_minutes INTEGER NOT NULL DEFAULT 30,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_email_conn_user ON public.email_connections(user_id);
CREATE INDEX IF NOT EXISTS idx_email_conn_org ON public.email_connections(org_id);
CREATE INDEX IF NOT EXISTS idx_email_conn_active ON public.email_connections(is_active) WHERE is_active = TRUE;

-- ============================================================================
-- 7. FORWARD ADDRESSES
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.forward_addresses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL,
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    forward_email TEXT NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- 8. SCAN JOBS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id UUID NOT NULL REFERENCES public.email_connections(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'completed', 'failed')),
    emails_found INTEGER DEFAULT 0,
    emails_analyzed INTEGER DEFAULT 0,
    error_message TEXT,
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_user ON public.scan_jobs(user_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON public.scan_jobs(status);

-- ============================================================================
-- 9. INVITES
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    invited_by TEXT NOT NULL,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_invites_org ON public.invites(org_id);
CREATE INDEX IF NOT EXISTS idx_invites_token ON public.invites(token);

-- ============================================================================
-- 10. USER FEEDBACK (XAI)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.user_feedback (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email_id TEXT NOT NULL,
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL,
    original_verdict TEXT NOT NULL CHECK (original_verdict IN ('safe', 'suspicious', 'malicious')),
    corrected_verdict TEXT NOT NULL CHECK (corrected_verdict IN ('safe', 'suspicious', 'malicious')),
    sender_domain TEXT DEFAULT '',
    sender_address TEXT DEFAULT '',
    reason TEXT DEFAULT '',
    feedback_type TEXT DEFAULT 'correction' CHECK (feedback_type IN ('correction', 'false_positive', 'false_negative')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_user_feedback_org ON public.user_feedback(org_id);
CREATE INDEX IF NOT EXISTS idx_user_feedback_user ON public.user_feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_user_feedback_sender_domain ON public.user_feedback(sender_domain);
CREATE INDEX IF NOT EXISTS idx_user_feedback_corrected ON public.user_feedback(corrected_verdict);
CREATE INDEX IF NOT EXISTS idx_user_feedback_created ON public.user_feedback(created_at DESC);

-- ============================================================================
-- 11. LEADS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.leads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    org_name TEXT DEFAULT '',
    source TEXT DEFAULT 'health_check' CHECK (source IN ('health_check', 'marketing', 'demo_request')),
    health_check_result JSONB DEFAULT '{}',
    converted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_leads_email ON public.leads(email);
CREATE INDEX IF NOT EXISTS idx_leads_source ON public.leads(source);
CREATE INDEX IF NOT EXISTS idx_leads_created ON public.leads(created_at DESC);

-- ============================================================================
-- 12. ORG SETTINGS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.org_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE UNIQUE,
    cost_per_incident REAL DEFAULT 4500.0,
    custom_whitelist_notes TEXT DEFAULT '',
    auto_whitelist_from_feedback BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_org_settings_org ON public.org_settings(org_id);

-- ============================================================================
-- 13. REQUEST LOGS
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.request_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    ip_address TEXT,
    user_agent TEXT,
    path TEXT,
    method TEXT,
    user_id TEXT,
    username TEXT,
    country TEXT,
    region TEXT,
    city TEXT,
    browser TEXT,
    os TEXT,
    device_type TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_request_logs_created ON public.request_logs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_request_logs_ip ON public.request_logs(ip_address);

-- ============================================================================
-- RLS: Enable on all tables
-- ============================================================================
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reported_emails ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.feedback_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.whitelist ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.forward_addresses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.user_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.leads ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.request_logs ENABLE ROW LEVEL SECURITY;

-- RLS Policies: service_role + anon bypass (DROP IF EXISTS + CREATE for idempotency)
-- anon role is used by publishable key; service_role bypasses RLS entirely
DO $$ BEGIN DROP POLICY IF EXISTS "svc_organizations" ON public.organizations; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_organizations" ON public.organizations FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_organizations" ON public.organizations; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_organizations" ON public.organizations FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_users" ON public.users; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_users" ON public.users FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_users" ON public.users; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_users" ON public.users FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_reported_emails" ON public.reported_emails; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_reported_emails" ON public.reported_emails FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_reported_emails" ON public.reported_emails; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_reported_emails" ON public.reported_emails FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_feedback_logs" ON public.feedback_logs; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_feedback_logs" ON public.feedback_logs FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_feedback_logs" ON public.feedback_logs; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_feedback_logs" ON public.feedback_logs FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_whitelist" ON public.whitelist; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_whitelist" ON public.whitelist FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_whitelist" ON public.whitelist; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_whitelist" ON public.whitelist FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_email_connections" ON public.email_connections; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_email_connections" ON public.email_connections FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_email_connections" ON public.email_connections; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_email_connections" ON public.email_connections FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_forward_addresses" ON public.forward_addresses; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_forward_addresses" ON public.forward_addresses FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_forward_addresses" ON public.forward_addresses; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_forward_addresses" ON public.forward_addresses FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_scan_jobs" ON public.scan_jobs; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_scan_jobs" ON public.scan_jobs FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_scan_jobs" ON public.scan_jobs; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_scan_jobs" ON public.scan_jobs FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_invites" ON public.invites; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_invites" ON public.invites FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_invites" ON public.invites; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_invites" ON public.invites FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_user_feedback" ON public.user_feedback; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_user_feedback" ON public.user_feedback FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_user_feedback" ON public.user_feedback; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_user_feedback" ON public.user_feedback FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_leads" ON public.leads; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_leads" ON public.leads FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_leads" ON public.leads; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_leads" ON public.leads FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_org_settings" ON public.org_settings; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_org_settings" ON public.org_settings FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_org_settings" ON public.org_settings; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_org_settings" ON public.org_settings FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_request_logs" ON public.request_logs; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_request_logs" ON public.request_logs FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_request_logs" ON public.request_logs; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_request_logs" ON public.request_logs FOR ALL USING (auth.role() = 'anon');

-- ============================================================================
-- SEED DATA
-- ============================================================================
INSERT INTO public.organizations (name, domain, sla_status)
VALUES ('Default Organization', 'sentinel.local', 'active')
ON CONFLICT (domain) DO NOTHING;

INSERT INTO public.org_settings (org_id, cost_per_incident)
SELECT id, 4500.0 FROM organizations
WHERE domain = 'sentinel.local'
ON CONFLICT (org_id) DO NOTHING;
"""

def _extract_supabase_ref(url: str) -> Optional[str]:
    """Extract project ref from Supabase URL like https://xxxxx.supabase.co"""
    if not url:
        return None
    try:
        from urllib.parse import urlparse
        host = urlparse(url).hostname or ""
        return host.split(".")[0] if host.endswith(".supabase.co") else None
    except Exception:
        return None

def _tables_exist() -> bool:
    """Check if core tables already exist by querying organizations."""
    global _supabase_client
    try:
        _supabase_client.table("organizations").select("id").limit(1).execute()
        return True
    except Exception:
        return False

def ensure_supabase_tables(url: str, key: str) -> bool:
    """Auto-create all Supabase tables via Management API if they don't exist.
    Requires SUPABASE_ACCESS_TOKEN env var (create at https://supabase.com/dashboard/account/tokens).
    Returns True if tables were created or already exist, False if auto-migration failed."""
    global _supabase_client

    if not url or not key:
        print("[SENTINEL] Supabase URL or key missing", flush=True)
        return False

    # First check if tables already exist
    try:
        from supabase import create_client
        _supabase_client = create_client(url, key)
        if _tables_exist():
            print("[SENTINEL] Supabase tables verified - all good", flush=True)
            return True
        print("[SENTINEL] Supabase connected but tables missing - will auto-create", flush=True)
    except Exception as e:
        print(f"[SENTINEL] Supabase client init failed: {e}", flush=True)

    # Tables missing — need Management API token
    if not _SUPABASE_ACCESS_TOKEN:
        print("[SENTINEL] CRITICAL: Supabase tables missing and no SUPABASE_ACCESS_TOKEN env var.", flush=True)
        print("[SENTINEL] Set SUPABASE_ACCESS_TOKEN in Railway variables.", flush=True)
        print("[SENTINEL] Create token: https://supabase.com/dashboard/account/tokens", flush=True)
        return False

    project_ref = _extract_supabase_ref(url)
    if not project_ref:
        print(f"[SENTINEL] CRITICAL: Could not extract project ref from URL: {url}", flush=True)
        return False

    print(f"[SENTINEL] Auto-creating Supabase tables (project: {project_ref})...", flush=True)

    try:
        import httpx
        resp = httpx.post(
            f"https://api.supabase.com/v1/projects/{project_ref}/database/query",
            headers={
                "Authorization": f"Bearer {_SUPABASE_ACCESS_TOKEN}",
                "Content-Type": "application/json",
            },
            json={"query": _MIGRATION_SQL},
            timeout=120.0,
        )
        if resp.status_code == 200:
            print("[SENTINEL] Migration SQL executed successfully", flush=True)
        else:
            body = resp.text[:1000]
            print(f"[SENTINEL] Management API error {resp.status_code}: {body}", flush=True)
            return False
    except Exception as e:
        print(f"[SENTINEL] Management API call failed: {e}", flush=True)
        return False

    # Re-init client and verify tables exist
    import time
    time.sleep(2)
    try:
        from supabase import create_client as _cc
        _supabase_client = _cc(url, key)
        if _tables_exist():
            print("[SENTINEL] Supabase connected - tables verified", flush=True)
            return True
        print("[SENTINEL] Tables created but not yet visible - retrying...", flush=True)
        time.sleep(3)
        if _tables_exist():
            print("[SENTINEL] Supabase connected - tables verified (retry)", flush=True)
            return True
        print("[SENTINEL] WARNING: Migration ran but tables still not visible", flush=True)
        return False
    except Exception as e:
        print(f"[SENTINEL] Post-migration verification failed: {e}", flush=True)
        return False

def init_supabase(url: str, key: str):
    global _supabase_client, _supabase_available
    if not url or not key:
        print("[SENTINEL] Supabase not configured - using local fallback", flush=True)
        return
    # Try auto-migration first if tables might be missing
    if ensure_supabase_tables(url, key):
        _supabase_available = True
        return
    # Fallback: try direct connection (tables might already exist)
    try:
        from supabase import create_client
        _supabase_client = create_client(url, key)
        _supabase_client.table("organizations").select("id").limit(1).execute()
        _supabase_available = True
        print("[SENTINEL] Supabase connected", flush=True)
    except Exception as e:
        print(f"[SENTINEL] Supabase failed: {e} - using local fallback", flush=True)
        _supabase_available = False

def get_supabase():
    return _supabase_client if _supabase_available else None

def is_supabase_available() -> bool:
    return _supabase_available

# ============================================================================
# USER OPERATIONS (Cloud)
# ============================================================================

def user_create(username: str, email: str, password_hash: str, org_id: str = None, user_id: str = None) -> Optional[dict]:
    sb = get_supabase()
    if not user_id:
        user_id = str(uuid.uuid4())
    if sb:
        try:
            data = {
                "id": user_id,
                "username": username,
                "email": email,
                "password_hash": password_hash,
                "role": "owner" if not org_id else "member",
                "is_active": True,
            }
            if org_id:
                data["org_id"] = org_id
            result = sb.table("users").insert(data).execute()
            return result.data[0] if result.data else data
        except Exception as e:
            print(f"[SENTINEL] user_create (Supabase) failed: {e}", flush=True)
    # Local fallback
    return user_create_local(username, email, password_hash, user_id=user_id)

def user_get_by_username(username: str) -> Optional[dict]:
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("users").select("*").eq("username", username).execute()
            if result.data:
                return result.data[0]
        except Exception:
            pass
    return user_get_by_username_local(username)

def user_get_by_id(user_id: str) -> Optional[dict]:
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("users").select("*").eq("id", user_id).execute()
            if result.data:
                return result.data[0]
        except Exception:
            pass
    return user_get_by_id_local(user_id)

def user_get_by_email(email: str) -> Optional[dict]:
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("users").select("*").eq("email", email).execute()
            return result.data[0] if result.data else None
        except Exception:
            return None
    return None

def user_update_last_login(user_id: str):
    sb = get_supabase()
    if sb:
        try:
            sb.table("users").update({"last_login": datetime.utcnow().isoformat()}).eq("id", user_id).execute()
        except Exception:
            pass

def user_list_org(org_id: str) -> List[dict]:
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("users").select("id,username,email,role,is_active,last_login,created_at").eq("org_id", org_id).execute()
            return result.data or []
        except Exception:
            pass
    try:
        conn = _get_users_db()
        rows = conn.execute("SELECT id,username,email,role,is_active,last_login,created_at FROM users WHERE org_id=?", (org_id,)).fetchall()
        conn.close()
        return [dict(r) for r in rows]
    except Exception:
        return []

# ============================================================================
# ORGANIZATION OPERATIONS
# ============================================================================

def org_create(name: str, domain: str) -> Optional[dict]:
    sb = get_supabase()
    if not sb:
        return {"id": _LOCAL_ORG_ID, "name": name, "domain": domain}
    try:
        org_id = str(uuid.uuid4())
        result = sb.table("organizations").insert({
            "id": org_id,
            "name": name,
            "domain": domain,
            "sla_status": "trial",
        }).execute()
        return result.data[0] if result.data else {"id": org_id, "name": name}
    except Exception as e:
        print(f"[SENTINEL] org_create failed: {e}", flush=True)
        return None

def org_get(org_id: str) -> Optional[dict]:
    sb = get_supabase()
    if not sb:
        return None
    try:
        result = sb.table("organizations").select("*").eq("id", org_id).execute()
        return result.data[0] if result.data else None
    except Exception:
        return None

def get_or_create_default_org() -> Optional[str]:
    sb = get_supabase()
    if not sb:
        return _LOCAL_ORG_ID
    try:
        result = sb.table("organizations").select("id").eq("domain", "sentinel.local").execute()
        if result.data:
            return result.data[0]["id"]
        org_id = str(uuid.uuid4())
        sb.table("organizations").insert({
            "id": org_id, "name": "Default Organization",
            "domain": "sentinel.local", "sla_status": "active",
        }).execute()
        return org_id
    except Exception:
        return _LOCAL_ORG_ID

_LOCAL_ORG_ID = "org-local-default"

# ============================================================================
# EMAIL CONNECTIONS (Per-user IMAP)
# ============================================================================

def _conns_file(user_id: str = "_global") -> str:
    user_dir = os.path.join(DATA_DIR, user_id)
    os.makedirs(user_dir, exist_ok=True)
    return os.path.join(user_dir, "email_connections.json")

def _scans_file(user_id: str = "_global") -> str:
    user_dir = os.path.join(DATA_DIR, user_id)
    os.makedirs(user_dir, exist_ok=True)
    return os.path.join(user_dir, "scan_jobs.json")

def email_connection_create(user_id: str, org_id: str, label: str, provider: str,
                            imap_host: str, imap_port: int, imap_username: str,
                            imap_password_enc: str, imap_folder: str = "INBOX",
                            scan_interval: int = 30) -> Optional[dict]:
    sb = get_supabase()
    conn_id = str(uuid.uuid4())
    if sb:
        try:
            result = sb.table("email_connections").insert({
                "id": conn_id,
                "user_id": user_id,
                "org_id": org_id,
                "label": label,
                "provider": provider,
                "imap_host": imap_host,
                "imap_port": imap_port,
                "imap_username": imap_username,
                "imap_password_enc": imap_password_enc,
                "imap_folder": imap_folder,
                "is_active": True,
                "scan_interval_minutes": scan_interval,
            }).execute()
            return result.data[0] if result.data else {"id": conn_id}
        except Exception as e:
            print(f"[SENTINEL] email_connection_create (Supabase) failed: {e}", flush=True)
    # Local fallback
    conn_data = {
        "id": conn_id, "user_id": user_id, "org_id": org_id,
        "label": label, "provider": provider,
        "imap_host": imap_host, "imap_port": imap_port,
        "imap_username": imap_username, "imap_password_enc": imap_password_enc,
        "imap_folder": imap_folder, "is_active": True,
        "last_scan_at": None, "last_scan_count": 0,
        "scan_interval_minutes": scan_interval,
        "created_at": datetime.utcnow().isoformat(),
    }
    with _store_lock:
        conns = _load_json(_conns_file(user_id))
        conns.append(conn_data)
        _save_json(_conns_file(user_id), conns)
    return conn_data

def email_connection_list(user_id: str) -> List[dict]:
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("email_connections").select(
                "id,label,provider,imap_host,imap_username,imap_folder,is_active,last_scan_at,last_scan_count,scan_interval_minutes,created_at"
            ).eq("user_id", user_id).order("created_at", desc=True).execute()
            return result.data or []
        except Exception:
            pass
    # Local fallback
    conns = _load_json(_conns_file(user_id))
    # Strip password from list view
    return [{k: v for k, v in c.items() if k != "imap_password_enc"} for c in conns]

def email_connection_get(conn_id: str, user_id: str) -> Optional[dict]:
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("email_connections").select("*").eq("id", conn_id).eq("user_id", user_id).execute()
            return result.data[0] if result.data else None
        except Exception:
            pass
    conns = _load_json(_conns_file(user_id))
    return next((c for c in conns if c["id"] == conn_id), None)

def email_connection_get_active_all() -> List[dict]:
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("email_connections").select("*").eq("is_active", True).execute()
            return result.data or []
        except Exception:
            pass
    return []

def email_connection_update_scan(conn_id: str, emails_count: int):
    sb = get_supabase()
    if sb:
        try:
            sb.table("email_connections").update({
                "last_scan_at": datetime.utcnow().isoformat(),
                "last_scan_count": emails_count,
            }).eq("id", conn_id).execute()
            return
        except Exception:
            pass
    # Local fallback: scan through all user files
    for user_dir in os.listdir(DATA_DIR):
        fpath = os.path.join(DATA_DIR, user_dir, "email_connections.json")
        if os.path.isfile(fpath):
            with _store_lock:
                conns = _load_json(fpath)
                for c in conns:
                    if c["id"] == conn_id:
                        c["last_scan_at"] = datetime.utcnow().isoformat()
                        c["last_scan_count"] = emails_count
                        _save_json(fpath, conns)
                        return

def email_connection_delete(conn_id: str, user_id: str) -> bool:
    sb = get_supabase()
    if sb:
        try:
            sb.table("email_connections").delete().eq("id", conn_id).eq("user_id", user_id).execute()
            return True
        except Exception:
            pass
    with _store_lock:
        conns = _load_json(_conns_file(user_id))
        new_conns = [c for c in conns if c["id"] != conn_id]
        if len(new_conns) < len(conns):
            _save_json(_conns_file(user_id), new_conns)
            return True
    return False

def email_connection_toggle(conn_id: str, user_id: str, is_active: bool) -> bool:
    sb = get_supabase()
    if sb:
        try:
            sb.table("email_connections").update({"is_active": is_active}).eq("id", conn_id).eq("user_id", user_id).execute()
            return True
        except Exception:
            pass
    with _store_lock:
        conns = _load_json(_conns_file(user_id))
        for c in conns:
            if c["id"] == conn_id:
                c["is_active"] = is_active
                _save_json(_conns_file(user_id), conns)
                return True
    return False

# ============================================================================
# SCAN JOBS
# ============================================================================

def scan_job_create(connection_id: str, user_id: str, org_id: str) -> Optional[str]:
    sb = get_supabase()
    job_id = str(uuid.uuid4())
    if sb:
        try:
            sb.table("scan_jobs").insert({
                "id": job_id, "connection_id": connection_id,
                "user_id": user_id, "org_id": org_id, "status": "pending",
            }).execute()
            return job_id
        except Exception:
            pass
    # Local fallback
    job = {
        "id": job_id, "connection_id": connection_id,
        "user_id": user_id, "org_id": org_id, "status": "pending",
        "emails_found": 0, "emails_analyzed": 0, "error_message": None,
        "started_at": None, "completed_at": None,
        "created_at": datetime.utcnow().isoformat(),
    }
    with _store_lock:
        jobs = _load_json(_scans_file(user_id))
        jobs.append(job)
        _save_json(_scans_file(user_id), jobs)
    return job_id

def scan_job_update(job_id: str, status: str, emails_found: int = 0,
                    emails_analyzed: int = 0, error_message: str = None):
    sb = get_supabase()
    if sb:
        try:
            data = {"status": status}
            if status == "running":
                data["started_at"] = datetime.utcnow().isoformat()
            if status in ("completed", "failed"):
                data["completed_at"] = datetime.utcnow().isoformat()
            if emails_found:
                data["emails_found"] = emails_found
            if emails_analyzed:
                data["emails_analyzed"] = emails_analyzed
            if error_message:
                data["error_message"] = error_message
            sb.table("scan_jobs").update(data).eq("id", job_id).execute()
            return
        except Exception:
            pass
    # Local fallback
    for user_dir in os.listdir(DATA_DIR):
        fpath = os.path.join(DATA_DIR, user_dir, "scan_jobs.json")
        if os.path.isfile(fpath):
            with _store_lock:
                jobs = _load_json(fpath)
                for j in jobs:
                    if j["id"] == job_id:
                        j["status"] = status
                        if status == "running":
                            j["started_at"] = datetime.utcnow().isoformat()
                        if status in ("completed", "failed"):
                            j["completed_at"] = datetime.utcnow().isoformat()
                        if emails_found:
                            j["emails_found"] = emails_found
                        if emails_analyzed:
                            j["emails_analyzed"] = emails_analyzed
                        if error_message:
                            j["error_message"] = error_message
                        _save_json(fpath, jobs)
                        return

def scan_job_list(user_id: str, limit: int = 20) -> List[dict]:
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("scan_jobs").select(
                "id,status,emails_found,emails_analyzed,error_message,started_at,completed_at,created_at"
            ).eq("user_id", user_id).order("created_at", desc=True).limit(limit).execute()
            return result.data or []
        except Exception:
            pass
    jobs = _load_json(_scans_file(user_id))
    jobs.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return jobs[:limit]

# ============================================================================
# INVITES
# ============================================================================

def _invites_file_path() -> str:
    return os.path.join(DATA_DIR, "invites.json")

def invite_create(org_id: str, email: str, role: str, invited_by: str) -> Optional[dict]:
    sb = get_supabase()
    token = str(uuid.uuid4()).replace("-", "")
    expires = (datetime.utcnow() + timedelta(days=7)).isoformat()
    if sb:
        try:
            result = sb.table("invites").insert({
                "org_id": org_id, "email": email, "role": role,
                "invited_by": invited_by, "token": token, "expires_at": expires,
            }).execute()
            return result.data[0] if result.data else {"token": token}
        except Exception:
            pass
    # Local fallback
    invite = {
        "id": str(uuid.uuid4()), "org_id": org_id, "email": email,
        "role": role, "invited_by": invited_by, "token": token,
        "expires_at": expires, "accepted_at": None,
        "created_at": datetime.utcnow().isoformat(),
    }
    with _store_lock:
        invites = _load_json(_invites_file_path())
        invites.append(invite)
        _save_json(_invites_file_path(), invites)
    return invite

def invite_get_by_token(token: str) -> Optional[dict]:
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("invites").select("*").eq("token", token).is_("accepted_at", "null").execute()
            invite = result.data[0] if result.data else None
            if invite and invite.get("expires_at"):
                if datetime.fromisoformat(invite["expires_at"].replace("Z", "+00:00")).replace(tzinfo=None) < datetime.utcnow():
                    return None
            return invite
        except Exception:
            pass
    invites = _load_json(_invites_file_path())
    for inv in invites:
        if inv["token"] == token and not inv.get("accepted_at"):
            if inv.get("expires_at") and datetime.fromisoformat(inv["expires_at"]) < datetime.utcnow():
                return None
            return inv
    return None

def invite_accept(token: str, user_id: str) -> bool:
    sb = get_supabase()
    if sb:
        try:
            invite = invite_get_by_token(token)
            if not invite:
                return False
            sb.table("users").update({"org_id": invite["org_id"], "role": invite["role"]}).eq("id", user_id).execute()
            sb.table("invites").update({"accepted_at": datetime.utcnow().isoformat()}).eq("token", token).execute()
            return True
        except Exception:
            pass
    # Local fallback
    invite = invite_get_by_token(token)
    if not invite:
        return False
    with _store_lock:
        invites = _load_json(_invites_file_path())
        for inv in invites:
            if inv["token"] == token:
                inv["accepted_at"] = datetime.utcnow().isoformat()
                _save_json(_invites_file_path(), invites)
                break
    return True

def invite_list_org(org_id: str) -> List[dict]:
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("invites").select("id,email,role,accepted_at,expires_at,created_at").eq("org_id", org_id).is_("accepted_at", "null").execute()
            return result.data or []
        except Exception:
            pass
    invites = _load_json(_invites_file_path())
    return [i for i in invites if i.get("org_id") == org_id and not i.get("accepted_at")]

def invite_delete(invite_id: str, org_id: str) -> bool:
    sb = get_supabase()
    if sb:
        try:
            sb.table("invites").delete().eq("id", invite_id).eq("org_id", org_id).execute()
            return True
        except Exception:
            pass
    with _store_lock:
        invites = _load_json(_invites_file_path())
        new_invites = [i for i in invites if i["id"] != invite_id]
        if len(new_invites) < len(invites):
            _save_json(_invites_file_path(), new_invites)
            return True
    return False

# ============================================================================
# REPORTED EMAIL OPERATIONS
# ============================================================================

def report_save(email_id: str, user_id: str, record: dict, org_id: str = None):
    sb = get_supabase()
    if not sb:
        return
    if not org_id:
        org_id = get_or_create_default_org()
    if not org_id:
        return
    try:
        ai_analysis = record.get("verdict", {})
        sb.table("reported_emails").upsert({
            "id": email_id,
            "org_id": org_id,
            "user_id": user_id,
            "sender": record.get("from_address", ""),
            "subject": record.get("subject", "(no subject)"),
            "raw_body": record.get("body_text", ""),
            "ai_risk_score": round((ai_analysis.get("confidence", 0) or 0) * 100, 1),
            "ai_analysis": ai_analysis,
            "urls": record.get("urls", []),
            "has_attachments": record.get("has_attachments", False),
            "created_at": record.get("received_at", datetime.now().isoformat()),
        }).execute()
    except Exception as e:
        print(f"[SENTINEL] report_save failed: {e}", flush=True)

def report_list(user_id: str = None, org_id: str = None,
                threat_level: str = None, limit: int = 100) -> List[dict]:
    sb = get_supabase()
    if not sb:
        return []
    try:
        query = sb.table("reported_emails").select("*")
        if org_id:
            query = query.eq("org_id", org_id)
        if user_id:
            query = query.eq("user_id", user_id)
        if threat_level:
            query = query.eq("ai_analysis->>threat_level", threat_level)
        query = query.order("created_at", desc=True).limit(limit)
        result = query.execute()
        return result.data or []
    except Exception as e:
        print(f"[SENTINEL] report_list failed: {e}", flush=True)
        return []

def report_delete_all(user_id: str = None, org_id: str = None) -> int:
    sb = get_supabase()
    if not sb:
        return 0
    try:
        query = sb.table("reported_emails").delete()
        if org_id:
            query = query.eq("org_id", org_id)
        if user_id:
            query = query.eq("user_id", user_id)
        query.execute()
        return -1
    except Exception as e:
        print(f"[SENTINEL] report_delete_all failed: {e}", flush=True)
        return 0

def report_get_stats(org_id: str = None) -> dict:
    sb = get_supabase()
    if not sb:
        return {"total": 0, "malicious": 0, "suspicious": 0, "safe": 0}
    try:
        query = sb.table("reported_emails").select("ai_analysis")
        if org_id:
            query = query.eq("org_id", org_id)
        result = query.execute()
        emails = result.data or []
        total = len(emails)
        malicious = sum(1 for e in emails if (e.get("ai_analysis") or {}).get("threat_level") == "malicious")
        suspicious = sum(1 for e in emails if (e.get("ai_analysis") or {}).get("threat_level") == "suspicious")
        safe = sum(1 for e in emails if (e.get("ai_analysis") or {}).get("threat_level") == "safe")
        return {"total": total, "malicious": malicious, "suspicious": suspicious, "safe": safe}
    except Exception as e:
        print(f"[SENTINEL] report_get_stats failed: {e}", flush=True)
        return {"total": 0, "malicious": 0, "suspicious": 0, "safe": 0}

# ============================================================================
# FEEDBACK OPERATIONS
# ============================================================================

def feedback_save(email_id: str, user_id: str, org_id: str,
                  original_verdict: str, corrected_verdict: str, reason: str = "",
                  sender_domain: str = "", sender_address: str = "") -> bool:
    sb = get_supabase()
    if sb:
        try:
            sb.table("feedback_logs").insert({
                "email_id": email_id,
                "org_id": org_id,
                "user_id": user_id,
                "original_verdict": original_verdict,
                "corrected_verdict": corrected_verdict,
                "reason": reason,
            }).execute()
            # Also save to user_feedback table for adaptive heuristics
            try:
                fb_type = "false_positive" if original_verdict == "malicious" and corrected_verdict == "safe" else \
                          "false_negative" if original_verdict == "safe" and corrected_verdict == "malicious" else "correction"
                sb.table("user_feedback").insert({
                    "email_id": email_id,
                    "org_id": org_id,
                    "user_id": user_id,
                    "original_verdict": original_verdict,
                    "corrected_verdict": corrected_verdict,
                    "sender_domain": sender_domain,
                    "sender_address": sender_address,
                    "reason": reason,
                    "feedback_type": fb_type,
                }).execute()
            except Exception:
                pass
            _check_feedback_whitelist(email_id, corrected_verdict, org_id)
            # Update adaptive heuristics cache
            try:
                feedback_cache.record_feedback(org_id, sender_domain, sender_address, corrected_verdict)
            except Exception:
                pass
            return True
        except Exception as e:
            print(f"[SENTINEL] feedback_save failed: {e}", flush=True)
    ok = feedback_save_local(email_id, user_id, original_verdict, corrected_verdict, reason,
                             sender_domain=sender_domain, sender_address=sender_address)
    if ok and corrected_verdict == "safe":
        _check_feedback_whitelist_local(email_id, corrected_verdict, user_id)
    try:
        feedback_cache.record_feedback(org_id or "", sender_domain, sender_address, corrected_verdict)
    except Exception:
        pass
    return ok

def feedback_list(user_id: str = None, org_id: str = None, limit: int = 50) -> List[dict]:
    sb = get_supabase()
    if sb:
        try:
            query = sb.table("feedback_logs").select("*")
            if org_id:
                query = query.eq("org_id", org_id)
            result = query.order("created_at", desc=True).limit(limit).execute()
            return result.data or []
        except Exception as e:
            print(f"[SENTINEL] feedback_list failed: {e}", flush=True)
    return feedback_list_local(user_id=user_id or "_global", limit=limit)

def _check_feedback_whitelist(email_id: str, corrected_verdict: str, org_id: str):
    if corrected_verdict != "safe":
        return
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("reported_emails").select("sender").eq("id", email_id).execute()
            if not result.data:
                return
            sender = result.data[0].get("sender", "")
            domain = sender.split("@")[-1] if "@" in sender else ""
            if not domain or domain in ("gmail.com", "outlook.com", "yahoo.com", "hotmail.com"):
                return
            existing = sb.table("whitelist").select("id").eq("org_id", org_id).eq("pattern_type", "domain").eq("pattern_value", domain).execute()
            if existing.data:
                sb.table("whitelist").update({"hit_count": existing.data[0].get("hit_count", 0) + 1}).eq("id", existing.data[0]["id"]).execute()
            else:
                sb.table("whitelist").insert({
                    "org_id": org_id, "pattern_type": "domain",
                    "pattern_value": domain, "added_by": "system", "source": "feedback_auto",
                }).execute()
        except Exception as e:
            print(f"[SENTINEL] whitelist auto-update failed: {e}", flush=True)

def _check_feedback_whitelist_local(email_id: str, corrected_verdict: str, user_id: str = "_global"):
    if corrected_verdict != "safe":
        return
    user_path = os.path.join(DATA_DIR, user_id, "email_data.json")
    if os.path.isfile(user_path):
        try:
            with open(user_path, "r", encoding="utf-8") as f:
                store = json.load(f)
            if email_id in store:
                sender = store[email_id].get("from_address", "")
                domain = sender.split("@")[-1] if "@" in sender else ""
                if domain and domain not in ("gmail.com", "outlook.com", "yahoo.com", "hotmail.com"):
                    whitelist_add_local("domain", domain, "feedback_auto", user_id=user_id)
        except Exception:
            pass

# ============================================================================
# WHITELIST OPERATIONS
# ============================================================================

def whitelist_get(org_id: str, user_id: str = None) -> List[dict]:
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("whitelist").select("*").eq("org_id", org_id).execute()
            return result.data or []
        except Exception:
            pass
    return whitelist_get_local(user_id=user_id or "_global")

def whitelist_check(org_id: str, sender: str = "", domain: str = "") -> dict:
    sb = get_supabase()
    if not sb:
        return {"matched": False}
    try:
        entries = whitelist_get(org_id)
        for entry in entries:
            if entry["pattern_type"] == "domain" and domain and domain.lower() == entry["pattern_value"].lower():
                return {"matched": True, "type": "domain", "value": entry["pattern_value"], "source": entry["source"]}
            if entry["pattern_type"] == "sender" and sender and sender.lower() == entry["pattern_value"].lower():
                return {"matched": True, "type": "sender", "value": entry["pattern_value"], "source": entry["source"]}
        return {"matched": False}
    except Exception:
        return {"matched": False}

def whitelist_add(org_id: str, pattern_type: str, pattern_value: str, added_by: str = "manual", user_id: str = None) -> bool:
    sb = get_supabase()
    if sb:
        try:
            sb.table("whitelist").upsert({
                "org_id": org_id, "pattern_type": pattern_type,
                "pattern_value": pattern_value, "added_by": added_by, "source": "manual",
            }).execute()
            return True
        except Exception as e:
            print(f"[SENTINEL] whitelist_add failed: {e}", flush=True)
    return whitelist_add_local(pattern_type, pattern_value, added_by, user_id=user_id or "_global")

def whitelist_delete(org_id: str, entry_id: str, user_id: str = None) -> bool:
    sb = get_supabase()
    if sb:
        try:
            sb.table("whitelist").delete().eq("id", entry_id).eq("org_id", org_id).execute()
            return True
        except Exception:
            pass
    return whitelist_delete_local(entry_id, user_id=user_id or "_global")

# ============================================================================
# REPORTING / ANALYTICS
# ============================================================================

def reporting_monthly(org_id: str = None, months_back: int = 1) -> dict:
    sb = get_supabase()
    if not sb:
        return {"total": 0, "malicious": 0, "suspicious": 0, "safe": 0,
                "top_targets": [], "top_senders": [], "estimated_cost": 0,
                "period_start": "", "period_end": ""}
    try:
        cutoff = (datetime.utcnow() - timedelta(days=30 * months_back)).isoformat()
        query = sb.table("reported_emails").select("*")
        if org_id:
            query = query.eq("org_id", org_id)
        query = query.gte("created_at", cutoff)
        result = query.execute()
        emails = result.data or []
        total = len(emails)
        malicious = [e for e in emails if (e.get("ai_analysis") or {}).get("threat_level") == "malicious"]
        suspicious = [e for e in emails if (e.get("ai_analysis") or {}).get("threat_level") == "suspicious"]
        safe = [e for e in emails if (e.get("ai_analysis") or {}).get("threat_level") == "safe"]
        user_counts = {}
        for e in emails:
            uid = e.get("user_id", "unknown")
            user_counts[uid] = user_counts.get(uid, 0) + 1
        top_targets = sorted(user_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        domain_counts = {}
        for e in malicious:
            sender = e.get("sender", "")
            domain = sender.split("@")[-1] if "@" in sender else sender
            domain_counts[domain] = domain_counts.get(domain, 0) + 1
        top_senders = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        period_start = emails[-1]["created_at"] if emails else cutoff
        period_end = emails[0]["created_at"] if emails else datetime.utcnow().isoformat()
        return {
            "total": total, "malicious": len(malicious), "suspicious": len(suspicious), "safe": len(safe),
            "top_targets": top_targets, "top_senders": top_senders,
            "period_start": period_start, "period_end": period_end,
        }
    except Exception as e:
        print(f"[SENTINEL] reporting_monthly failed: {e}", flush=True)
        return {"total": 0, "malicious": 0, "suspicious": 0, "safe": 0,
                "top_targets": [], "top_senders": [], "period_start": "", "period_end": ""}

# ============================================================================
# LEADS (Public Health Check Lead Capture)
# ============================================================================

def lead_save(email: str, source: str = "health_check", org_name: str = "",
              health_check_result: dict = None) -> Optional[dict]:
    """Save a lead from the public health check widget."""
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("leads").insert({
                "email": email,
                "source": source,
                "org_name": org_name,
                "health_check_result": health_check_result or {},
            }).execute()
            return result.data[0] if result.data else None
        except Exception:
            pass
    # Local fallback
    lead = {
        "id": str(uuid.uuid4()),
        "email": email,
        "source": source,
        "org_name": org_name,
        "health_check_result": health_check_result or {},
        "converted": False,
        "created_at": datetime.now().isoformat(),
    }
    leads_path = os.path.join(DATA_DIR, "leads.json")
    leads = _load_json(leads_path)
    leads.append(lead)
    _save_json(leads_path, leads)
    return lead

def lead_exists(email: str) -> bool:
    """Check if a lead email already exists."""
    sb = get_supabase()
    if sb:
        try:
            result = sb.table("leads").select("id").eq("email", email).limit(1).execute()
            return bool(result.data)
        except Exception:
            pass
    leads = _load_json(os.path.join(DATA_DIR, "leads.json"))
    return any(l.get("email") == email for l in leads)

# ============================================================================
# ENHANCED REPORTING (for PDF generation)
# ============================================================================

def reporting_monthly_enhanced(org_id: str = None, months_back: int = 1, cost_per_incident: float = 4500.0) -> dict:
    """Enhanced monthly report with feedback stats, estimated cost, and org info."""
    base = reporting_monthly(org_id, months_back)

    # Add cost calculation
    threats_blocked = base.get("malicious", 0) + base.get("suspicious", 0)
    base["threats_blocked"] = threats_blocked
    base["estimated_cost_prevented"] = threats_blocked * cost_per_incident
    base["cost_per_incident"] = cost_per_incident

    # Add feedback stats
    sb = get_supabase()
    if sb and org_id:
        try:
            cutoff = (datetime.utcnow() - timedelta(days=30 * months_back)).isoformat()
            fb_result = sb.table("user_feedback").select("*").eq("org_id", org_id).gte("created_at", cutoff).execute()
            feedbacks = fb_result.data or []
            base["feedback_count"] = len(feedbacks)
            base["false_positives"] = len([f for f in feedbacks if f.get("feedback_type") == "false_positive"])
            base["false_negatives"] = len([f for f in feedbacks if f.get("feedback_type") == "false_negative"])
            # Get unique users who were targeted
            targeted_users = set()
            for e in (base.get("top_targets") or []):
                targeted_users.add(e[0])
            base["unique_targets"] = len(targeted_users)
        except Exception:
            base["feedback_count"] = 0
            base["false_positives"] = 0
            base["false_negatives"] = 0
            base["unique_targets"] = len(base.get("top_targets", []))
    else:
        base["feedback_count"] = 0
        base["false_positives"] = 0
        base["false_negatives"] = 0
        base["unique_targets"] = len(base.get("top_targets", []))

    # Add org info
    if org_id:
        org = org_get(org_id)
        base["org_name"] = org.get("name", "Unknown Organization") if org else "Unknown Organization"
    else:
        base["org_name"] = "Unknown Organization"

    return base

# ============================================================================
# LOCAL FALLBACK STORAGE (SQLite + JSON)
# ============================================================================

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
os.makedirs(DATA_DIR, exist_ok=True)

def _user_data_path(user_id: str) -> str:
    user_dir = os.path.join(DATA_DIR, user_id)
    os.makedirs(user_dir, exist_ok=True)
    return os.path.join(user_dir, "email_data.json")

def _load_user_store(user_id: str) -> Dict[str, dict]:
    path = _user_data_path(user_id)
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}

def _save_user_store(user_id: str, store: Dict[str, dict]):
    try:
        with open(_user_data_path(user_id), "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[SENTINEL] Failed to save data for user {user_id}: {e}", flush=True)

def store_get(user_id: str) -> Dict[str, dict]:
    return _load_user_store(user_id)

def store_set(user_id: str, email_id: str, record: dict):
    if is_supabase_available():
        report_save(email_id, user_id, record)
    with _store_lock:
        store = _load_user_store(user_id)
        store[email_id] = record
        _save_user_store(user_id, store)

def store_clear(user_id: str):
    if is_supabase_available():
        report_delete_all(user_id=user_id)
    with _store_lock:
        _save_user_store(user_id, {})

# ============================================================================
# LOCAL FALLBACK: USERS (SQLite)
# ============================================================================

import sqlite3 as _sqlite3
import re as _re

_USERS_DB = os.path.join(DATA_DIR, "users.db")

def _get_users_db():
    conn = _sqlite3.connect(_USERS_DB)
    conn.row_factory = _sqlite3.Row
    return conn

def _init_users_db():
    conn = _get_users_db()
    conn.execute("""CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL, created_at TEXT NOT NULL
    )""")
    for col, default in [
        ("role", "'member'"), ("org_id", "NULL"), ("is_active", "1"), ("last_login", "NULL"),
    ]:
        # Defense-in-depth: these are hardcoded, but never build DDL from an
        # identifier that isn't a plain [a-z_] name (blocks SQL injection if this
        # list is ever fed from a variable/user input in future).
        if not _re.fullmatch(r"[a-z_][a-z0-9_]*", col):
            continue
        try:
            conn.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT DEFAULT {default}")
        except Exception:
            pass
    conn.commit()
    conn.close()

_init_users_db()

def user_create_local(username: str, email: str, password_hash: str, user_id: str = None) -> Optional[dict]:
    if not user_id:
        user_id = str(uuid.uuid4())
    try:
        conn = _get_users_db()
        conn.execute("INSERT INTO users (id, username, email, password_hash, created_at) VALUES (?,?,?,?,?)",
                     (user_id, username, email, password_hash, datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
        return {"id": user_id, "username": username, "email": email}
    except Exception:
        return None

def user_get_by_username_local(username: str) -> Optional[dict]:
    try:
        conn = _get_users_db()
        row = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None

def user_get_by_id_local(user_id: str) -> Optional[dict]:
    try:
        conn = _get_users_db()
        row = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
        conn.close()
        return dict(row) if row else None
    except Exception:
        return None

# ============================================================================
# LOCAL FALLBACK: FEEDBACK & WHITELIST (JSON)
# ============================================================================

def _feedback_file(user_id: str = "_global") -> str:
    user_dir = os.path.join(DATA_DIR, user_id)
    os.makedirs(user_dir, exist_ok=True)
    return os.path.join(user_dir, "feedback_logs.json")

def _whitelist_file(user_id: str = "_global") -> str:
    user_dir = os.path.join(DATA_DIR, user_id)
    os.makedirs(user_dir, exist_ok=True)
    return os.path.join(user_dir, "whitelist.json")

def _load_json(path: str) -> list:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return []

def _save_json(path: str, data: list):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def feedback_save_local(email_id: str, user_id: str, original_verdict: str,
                        corrected_verdict: str, reason: str = "",
                        sender_domain: str = "", sender_address: str = "") -> bool:
    with _store_lock:
        entries = _load_json(_feedback_file(user_id))
        entries.append({
            "id": str(uuid.uuid4()), "email_id": email_id, "user_id": user_id,
            "org_id": _LOCAL_ORG_ID, "original_verdict": original_verdict,
            "corrected_verdict": corrected_verdict, "reason": reason,
            "sender_domain": sender_domain, "sender_address": sender_address,
            "created_at": datetime.now().isoformat(),
        })
        _save_json(_feedback_file(user_id), entries)
    return True

def feedback_list_local(user_id: str = "_global", limit: int = 50) -> list:
    entries = _load_json(_feedback_file(user_id))
    entries.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return entries[:limit]

def whitelist_add_local(pattern_type: str, pattern_value: str, added_by: str = "manual", user_id: str = "_global") -> bool:
    with _store_lock:
        entries = _load_json(_whitelist_file(user_id))
        for e in entries:
            if e.get("pattern_type") == pattern_type and e.get("pattern_value") == pattern_value:
                e["hit_count"] = e.get("hit_count", 0) + 1
                _save_json(_whitelist_file(user_id), entries)
                return True
        entries.append({
            "id": str(uuid.uuid4()), "org_id": _LOCAL_ORG_ID,
            "pattern_type": pattern_type, "pattern_value": pattern_value,
            "added_by": added_by, "source": "manual", "hit_count": 0,
            "created_at": datetime.now().isoformat(),
        })
        _save_json(_whitelist_file(user_id), entries)
    return True

def whitelist_get_local(user_id: str = "_global") -> list:
    return _load_json(_whitelist_file(user_id))

def whitelist_delete_local(entry_id: str, user_id: str = "_global") -> bool:
    with _store_lock:
        entries = _load_json(_whitelist_file(user_id))
        entries = [e for e in entries if e.get("id") != entry_id]
        _save_json(_whitelist_file(user_id), entries)
    return True


# ============================================================================
# FEEDBACK CACHE (Adaptive Heuristics Engine)
# ============================================================================
# In-memory cache that intercepts scans before hitting the LLM API.
# Checks if a sender domain has been explicitly marked Safe (whitelisted)
# or Malicious (blacklisted) by admin feedback. Saves API tokens and
# provides instant verdicts for known patterns.

class FeedbackCache:
    """
    Adaptive heuristics cache. Per-org lookup tables for:
      - safe_domains: set of domains explicitly marked safe by admin feedback
      - malicious_domains: set of domains explicitly marked malicious by admin feedback
      - safe_senders: set of full sender addresses marked safe
      - malicious_senders: set of full sender addresses marked malicious

    Usage:
        cache = FeedbackCache()
        result = cache.check("paypal.com", "security@paypal.com")
        if result:
            return result  # Pre-computed verdict, skip LLM
        # ... call LLM ...
        # After scan, if user corrects verdict:
        cache.record_feedback(org_id, "paypal.com", "security@paypal.com", "safe")
    """

    def __init__(self):
        self._cache = {}  # org_id -> {safe_domains, malicious_domains, safe_senders, malicious_senders}
        self._last_refresh = {}  # org_id -> timestamp
        self._refresh_interval = 300  # 5 minutes

    def _ensure_org(self, org_id: str):
        """Ensure org entry exists in cache."""
        if org_id not in self._cache:
            self._cache[org_id] = {
                "safe_domains": set(),
                "malicious_domains": set(),
                "safe_senders": set(),
                "malicious_senders": set(),
            }

    def refresh(self, org_id: str, force: bool = False):
        """Refresh cache for an org from the database. Rate-limited to every 5 min."""
        import time
        now = time.time()
        if not force and org_id in self._last_refresh:
            if now - self._last_refresh[org_id] < self._refresh_interval:
                return

        self._ensure_org(org_id)
        entry = self._cache[org_id]

        # Load from Supabase
        sb = get_supabase()
        if sb:
            try:
                result = sb.table("whitelist").select("pattern_type,pattern_value").eq("org_id", org_id).execute()
                rows = result.data or []
                entry["safe_domains"] = set()
                entry["malicious_domains"] = set()
                entry["safe_senders"] = set()
                entry["malicious_senders"] = set()
                for row in rows:
                    pt = row.get("pattern_type", "")
                    pv = row.get("pattern_value", "").lower()
                    if pt == "domain" or pt == "safe_domain":
                        entry["safe_domains"].add(pv)
                    elif pt == "malicious_domain":
                        entry["malicious_domains"].add(pv)
                    elif pt == "sender":
                        entry["safe_senders"].add(pv)
                # Also load from user_feedback aggregation
                fb_result = sb.table("user_feedback").select("sender_domain,sender_address,corrected_verdict").eq("org_id", org_id).execute()
                for fb in (fb_result.data or []):
                    domain = (fb.get("sender_domain") or "").lower()
                    sender = (fb.get("sender_address") or "").lower()
                    verdict = fb.get("corrected_verdict", "")
                    if verdict == "safe" and domain:
                        entry["safe_domains"].add(domain)
                        if sender:
                            entry["safe_senders"].add(sender)
                    elif verdict == "malicious" and domain:
                        entry["malicious_domains"].add(domain)
                        if sender:
                            entry["malicious_senders"].add(sender)
                self._last_refresh[org_id] = now
                return
            except Exception:
                pass

        # Local fallback: load from JSON whitelist + feedback files
        try:
            wl_entries = whitelist_get_local()
            entry["safe_domains"] = set()
            entry["malicious_domains"] = set()
            entry["safe_senders"] = set()
            entry["malicious_senders"] = set()
            for wl in wl_entries:
                pt = wl.get("pattern_type", "")
                pv = wl.get("pattern_value", "").lower()
                if pt == "domain" or pt == "safe_domain":
                    entry["safe_domains"].add(pv)
                elif pt == "malicious_domain":
                    entry["malicious_domains"].add(pv)
                elif pt == "sender":
                    entry["safe_senders"].add(pv)
            fb_entries = feedback_list_local()
            for fb in fb_entries:
                domain = (fb.get("sender_domain") or "").lower()
                sender = (fb.get("sender_address") or "").lower()
                verdict = fb.get("corrected_verdict", "")
                if verdict == "safe" and domain:
                    entry["safe_domains"].add(domain)
                    if sender:
                        entry["safe_senders"].add(sender)
                elif verdict == "malicious" and domain:
                    entry["malicious_domains"].add(domain)
                    if sender:
                        entry["malicious_senders"].add(sender)
        except Exception:
            pass

        self._last_refresh[org_id] = now

    def check(self, sender_domain: str, sender_address: str = "", org_id: str = "") -> Optional[dict]:
        """
        Check if sender is in the adaptive cache.
        Returns a verdict dict if found, None if not (proceed to LLM).
        """
        if not org_id:
            return None
        self.refresh(org_id)
        entry = self._cache.get(org_id, {})
        domain = sender_domain.lower().strip()
        sender = sender_address.lower().strip()

        # Check blacklist first (higher priority)
        if domain in entry.get("malicious_domains", set()) or sender in entry.get("malicious_senders", set()):
            return {
                "verdict": "malicious",
                "threat_level": "malicious",
                "confidence_score": 95.0,
                "confidence": 0.95,
                "reasoning": f"Domain '{domain}' has been explicitly flagged as malicious by your organization's admin. This sender pattern was previously identified as a threat.",
                "indicators": [f"Domain '{domain}' is blacklisted by admin feedback"],
                "recommendations": ["Block this sender domain at your mail gateway", "Do not interact with emails from this domain"],
                "social_engineering_tactics": {},
                "technical_indicators": {},
                "llm_model": "adaptive-heuristics-cache",
                "cached": True,
            }

        # Check whitelist
        if domain in entry.get("safe_domains", set()) or sender in entry.get("safe_senders", set()):
            return {
                "verdict": "safe",
                "threat_level": "safe",
                "confidence_score": 92.0,
                "confidence": 0.92,
                "reasoning": f"Domain '{domain}' has been verified as safe by your organization's admin. This sender pattern was previously reviewed and approved.",
                "indicators": [f"Domain '{domain}' is whitelisted by admin feedback"],
                "recommendations": ["No action required - email is from a verified safe sender"],
                "social_engineering_tactics": {},
                "technical_indicators": {},
                "llm_model": "adaptive-heuristics-cache",
                "cached": True,
            }

        return None

    def record_feedback(self, org_id: str, sender_domain: str, sender_address: str, corrected_verdict: str):
        """Update the in-memory cache after feedback is submitted."""
        self.refresh(org_id, force=True)

    def get_stats(self, org_id: str) -> dict:
        """Return cache statistics for an org."""
        self.refresh(org_id)
        entry = self._cache.get(org_id, {})
        return {
            "safe_domains": len(entry.get("safe_domains", set())),
            "malicious_domains": len(entry.get("malicious_domains", set())),
            "safe_senders": len(entry.get("safe_senders", set())),
            "malicious_senders": len(entry.get("malicious_senders", set())),
        }


# Global cache instance
feedback_cache = FeedbackCache()

# ============================================================================
# REQUEST LOGGING & ANALYTICS
# ============================================================================

def _init_request_logs_db():
    conn = _sqlite3.connect(_USERS_DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS request_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT NOT NULL,
        path TEXT NOT NULL,
        method TEXT NOT NULL,
        user_agent TEXT,
        country TEXT DEFAULT '',
        region TEXT DEFAULT '',
        city TEXT DEFAULT '',
        device_type TEXT DEFAULT '',
        browser TEXT DEFAULT '',
        os TEXT DEFAULT '',
        user_id TEXT DEFAULT '',
        username TEXT DEFAULT '',
        response_status INTEGER DEFAULT 200,
        created_at TEXT NOT NULL
    )""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_created_at ON request_logs(created_at)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_ip ON request_logs(ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_request_logs_path ON request_logs(path)")
    conn.commit()
    conn.close()

_init_request_logs_db()

def request_log_save(ip: str, path: str, method: str, user_agent: str,
                     country: str = "", region: str = "", city: str = "",
                     device_type: str = "", browser: str = "", os_name: str = "",
                     user_id: str = "", username: str = "", response_status: int = 200):
    sb = get_supabase()
    if sb:
        try:
            sb.table("request_logs").insert({
                "ip_address": ip, "path": path, "method": method, "user_agent": user_agent,
                "country": country, "region": region, "city": city,
                "device_type": device_type, "browser": browser, "os": os_name,
                "user_id": user_id, "username": username,
                "created_at": datetime.utcnow().isoformat(),
            }).execute()
            return
        except Exception:
            pass
    # Local fallback
    try:
        conn = _sqlite3.connect(_USERS_DB)
        conn.execute(
            "INSERT INTO request_logs (ip,path,method,user_agent,country,region,city,device_type,browser,os,user_id,username,response_status,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (ip, path, method, user_agent, country, region, city, device_type, browser, os_name, user_id, username, response_status, datetime.utcnow().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def request_log_stats(days: int = 30) -> dict:
    """Get analytics stats for the last N days."""
    sb = get_supabase()
    since = (datetime.utcnow() - timedelta(days=days)).isoformat()

    if sb:
        try:
            rows = sb.table("request_logs").select("*").gte("created_at", since).execute()
            data = rows.data or []
        except Exception:
            data = []
    else:
        try:
            conn = _sqlite3.connect(_USERS_DB)
            conn.row_factory = _sqlite3.Row
            rows = conn.execute("SELECT * FROM request_logs WHERE created_at >= ?", (since,)).fetchall()
            data = [dict(r) for r in rows]
            conn.close()
        except Exception:
            data = []

    total = len(data)
    unique_ips = len(set(r.get("ip_address", r.get("ip", "")) for r in data))
    unique_users = len(set(r.get("user_id", "") for r in data if r.get("user_id")))

    countries = {}
    regions = {}
    cities = {}
    devices = {}
    browsers = {}
    oses = {}
    hours = {str(h): 0 for h in range(24)}
    days_of_week = {}
    paths = {}

    for r in data:
        c = r.get("country") or "Unknown"
        countries[c] = countries.get(c, 0) + 1
        reg = r.get("region") or "Unknown"
        regions[reg] = regions.get(reg, 0) + 1
        ci = r.get("city") or "Unknown"
        cities[ci] = cities.get(ci, 0) + 1
        d = r.get("device_type") or "Unknown"
        devices[d] = devices.get(d, 0) + 1
        b = r.get("browser") or "Unknown"
        browsers[b] = browsers.get(b, 0) + 1
        o = r.get("os") or "Unknown"
        oses[o] = oses.get(o, 0) + 1
        p = r.get("path") or "/"
        paths[p] = paths.get(p, 0) + 1

        ts = r.get("created_at", "")
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            hours[str(dt.hour)] = hours.get(str(dt.hour), 0) + 1
            dow = dt.strftime("%A")
            days_of_week[dow] = days_of_week.get(dow, 0) + 1
        except Exception:
            pass

    return {
        "total_requests": total,
        "unique_ips": unique_ips,
        "unique_users": unique_users,
        "period_days": days,
        "countries": countries,
        "regions": regions,
        "cities": cities,
        "devices": devices,
        "browsers": browsers,
        "oses": oses,
        "hourly_distribution": hours,
        "daily_distribution": days_of_week,
        "top_paths": dict(sorted(paths.items(), key=lambda x: -x[1])[:20]),
    }

def request_log_unique_ips(days: int = 7) -> List[dict]:
    """Get unique IPs with their info for the last N days."""
    sb = get_supabase()
    since = (datetime.utcnow() - timedelta(days=days)).isoformat()
    if sb:
        try:
            rows = sb.table("request_logs").select("ip_address,country,region,city,device_type,browser,os,created_at").gte("created_at", since).execute()
            data = rows.data or []
        except Exception:
            data = []
    else:
        try:
            conn = _sqlite3.connect(_USERS_DB)
            conn.row_factory = _sqlite3.Row
            rows = conn.execute("SELECT ip,country,region,city,device_type,browser,os,created_at FROM request_logs WHERE created_at >= ?", (since,)).fetchall()
            data = [dict(r) for r in rows]
            conn.close()
        except Exception:
            data = []

    seen = {}
    for r in data:
        ip = r.get("ip_address", r.get("ip", ""))
        if ip not in seen:
            seen[ip] = {
                "ip": ip,
                "country": r.get("country", ""),
                "region": r.get("region", ""),
                "city": r.get("city", ""),
                "device_type": r.get("device_type", ""),
                "browser": r.get("browser", ""),
                "os": r.get("os", ""),
                "first_seen": r.get("created_at", ""),
                "last_seen": r.get("created_at", ""),
                "request_count": 0,
            }
        seen[ip]["request_count"] += 1
        ts = r.get("created_at", "")
        if ts < seen[ip]["first_seen"]:
            seen[ip]["first_seen"] = ts
        if ts > seen[ip]["last_seen"]:
            seen[ip]["last_seen"] = ts

    return sorted(seen.values(), key=lambda x: -x["request_count"])
