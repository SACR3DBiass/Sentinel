-- SENTINEL Migration 002: Cloud SaaS Schema
-- Run this AFTER 001_initial_schema.sql
-- Adds: users, email_connections, invites, scan_jobs, forward_addresses

-- ============================================================================
-- USERS (Authentication & Multi-tenancy)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
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
-- EMAIL CONNECTIONS (Per-user IMAP credentials)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.email_connections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
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
-- FORWARD ADDRESSES (Central inbox for email forwarding)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.forward_addresses (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    forward_email TEXT NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ============================================================================
-- SCAN JOBS (Background IMAP scanning tracking)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.scan_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    connection_id UUID NOT NULL REFERENCES public.email_connections(id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
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
-- INVITES (Team invitation system)
-- ============================================================================
CREATE TABLE IF NOT EXISTS public.invites (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member')),
    invited_by UUID NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    token TEXT UNIQUE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_invites_org ON public.invites(org_id);
CREATE INDEX IF NOT EXISTS idx_invites_token ON public.invites(token);

-- ============================================================================
-- RLS POLICIES (new tables)
-- ============================================================================
ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_connections ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.forward_addresses ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.scan_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.invites ENABLE ROW LEVEL SECURITY;

CREATE POLICY "service_role_all_users" ON public.users
    FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "service_role_all_email_connections" ON public.email_connections
    FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "service_role_all_forward_addresses" ON public.forward_addresses
    FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "service_role_all_scan_jobs" ON public.scan_jobs
    FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "service_role_all_invites" ON public.invites
    FOR ALL USING (auth.role() = 'service_role');
