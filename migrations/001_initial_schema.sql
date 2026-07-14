-- SENTINEL Database Migration 001: Core Schema
-- Run this in Supabase SQL Editor: https://supabase.com/dashboard → SQL Editor
-- Creates: organizations, reported_emails, feedback_logs with RLS enabled

-- ============================================================================
-- ORGANIZATIONS (Multi-tenancy)
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
-- REPORTED EMAILS (System of Record for submissions)
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
-- FEEDBACK LOGS (User corrections for AI improvement)
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
-- WHITELIST (Auto-populated from feedback patterns)
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

-- ============================================================================
-- ROW-LEVEL SECURITY (RLS)
-- ============================================================================
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.reported_emails ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.feedback_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.whitelist ENABLE ROW LEVEL SECURITY;

-- Service role bypass (allows the backend to access all data)
CREATE POLICY "service_role_all_organizations" ON public.organizations
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "service_role_all_reported_emails" ON public.reported_emails
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "service_role_all_feedback_logs" ON public.feedback_logs
    FOR ALL USING (auth.role() = 'service_role');

CREATE POLICY "service_role_all_whitelist" ON public.whitelist
    FOR ALL USING (auth.role() = 'service_role');

-- ============================================================================
-- SEED DATA: Default organization for single-tenant mode
-- ============================================================================
INSERT INTO public.organizations (name, domain, sla_status)
VALUES ('Default Organization', 'sentinel.local', 'active')
ON CONFLICT (domain) DO NOTHING;
