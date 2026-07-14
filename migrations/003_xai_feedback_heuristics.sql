-- ============================================================================
-- SENTINEL Migration 003: XAI Feedback Loop + Adaptive Heuristics
-- ============================================================================
-- This migration adds:
--   1. user_feedback table for capturing AI verdict corrections
--   2. Enhanced whitelist with blacklist support for adaptive heuristics
--   3. leads table for public health check lead capture
-- ============================================================================

-- ============================================================================
-- 1. USER FEEDBACK TABLE (verdict corrections)
-- ============================================================================
-- Captures when a user disputes an AI verdict (false positive/negative).
-- This feeds the adaptive heuristics system.

CREATE TABLE IF NOT EXISTS user_feedback (
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

-- Indexes for fast lookups during scan preprocessing
CREATE INDEX IF NOT EXISTS idx_user_feedback_org ON user_feedback(org_id);
CREATE INDEX IF NOT EXISTS idx_user_feedback_user ON user_feedback(user_id);
CREATE INDEX IF NOT EXISTS idx_user_feedback_sender_domain ON user_feedback(sender_domain);
CREATE INDEX IF NOT EXISTS idx_user_feedback_corrected ON user_feedback(corrected_verdict);
CREATE INDEX IF NOT EXISTS idx_user_feedback_created ON user_feedback(created_at DESC);

-- ============================================================================
-- 2. ENHANCED WHITELIST (add blacklist support)
-- ============================================================================
-- Extend existing whitelist table to support 'blacklist' patterns.
-- The existing whitelist table already has pattern_type = 'domain' | 'sender' | 'subject_regex'.
-- We add a 'safe_domain' and 'malicious_domain' pattern_type for explicit override.

-- Add new pattern types to existing whitelist via comment (enforced in app code):
-- pattern_type can be: 'domain', 'sender', 'subject_regex', 'safe_domain', 'malicious_domain'

-- Add hit_count tracking column if not exists (already in schema)
-- Add last_hit_at for recency tracking
ALTER TABLE whitelist ADD COLUMN IF NOT EXISTS last_hit_at TIMESTAMPTZ;
ALTER TABLE whitelist ADD COLUMN IF NOT EXISTS notes TEXT DEFAULT '';

-- ============================================================================
-- 3. LEADS TABLE (public health check lead capture)
-- ============================================================================
-- Stores email addresses from the public Security Health Check widget.
-- Used for sales pipeline / lead generation.

CREATE TABLE IF NOT EXISTS leads (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL,
    org_name TEXT DEFAULT '',
    source TEXT DEFAULT 'health_check' CHECK (source IN ('health_check', 'marketing', 'demo_request')),
    health_check_result JSONB DEFAULT '{}',
    converted BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_leads_email ON leads(email);
CREATE INDEX IF NOT EXISTS idx_leads_source ON leads(source);
CREATE INDEX IF NOT EXISTS idx_leads_created ON leads(created_at DESC);

-- ============================================================================
-- 4. ORG SETTINGS TABLE (for per-org configuration)
-- ============================================================================
-- Stores org-level settings like cost_per_incident, custom rules, etc.

CREATE TABLE IF NOT EXISTS org_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID REFERENCES organizations(id) ON DELETE CASCADE UNIQUE,
    cost_per_incident REAL DEFAULT 4500.0,
    custom_whitelist_notes TEXT DEFAULT '',
    auto_whitelist_from_feedback BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_org_settings_org ON org_settings(org_id);

-- ============================================================================
-- RLS POLICIES
-- ============================================================================

ALTER TABLE user_feedback ENABLE ROW LEVEL SECURITY;
ALTER TABLE leads ENABLE ROW LEVEL SECURITY;
ALTER TABLE org_settings ENABLE ROW LEVEL SECURITY;

-- Service role bypass
CREATE POLICY "service_role_all_user_feedback" ON user_feedback FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "service_role_all_leads" ON leads FOR ALL USING (auth.role() = 'service_role');
CREATE POLICY "service_role_all_org_settings" ON org_settings FOR ALL USING (auth.role() = 'service_role');

-- Authenticated read/write (Supabase client will use service_role key, so these are fallbacks)
CREATE POLICY "auth_user_feedback" ON user_feedback FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "auth_leads" ON leads FOR ALL USING (auth.role() = 'authenticated');
CREATE POLICY "auth_org_settings" ON org_settings FOR ALL USING (auth.role() = 'authenticated');

-- ============================================================================
-- SEED: Default org settings
-- ============================================================================
INSERT INTO org_settings (org_id, cost_per_incident)
SELECT id, 4500.0 FROM organizations
WHERE domain = 'sentinel.local'
ON CONFLICT (org_id) DO NOTHING;
