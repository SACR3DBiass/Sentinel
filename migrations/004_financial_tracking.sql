-- ============================================================================
-- SENTINEL Migration 004: Financial Tracking & Acquisition Metrics
-- Run in Supabase SQL Editor to add subscription_history, org_metrics,
-- conversions tables, plus volume queueing support.
-- ============================================================================

-- 14. SUBSCRIPTION HISTORY
CREATE TABLE IF NOT EXISTS public.subscription_history (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL CHECK (event_type IN ('signup', 'upgrade', 'downgrade', 'renewal', 'cancellation', 'reactivation', 'trial_start', 'trial_end')),
    plan_name TEXT NOT NULL DEFAULT 'free',
    monthly_amount NUMERIC(10,2) NOT NULL DEFAULT 0,
    billing_cycle TEXT DEFAULT 'monthly' CHECK (billing_cycle IN ('monthly', 'annual', 'one_time')),
    payment_status TEXT DEFAULT 'pending' CHECK (payment_status IN ('pending', 'paid', 'failed', 'refunded', 'cancelled')),
    stripe_subscription_id TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_sub_history_org ON public.subscription_history(org_id);
CREATE INDEX IF NOT EXISTS idx_sub_history_event ON public.subscription_history(event_type);
CREATE INDEX IF NOT EXISTS idx_sub_history_occurred ON public.subscription_history(occurred_at DESC);
CREATE INDEX IF NOT EXISTS idx_sub_history_plan ON public.subscription_history(plan_name);

-- 15. ORG METRICS (CAC, Churn, MRR snapshots)
CREATE TABLE IF NOT EXISTS public.org_metrics (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    period_start TIMESTAMPTZ NOT NULL,
    period_end TIMESTAMPTZ NOT NULL,
    mrr NUMERIC(10,2) NOT NULL DEFAULT 0,
    arr NUMERIC(10,2) NOT NULL DEFAULT 0,
    cac NUMERIC(10,2) NOT NULL DEFAULT 0,
    ltv NUMERIC(10,2) NOT NULL DEFAULT 0,
    churn_risk_score NUMERIC(5,2) NOT NULL DEFAULT 0,
    is_churned BOOLEAN NOT NULL DEFAULT FALSE,
    days_since_signup INTEGER NOT NULL DEFAULT 0,
    total_emails_analyzed INTEGER NOT NULL DEFAULT 0,
    total_threats_blocked INTEGER NOT NULL DEFAULT 0,
    sessions_in_period INTEGER NOT NULL DEFAULT 0,
    last_active_at TIMESTAMPTZ,
    notes TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_org_metrics_org ON public.org_metrics(org_id);
CREATE INDEX IF NOT EXISTS idx_org_metrics_period ON public.org_metrics(period_start DESC);
CREATE INDEX IF NOT EXISTS idx_org_metrics_churn ON public.org_metrics(is_churned);

-- 16. CONVERSION FUNNEL
CREATE TABLE IF NOT EXISTS public.conversions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    lead_id UUID REFERENCES public.leads(id) ON DELETE SET NULL,
    org_id UUID REFERENCES public.organizations(id) ON DELETE SET NULL,
    source TEXT DEFAULT 'organic',
    converted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    plan_name TEXT DEFAULT 'free',
    signup_to_convert_hours NUMERIC(10,2),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_conversions_org ON public.conversions(org_id);
CREATE INDEX IF NOT EXISTS idx_conversions_source ON public.conversions(source);

-- RLS Policies
ALTER TABLE public.subscription_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.org_metrics ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.conversions ENABLE ROW LEVEL SECURITY;

DO $$ BEGIN DROP POLICY IF EXISTS "svc_subscription_history" ON public.subscription_history; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_subscription_history" ON public.subscription_history FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_subscription_history" ON public.subscription_history; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_subscription_history" ON public.subscription_history FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_org_metrics" ON public.org_metrics; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_org_metrics" ON public.org_metrics FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_org_metrics" ON public.org_metrics; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_org_metrics" ON public.org_metrics FOR ALL USING (auth.role() = 'anon');

DO $$ BEGIN DROP POLICY IF EXISTS "svc_conversions" ON public.conversions; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "svc_conversions" ON public.conversions FOR ALL USING (auth.role() = 'service_role');
DO $$ BEGIN DROP POLICY IF EXISTS "anon_conversions" ON public.conversions; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE POLICY "anon_conversions" ON public.conversions FOR ALL USING (auth.role() = 'anon');
