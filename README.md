# SENTINEL - AI-Powered Phishing Triage Intelligence

A B2B SaaS cybersecurity platform that uses AI to analyze employee-reported phishing emails, generate executive security reports, and learn from analyst feedback. Built with FastAPI, React, Groq Llama-3, and Supabase PostgreSQL.

**Cost: $0** - Runs entirely on free-tier services.

**Features:** AI phishing analysis, IMAP inbox scanning, explainable AI (XAI), feedback loop with auto-whitelisting, ROI-optimized executive PDF reports, per-org volume queueing (20 emails/hour limit), per-user/org API rate limiting, subscription & churn tracking, CAC/LTV metrics, CSV financial export.

---

## Architecture

```
                          SENTINEL v3.0 Architecture
 ┌─────────────────────────────────────────────────────────────────────┐
 │                        PRESENTATION LAYER                          │
 │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────────┐  │
 │  │ Landing  │  │  Login   │  │ Register │  │   Dashboard (React)│  │
 │  │  Page    │  │  Page    │  │  Page    │  │  Embedded in Babel │  │
 │  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────────┬──────────┘  │
 │       └──────────────┴─────────────┴────────────────┘              │
 └───────────────────────────────┬─────────────────────────────────────┘
                                 │ HTTP / WebSocket
 ┌───────────────────────────────┴─────────────────────────────────────┐
 │                        API LAYER (FastAPI)                          │
 │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
 │  │   Auth   │ │  Email   │ │ Feedback │ │ Reports  │ │    DB    │ │
 │  │Register/ │ │  Paste/  │ │ Corrections│ │  PDF     │ │  Status  │ │
 │  │  Login   │ │  List/Del│ │ + Whitelist│ │  Monthly │ │          │ │
 │  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
 └───────────────────────────────┬─────────────────────────────────────┘
                                 │
 ┌───────────────────────────────┴─────────────────────────────────────┐
 │                      SERVICE LAYER                                  │
 │  ┌──────────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
 │  │  GroqAnalyzer    │  │  IMAPEmail   │  │  PDF Report          │  │
 │  │  XAI Prompt      │  │  Service     │  │  Generator           │  │
 │  │  Model Fallback  │  │  Background   │  │  (reportlab)         │  │
 │  │  Whitelist Check │  │  Polling     │  │                      │  │
 │  └──────────────────┘  └──────────────┘  └──────────────────────┘  │
 └───────────────────────────────┬─────────────────────────────────────┘
                                 │
 ┌───────────────────────────────┴─────────────────────────────────────┐
 │                      DATA LAYER (db.py)                             │
 │  ┌──────────────────────────────────────────────────────────────┐   │
 │  │  Supabase PostgreSQL (primary)  │  SQLite + JSON (fallback) │   │
 │  │  organizations                  │  users.db                  │   │
 │  │  reported_emails                │  data/<user>/email_data.json│  │
 │  │  feedback_logs                  │  data/feedback_logs.json   │   │
 │  │  whitelist                      │  data/whitelist.json       │   │
 │  │  RLS Enabled                    │                            │   │
 │  └──────────────────────────────────────────────────────────────┘   │
 └─────────────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Clone & Setup

```bash
git clone <your-repo-url>
cd sentinel
python -m venv venv
venv\Scripts\activate          # Windows
# source venv/bin/activate    # macOS/Linux
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your API keys
```

### 2. Configure Environment

```bash
# .env
GROQ_API_KEY=gsk_xxxxxxxxxxxxxxxxxxxxxx       # https://console.groq.com
SUPABASE_URL=https://your-project.supabase.co  # https://supabase.com
SUPABASE_KEY=your_supabase_anon_key
IMAP_USERNAME=your@gmail.com
IMAP_PASSWORD=your_app_password
COST_PER_INCIDENT=4500                         # USD per incident prevented
```

### 3. Setup Database (Supabase)

1. Go to your Supabase project dashboard → **SQL Editor**
2. Paste the contents of `migrations/001_initial_schema.sql`
3. Click **Run** to create all tables with RLS enabled

> **Note:** The app works without Supabase — it automatically falls back to SQLite + JSON files.

### 4. Run

```bash
python app.py
# Or double-click start.bat
```

- **Dashboard:** http://localhost:8000/dashboard
- **Landing:** http://localhost:8000/
- **API Docs:** http://localhost:8000/docs

---

## Project Structure

```
sentinel/
├── app.py                     # Main FastAPI application (routes, pages, AI)
├── db.py                      # Database layer (Supabase + local fallback)
├── report.py                  # PDF report generation (reportlab)
├── requirements.txt           # Python dependencies
├── .env                       # Environment variables (git-ignored)
├── .env.example               # Environment template
├── .gitignore                 # Git ignore rules
├── start.bat                  # One-click launcher (Windows)
│
├── migrations/
│   └── 001_initial_schema.sql # Supabase DDL (run in SQL Editor)
│
├── data/                      # Local fallback storage
│   ├── users.db               # SQLite user database
│   ├── feedback_logs.json     # User corrections (local)
│   ├── whitelist.json         # Whitelist entries (local)
│   └── <user_id>/             # Per-user email reports
│       └── email_data.json
│
└── venv/                      # Python virtual environment
```

---

## API Reference

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/auth/register` | Create account (username, email, password) |
| `POST` | `/api/auth/login` | Login, returns JWT token |
| `POST` | `/api/auth/logout` | Clear session |
| `GET` | `/api/auth/me` | Get current user info |

### Email Analysis

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/analyze/paste` | Paste email text for AI analysis |
| `GET` | `/api/v1/emails` | List all analyzed emails |
| `DELETE` | `/api/v1/emails` | Clear all reports |
| `POST` | `/api/v1/imap/check` | Trigger IMAP inbox scan |

### Feedback Loop (Defensibility)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/feedback` | Submit correction to AI verdict |
| `GET` | `/api/v1/feedback` | List recent corrections |
| `GET` | `/api/v1/whitelist` | View organization whitelist |
| `POST` | `/api/v1/whitelist` | Add whitelist entry (domain/sender) |
| `DELETE` | `/api/v1/whitelist/{id}` | Remove whitelist entry |

### Executive Reporting

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/reports/monthly` | Download monthly PDF report (includes ROI section) |
| `GET` | `/api/v1/reports/monthly/data` | Get monthly data as JSON |
| `GET` | `/api/v1/db/status` | Database connection status |

### Volume Queueing & Cost Protection

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/volume/status` | Get org email volume status (limit, remaining, queued) |
| `POST` | `/api/v1/volume/drain` | Process queued emails for the org |

**Rate Limits:** 30 API calls/user/min, 100 API calls/org/min, 20 emails analyzed/org/hour.

### Financial Tracking & Acquisition Metrics

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/finance/subscription` | Record subscription event (signup, upgrade, cancellation) |
| `GET` | `/api/v1/finance/subscription` | List subscription history for org |
| `GET` | `/api/v1/finance/metrics` | Get CAC, churn risk, and metrics history |
| `POST` | `/api/v1/finance/metrics/record` | Record monthly metrics snapshot |
| `GET` | `/api/v1/finance/export/csv` | Export financial data as CSV (owner/admin only) |

---

## Explainable AI (XAI) Output

Every analysis returns structured JSON with human-readable reasoning:

```json
{
  "verdict": "malicious",
  "confidence_score": 98.0,
  "confidence": 0.98,
  "reasoning": "The sender domain paypa1-verify.xyz spoofs the legitimate paypal.com domain...",
  "indicators": [
    "Sender domain paypa1-verify.xyz spoofs legitimate paypal.com",
    "URL shortener bit.ly obscures true destination",
    "Urgency language: account will be suspended in 24 hours"
  ],
  "recommendations": ["Block sender domain at mail gateway", "Alert targeted user"],
  "social_engineering_tactics": {
    "urgency": true,
    "authority": true,
    "fear": true,
    "curiosity": false,
    "scarcity": false
  },
  "technical_indicators": {
    "spoofed_domain": true,
    "authentication_failure": false,
    "suspicious_urls": true,
    "malicious_attachments": false
  }
}
```

### Confidence Scoring

| Range | Level | Interpretation |
|-------|-------|----------------|
| 90-100 | Definitive | Clear spoofed domain + credential harvest |
| 70-89 | Strong | Multiple phishing signals present |
| 40-69 | Moderate | Suspicious but could be legitimate |
| 10-39 | Weak | Mostly legitimate with minor anomalies |
| 0-9 | Negligible | Clearly legitimate business communication |

---

## Feedback Loop (Defensibility)

When an analyst marks an AI verdict as incorrect:

1. **Correction logged** in `feedback_logs` with original vs. corrected verdict
2. **Auto-whitelist**: If a MALICIOUS email is marked SAFE, the sender domain is automatically added to the organization's whitelist
3. **Future analysis**: The AI prompt includes whitelist context to avoid re-flagging verified-safe senders
4. **Training data**: Feedback logs can be exported for fine-tuning or prompt optimization

---

## Executive Reporting

The Monthly Security Summary PDF includes:

- **Executive Summary**: Total analyzed, threats blocked, suspicious, safe
- **Cost Analysis**: Estimated cost prevented (configurable per-incident cost)
- **Top Targeted Users**: Users receiving the most phishing attempts
- **Top Malicious Domains**: Most common attacker sender domains
- **Recommendations**: Actionable next steps based on the data

---

## Testing

### Run All Tests

```bash
# Start the server first
python app.py

# In a separate terminal:
python test_v3.py
```

### Test Coverage

| Category | Tests | What's Verified |
|----------|-------|-----------------|
| Auth | 6 | Registration, login, JWT tokens, auth enforcement |
| XAI Analysis | 2 | Structured response, real AI model usage |
| Email Ops | 2 | List, clear reports |
| Feedback Loop | 3 | Submit correction, list feedback, analyze |
| Whitelist | 2 | Add/get whitelist entries |
| Reporting | 2 | PDF generation, JSON data endpoint |
| Database | 1 | Supabase connection status |
| Pages | 3 | Landing, login, dashboard load |
| Volume Queueing | 4 | Per-user/org rate limits, overflow queue, high volume alerts |
| Financial Tracking | 5 | Subscription events, CAC, churn risk, CSV export |
| ROI PDF | 2 | ROI calculation, costs prevented display |

### Testing Volume Queueing System

The volume queueing system limits each organization to 20 email analyses per hour. Excess emails are queued for later processing.

```bash
# Start the server
python app.py

# 1. Check volume status (returns emails_this_hour, remaining, queued)
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/volume/status

# 2. Simulate high volume by triggering multiple scans rapidly
# Each IMAP check processes up to 15 emails. After ~2 scans, you'll hit the 20/hour limit.
for i in {1..5}; do
  curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
    -d '{}' http://localhost:8000/api/v1/imap/check
  echo "Scan $i complete"
done

# 3. Check volume status again — should show remaining=0 and queued>0
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/volume/status

# 4. Drain queued emails manually (processes up to 20 per call)
curl -X POST -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/volume/drain

# 5. Paste analysis also respects volume limits
curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"content": "From: phish@evil.com\nSubject: URGENT\nClick here to verify."}' \
  http://localhost:8000/api/v1/analyze/paste
# If volume limit hit: returns {"status": "queued", "message": "Volume limit reached..."}

# 6. Per-user API rate limit: 30 requests/minute
# Rapid-fire requests will return 429 after 30 calls
```

**What happens when volume limit is hit:**
- IMAP scan emails beyond 20/hour are queued in memory
- A `high_volume_detected` audit log event is triggered
- The scan response includes `queued_count` in the results
- Admin can manually drain the queue via `POST /api/v1/volume/drain`
- Queued emails are analyzed with full AI verdicts when drained

### Testing Financial Tracking

```bash
# 1. Record a subscription event (requires owner/admin role)
curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"event_type": "signup", "plan_name": "pro", "monthly_amount": 299, "billing_cycle": "monthly"}' \
  http://localhost:8000/api/v1/finance/subscription

# 2. List subscription history
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/finance/subscription

# 3. Get CAC and churn risk metrics
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/finance/metrics

# 4. Record monthly metrics snapshot
curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
  -d '{"mrr": 299, "cac": 150, "ltv": 3588, "total_emails_analyzed": 450, "total_threats_blocked": 12}' \
  http://localhost:8000/api/v1/finance/metrics/record

# 5. Export all financial data as CSV
curl -H "Authorization: Bearer <token>" http://localhost:8000/api/v1/finance/export/csv -o financial_export.csv
```

### Testing ROI PDF Reports

```bash
# 1. Download monthly PDF report (now includes dedicated ROI section)
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/v1/reports/monthly -o report.pdf

# 2. Get the raw report data JSON (includes roi_percentage, net_savings)
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/v1/reports/monthly/data
```

**ROI section in PDF includes:**
- Total threats blocked × cost per breach = total costs prevented
- SENTINEL platform cost ($299/month default)
- Net savings = costs prevented - platform cost
- ROI % = (net savings / platform cost) × 100
- Threats blocked per dollar spent

### Manual Testing

```bash
# Test XAI analysis
curl -X POST http://localhost:8000/api/v1/analyze/paste \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"content": "From: security@paypa1-verify.xyz\nSubject: URGENT\n\nClick http://bit.ly/xyz to verify your password."}'

# Test feedback submission
curl -X POST http://localhost:8000/api/v1/feedback \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{"email_id": "<id>", "corrected_verdict": "safe", "reason": "Legitimate"}'

# Download monthly PDF report
curl -H "Authorization: Bearer <token>" \
  http://localhost:8000/api/v1/reports/monthly -o report.pdf
```

---

## Database Schema (Supabase)

### organizations
| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| name | TEXT | Organization name |
| domain | TEXT | Primary domain (unique) |
| sla_status | TEXT | active/suspended/trial |
| created_at | TIMESTAMPTZ | Creation timestamp |

### reported_emails
| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| org_id | UUID | FK → organizations |
| user_id | TEXT | Reporting user |
| sender | TEXT | Email sender address |
| subject | TEXT | Email subject |
| raw_body | TEXT | Full email body |
| ai_risk_score | REAL | 0-100 risk score |
| ai_analysis | JSONB | Full XAI analysis output |
| urls | TEXT[] | Extracted URLs |
| created_at | TIMESTAMPTZ | Analysis timestamp |

### feedback_logs
| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| email_id | UUID | FK → reported_emails |
| org_id | UUID | FK → organizations |
| user_id | TEXT | Analyst who corrected |
| original_verdict | TEXT | AI's original verdict |
| corrected_verdict | TEXT | Analyst's correction |
| reason | TEXT | Explanation |

### whitelist
| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| org_id | UUID | FK → organizations |
| pattern_type | TEXT | domain/sender/subject_regex |
| pattern_value | TEXT | The pattern to match |
| source | TEXT | manual/feedback_auto |
| hit_count | INTEGER | Times this pattern matched |

### subscription_history (New)
| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| org_id | UUID | FK → organizations |
| event_type | TEXT | signup/upgrade/downgrade/cancellation/trial_start/trial_end |
| plan_name | TEXT | free/pro/enterprise |
| monthly_amount | NUMERIC | Monthly subscription cost |
| billing_cycle | TEXT | monthly/annual/one_time |
| payment_status | TEXT | pending/paid/failed/refunded/cancelled |
| occurred_at | TIMESTAMPTZ | When the event occurred |

### org_metrics (New)
| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| org_id | UUID | FK → organizations |
| period_start | TIMESTAMPTZ | Metrics period start |
| period_end | TIMESTAMPTZ | Metrics period end |
| mrr | NUMERIC | Monthly recurring revenue |
| cac | NUMERIC | Customer acquisition cost |
| ltv | NUMERIC | Lifetime value |
| churn_risk_score | NUMERIC | 0-100 churn risk |
| is_churned | BOOLEAN | Whether org has churned |
| total_emails_analyzed | INTEGER | Emails analyzed in period |
| total_threats_blocked | INTEGER | Threats blocked in period |

### conversions (New)
| Column | Type | Description |
|--------|------|-------------|
| id | UUID | Primary key |
| lead_id | UUID | FK → leads |
| org_id | UUID | FK → organizations |
| source | TEXT | Conversion source |
| plan_name | TEXT | Plan they converted to |
| signup_to_convert_hours | NUMERIC | Hours from signup to conversion |

**Row-Level Security (RLS)** is enabled on all tables with service-role bypass policies.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| fastapi | Web framework |
| uvicorn | ASGI server |
| pydantic | Data validation |
| python-dotenv | Environment management |
| groq | Groq API client (Llama-3) |
| supabase | Supabase PostgreSQL client |
| reportlab | PDF report generation |
| bcrypt | Password hashing |
| PyJWT | JWT authentication |
| httpx | HTTP client |
| psycopg2-binary | PostgreSQL driver |

---

## License

MIT License
   
 