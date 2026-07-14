# SENTINEL - AI-Powered Phishing Triage Intelligence

A B2B SaaS cybersecurity platform that uses AI to analyze employee-reported phishing emails, generate executive security reports, and learn from analyst feedback. Built with FastAPI, React, Groq Llama-3, and Supabase PostgreSQL.

**Cost: $0** - Runs entirely on free-tier services.

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
| `GET` | `/api/v1/reports/monthly` | Download monthly PDF report |
| `GET` | `/api/v1/reports/monthly/data` | Get monthly data as JSON |
| `GET` | `/api/v1/db/status` | Database connection status |

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
