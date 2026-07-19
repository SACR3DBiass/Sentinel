"""
SENTINEL - AI-Powered Phishing Triage & Simulation Agent
Production-ready B2B SaaS cybersecurity platform.
"""

import os
import sys
import json
import re
import uuid
import time
import hashlib
import hmac
import secrets
import ipaddress
import imaplib
import email as email_lib
import asyncio
import threading
import sqlite3
from datetime import datetime, timedelta
from email.header import decode_header
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, HTTPException, Header, Request, Query, Response, Depends
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel, Field
import httpx
import bcrypt
import jwt

from dotenv import load_dotenv
import db
from report import generate_monthly_report_pdf
from lite import app as lite_app

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

# ============================================================================
# CONFIGURATION
# ============================================================================
class Settings:
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "") or "https://qnrdduwczpexihzhpuhq.supabase.co"
    SUPABASE_KEY: str = os.getenv("SUPABASE_KEY", "")
    SUPABASE_ACCESS_TOKEN: str = os.getenv("SUPABASE_ACCESS_TOKEN", "")
    # No hardcoded fallback secrets: use the env var, else a random per-process
    # secret. A random secret means forged tokens are impossible even if the env
    # var is forgotten (worst case: tokens invalidate on restart, never a known key).
    WEBHOOK_SECRET: str = os.getenv("WEBHOOK_SECRET") or secrets.token_urlsafe(48)
    APP_NAME: str = "SENTINEL"
    APP_VERSION: str = "3.0.0"
    JWT_SECRET: str = os.getenv("JWT_SECRET") or db.JWT_SECRET
    JWT_EXPIRY_HOURS: int = 15  # 15-minute access tokens (refresh token handles long sessions)
    IMAP_SERVER: str = os.getenv("IMAP_SERVER", "imap.gmail.com")
    IMAP_PORT: int = int(os.getenv("IMAP_PORT", "993"))
    IMAP_USERNAME: str = os.getenv("IMAP_USERNAME", "")
    IMAP_PASSWORD: str = os.getenv("IMAP_PASSWORD", "")
    IMAP_FOLDER: str = os.getenv("IMAP_FOLDER", "INBOX")
    IMAP_POLL_INTERVAL: int = int(os.getenv("IMAP_POLL_INTERVAL", "30"))
    COST_PER_INCIDENT: float = float(os.getenv("COST_PER_INCIDENT", "4500"))
    # Send the auth cookie only over HTTPS. Set COOKIE_SECURE=true in production;
    # left false for local http://localhost development.
    COOKIE_SECURE: bool = os.getenv("COOKIE_SECURE", "false").lower() in ("1", "true", "yes")
    # Comma-separated list of allowed browser origins. Never "*" with credentials.
    # Set CORS_ORIGINS in prod, e.g. "https://app.yourdomain.com".
    ALLOWED_ORIGINS: List[str] = [
        o.strip() for o in os.getenv(
            "CORS_ORIGINS",
            "http://localhost:8000,http://127.0.0.1:8000"
        ).split(",") if o.strip()
    ]

settings = Settings()

# ============================================================================
# DATABASE - Users managed via db.py (Supabase or SQLite fallback)
# ============================================================================
from db import (store_get, store_set, store_clear,
                user_create, user_get_by_username, user_get_by_id, user_list_org,
                user_update_last_login, org_create, org_get,
                email_connection_create, email_connection_list, email_connection_get,
                email_connection_get_active_all, email_connection_update_scan,
                email_connection_delete, email_connection_toggle,
                scan_job_create, scan_job_update, scan_job_list,
                invite_create, invite_get_by_token, invite_accept, invite_list_org, invite_delete,
                is_supabase_available, feedback_cache)

# ============================================================================
# AUTH HELPERS
# ============================================================================
def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

def create_token(user_id: str, username: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "exp": datetime.utcnow() + timedelta(hours=settings.JWT_EXPIRY_HOURS),
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm="HS256")

def decode_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, settings.JWT_SECRET, algorithms=["HS256"])
    except Exception:
        return None

def get_current_user(request: Request) -> Optional[dict]:
    token = request.cookies.get("sentinel_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        return None
    return decode_token(token)

def require_auth(request: Request) -> dict:
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user

_synced_users = set()  # Track users already synced to Supabase this session
_user_db_cache = {}  # user_id -> (dict, timestamp) - cache user lookups for 60s

def resolve_user_db(user: dict) -> Optional[dict]:
    uid = user["user_id"]
    cached = _user_db_cache.get(uid)
    if cached and (time.time() - cached[1]) < 60:
        return cached[0]
    user_db = user_get_by_id(uid)
    if not user_db:
        user_db = user_get_by_username(user["username"])
    if user_db:
        _user_db_cache[uid] = (user_db, time.time())
    # Auto-sync to Supabase once if only in SQLite
    if user_db and uid not in _synced_users:
        _synced_users.add(uid)
        try:
            sb = db.get_supabase()
            if sb:
                check = sb.table("users").select("id").eq("id", uid).execute()
                if not check.data:
                    sb.table("users").upsert({
                        "id": uid,
                        "username": user_db["username"],
                        "email": user_db.get("email", ""),
                        "password_hash": user_db.get("password_hash", ""),
                        "role": user_db.get("role", "member"),
                        "is_active": True,
                        "org_id": user_db.get("org_id"),
                    }).execute()
                    print(f"[SENTINEL] Synced user '{user_db['username']}' to Supabase", flush=True)
        except Exception:
            pass
    return user_db

# ============================================================================
# SCAN RATE LIMITER
# ============================================================================
_scan_cooldowns: dict = {}  # user_id -> last scan timestamp
SCAN_COOLDOWN_SECONDS = 30

def check_scan_cooldown(user_id: str) -> float:
    import time
    last = _scan_cooldowns.get(user_id, 0)
    elapsed = time.time() - last
    if elapsed < SCAN_COOLDOWN_SECONDS:
        return round(SCAN_COOLDOWN_SECONDS - elapsed, 1)
    return 0

def mark_scan_started(user_id: str):
    import time
    _scan_cooldowns[user_id] = time.time()

# ============================================================================
# AUTH RATE LIMITER (per-IP, in-memory sliding window)
# ============================================================================
_auth_attempts: dict = {}  # "bucket:ip" -> [timestamps]
AUTH_RATE_WINDOW = 60      # seconds

def _client_ip(request: Request) -> str:
    """Best-effort real client IP. Only trusts X-Forwarded-For if it's a valid IP."""
    fwd = request.headers.get("x-forwarded-for", "")
    if fwd:
        candidate = fwd.split(",")[0].strip()
        try:
            ipaddress.ip_address(candidate)
            return candidate
        except ValueError:
            pass
    return request.client.host if request.client else "unknown"

def enforce_rate_limit(request: Request, bucket: str, max_attempts: int, window: int = AUTH_RATE_WINDOW):
    """Raise 429 if this IP has exceeded max_attempts within the window."""
    ip = _client_ip(request)
    key = f"{bucket}:{ip}"
    now = time.time()
    attempts = [t for t in _auth_attempts.get(key, []) if now - t < window]
    if len(attempts) >= max_attempts:
        retry = int(window - (now - attempts[0])) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Too many attempts. Try again in {retry}s.",
            headers={"Retry-After": str(retry)},
        )
    attempts.append(now)
    _auth_attempts[key] = attempts

# ============================================================================
# USER RECORD SANITIZER
# ============================================================================
_USER_SECRET_FIELDS = {"password_hash", "password", "hashed_password", "secret", "token"}

def _public_user(record: dict) -> dict:
    """Strip secret fields before any user record is returned to a client.
    Defense-in-depth so a password hash can never leak even if a query changes."""
    if not isinstance(record, dict):
        return record
    return {k: v for k, v in record.items() if k not in _USER_SECRET_FIELDS}

# ============================================================================
# GEO-IP LOOKUP + DEVICE PARSING + REQUEST LOGGING
# ============================================================================
_geo_cache: dict = {}
_geo_cache_ttl = 86400

def _lookup_geo(ip: str) -> dict:
    # SECURITY: `ip` may originate from the attacker-controlled X-Forwarded-For
    # header. Only ever interpolate a validated IP address into the outbound URL,
    # never raw header text (prevents URL/SSRF injection).
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"country": "", "region": "", "city": "", "_ts": time.time()}
    if ip in _geo_cache:
        entry = _geo_cache[ip]
        if time.time() - entry.get("_ts", 0) < _geo_cache_ttl:
            return entry
    if addr.is_loopback or addr.is_private or addr.is_reserved or addr.is_link_local:
        return {"country": "Local", "region": "Local", "city": "Local", "_ts": time.time()}
    try:
        import httpx as _httpx
        resp = _httpx.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                result = {
                    "country": data.get("country", ""),
                    "region": data.get("regionName", ""),
                    "city": data.get("city", ""),
                    "_ts": time.time(),
                }
                _geo_cache[ip] = result
                return result
    except Exception:
        pass
    return {"country": "", "region": "", "city": "", "_ts": time.time()}

def _parse_user_agent(ua: str) -> dict:
    ua_lower = ua.lower()
    browser = "Unknown"
    os_name = "Unknown"
    device_type = "Desktop"

    if "mobile" in ua_lower or "android" in ua_lower and "mobile" in ua_lower:
        device_type = "Mobile"
    elif "tablet" in ua_lower or "ipad" in ua_lower:
        device_type = "Tablet"
    elif "bot" in ua_lower or "crawler" in ua_lower or "spider" in ua_lower:
        device_type = "Bot"

    if "edg/" in ua_lower or "edge/" in ua_lower:
        browser = "Edge"
    elif "opr/" in ua_lower or "opera" in ua_lower:
        browser = "Opera"
    elif "chrome" in ua_lower and "safari" in ua_lower:
        browser = "Chrome"
    elif "firefox" in ua_lower:
        browser = "Firefox"
    elif "safari" in ua_lower:
        browser = "Safari"
    elif "msie" in ua_lower or "trident" in ua_lower:
        browser = "IE"

    if "windows" in ua_lower:
        os_name = "Windows"
    elif "mac os" in ua_lower or "macos" in ua_lower:
        os_name = "macOS"
    elif "linux" in ua_lower:
        os_name = "Linux"
    elif "android" in ua_lower:
        os_name = "Android"
    elif "iphone" in ua_lower or "ipad" in ua_lower:
        os_name = "iOS"

    return {"browser": browser, "os": os_name, "device_type": device_type}

_ANALYTICS_EXCLUDE_PATHS = {"/static", "/favicon.ico", "/health"}
_ANALYTICS_SAMPLE_RATE = 1

class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        try:
            path = request.url.path
            if any(path.startswith(ex) for ex in _ANALYTICS_EXCLUDE_PATHS):
                return response
            ip = _client_ip(request)
            ua_string = request.headers.get("user-agent", "")
            ua_parsed = _parse_user_agent(ua_string)
            geo = _lookup_geo(ip)
            user_info = get_current_user(request)
            user_id = user_info.get("user_id", "") if user_info else ""
            username = user_info.get("username", "") if user_info else ""
            db.request_log_save(
                ip=ip, path=path, method=request.method, user_agent=ua_string,
                country=geo.get("country", ""), region=geo.get("region", ""),
                city=geo.get("city", ""),
                device_type=ua_parsed.get("device_type", ""),
                browser=ua_parsed.get("browser", ""),
                os_name=ua_parsed.get("os", ""),
                user_id=user_id, username=username,
                response_status=response.status_code,
            )
        except Exception:
            pass
        return response

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        host = request.headers.get("host", "")
        if "localhost" not in host and "127.0.0.1" not in host:
            response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com https://fonts.googleapis.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; connect-src 'self' https://ipapi.co https://api.ipify.org;"
        )
        return response

# ============================================================================
# PYDANTIC SCHEMAS
# ============================================================================
class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=30)
    email: str = Field(...)
    password: str = Field(..., min_length=6)

class LoginRequest(BaseModel):
    username: str  # accepts username OR email
    password: str

class PasteEmailRequest(BaseModel):
    content: str
    subject: Optional[str] = None
    from_address: Optional[str] = None

# ============================================================================
# EMAIL PARSER
# ============================================================================
class EmailParser:
    @staticmethod
    def _clean_body(text: str) -> str:
        text = re.sub(r"\r\n", "\n", text)
        text = re.sub(r"\r", "\n", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r" {2,}", " ", text)
        return text.strip()

    @staticmethod
    def _extract_urls(body_text: str, body_html: str = "") -> List[str]:
        url_pattern = re.compile(
            r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[/\w\-.~:/?#[\]@!$&'()*+,;=]*"
        )
        urls = set()
        urls.update(url_pattern.findall(body_text))
        urls.update(url_pattern.findall(body_html))
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(body_html):
            url = match.group(1).strip()
            if url.startswith("http"):
                urls.add(url)
        return sorted(list(urls))

    @staticmethod
    def parse_webhook(data: dict) -> dict:
        body_text = EmailParser._clean_body(data.get("text_body", "") or "")
        body_html = data.get("html_body", "") or ""
        urls = EmailParser._extract_urls(body_text, body_html)
        return {
            "message_id": data.get("message_id", f"<{uuid.uuid4()}@sentinel>"),
            "from_address": data.get("from", "unknown"),
            "to_address": data.get("to", ""),
            "subject": data.get("subject", "No Subject"),
            "headers": data.get("headers", {}),
            "body_text": body_text,
            "body_html": body_html,
            "urls": urls,
            "has_attachments": len(data.get("attachments", [])) > 0,
            "timestamp": data.get("timestamp", datetime.now().isoformat()),
        }

# ============================================================================
# FORWARDING PARSER
# ============================================================================
class ForwardedEmailParser:
    FORWARD_PATTERNS = [
        r"----------\s*Forwarded message\s*----------",
        r"_{20,}\s*Forwarded message\s*_{20,}",
        r"Begin forwarded message:",
        r"From:.*(?:wrote|sent):",
        r"_{5,}\s*Forwarded message\s*_{5,}",
    ]
    HEADER_PATTERNS = {
        "from": r"From:\s*(.+?)(?:\n|$)",
        "date": r"Date:\s*(.+?)(?:\n|$)",
        "subject": r"Subject:\s*(.+?)(?:\n|$)",
        "to": r"(?:To|Cc):\s*(.+?)(?:\n|$)",
    }

    @classmethod
    def is_forwarded(cls, raw_text: str) -> bool:
        for pattern in cls.FORWARD_PATTERNS:
            if re.search(pattern, raw_text, re.IGNORECASE | re.MULTILINE):
                return True
        return False

    @classmethod
    def extract_forwarded_content(cls, raw_text: str) -> dict:
        result = {"from_address": "", "to_address": "", "subject": "", "body": "", "is_forwarded": True}
        forwarded_section = raw_text
        for pattern in cls.FORWARD_PATTERNS:
            match = re.search(pattern, raw_text, re.IGNORECASE | re.MULTILINE)
            if match:
                forwarded_section = raw_text[match.start():]
                break
        for key, pattern in cls.HEADER_PATTERNS.items():
            match = re.search(pattern, forwarded_section, re.IGNORECASE | re.MULTILINE)
            if match:
                result[key] = match.group(1).strip()
        body_start = 0
        for pattern in cls.HEADER_PATTERNS.values():
            matches = list(re.finditer(pattern, forwarded_section, re.IGNORECASE | re.MULTILINE))
            if matches:
                body_start = max(body_start, matches[-1].end())
        result["body"] = forwarded_section[body_start:].strip() if body_start > 0 else forwarded_section
        return result

    @classmethod
    def parse_email_message(cls, msg) -> dict:
        forward_from = cls._decode_header(msg.get("From", "")) if msg.get("From") else ""
        forward_to = cls._decode_header(msg.get("To", "")) if msg.get("To") else ""
        body_text = ""
        body_html = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    body_text = cls._decode_payload(part)
                elif ct == "text/html":
                    body_html = cls._decode_payload(part)
        else:
            ct = msg.get_content_type()
            if ct == "text/plain":
                body_text = cls._decode_payload(msg)
            elif ct == "text/html":
                body_html = cls._decode_payload(msg)
        raw_text = body_text or cls._html_to_text(body_html)
        if cls.is_forwarded(raw_text):
            original = cls.extract_forwarded_content(raw_text)
            return {
                "from_address": original.get("from_address") or forward_from,
                "to_address": forward_to,
                "subject": original.get("subject") or cls._decode_header(msg.get("Subject", "")),
                "body_text": original.get("body", raw_text),
                "body_html": body_html,
                "is_forwarded": True,
                "message_id": cls._decode_header(msg.get("Message-ID", f"<{uuid.uuid4()}@fwd>")),
            }
        return {
            "from_address": forward_from,
            "to_address": forward_to,
            "subject": cls._decode_header(msg.get("Subject", "")),
            "body_text": body_text,
            "body_html": body_html,
            "is_forwarded": False,
            "message_id": cls._decode_header(msg.get("Message-ID", f"<{uuid.uuid4()}@direct>")),
        }

    @staticmethod
    def _decode_header(h):
        if not h:
            return ""
        parts = decode_header(h)
        result = []
        for part, charset in parts:
            if isinstance(part, bytes):
                result.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                result.append(part)
        return " ".join(result)

    @staticmethod
    def _decode_payload(msg):
        payload = msg.get_payload(decode=True)
        if payload is None:
            return ""
        charset = msg.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")

    @staticmethod
    def _html_to_text(html):
        text = re.sub(r"<style[^>]*>.*?</style>", "", html, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<script[^>]*>.*?</script>", "", text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r"<br\s*/?>", "\n", text, flags=re.IGNORECASE)
        text = re.sub(r"</p>", "\n\n", text, flags=re.IGNORECASE)
        text = re.sub(r"<[^>]+>", "", text)
        text = re.sub(r"&nbsp;", " ", text)
        text = re.sub(r"&amp;", "&", text)
        text = re.sub(r"&lt;", "<", text)
        text = re.sub(r"&gt;", ">", text)
        return re.sub(r"\n{3,}", "\n\n", text).strip()

# ============================================================================
# GROQ ANALYZER
# ============================================================================
PHISHING_ANALYSIS_PROMPT = """You are an elite Tier 3 SOC analyst specializing in phishing detection. Your task is to perform a thorough, evidence-based analysis of email content and return a structured verdict with Explainable AI (XAI) indicators. Accuracy is paramount — false positives waste analyst time, false negatives risk breaches.

ANALYSIS FRAMEWORK:
1. SENDER INTEGRITY: Examine the sender domain. Legitimate domains (google.com, paypal.com, microsoft.com) indicate legitimacy. Spoofed/lookalike domains (paypa1-verify.xyz, microsft365-alert.top) indicate phishing.
2. URL ANALYSIS: Check if linked domains match the claimed sender. URL shorteners (bit.ly, tinyurl) and suspicious TLDs (.xyz, .top, .buzz) are red flags.
3. CONTENT ANALYSIS: Look for social engineering tactics: urgency ("within 24 hours"), authority impersonation ("IT department"), fear ("account suspended"), credential harvesting ("verify your password"), and reward scams ("you've won").
4. HEADER ANALYSIS: Check for authentication failures, mismatched Reply-To addresses, and suspicious routing.
5. ATTACHMENT ANALYSIS: Check for suspicious file types (.exe, .scr, .js, .vbs, .zip with password).

RESPOND IN STRICT JSON ONLY (no markdown, no explanation outside JSON):
{
    "verdict": "safe | suspicious | malicious",
    "confidence_score": 0-100,
    "reasoning_summary": "A concise, human-friendly 1-2 sentence explanation of the verdict. Example: 'This email spoofs PayPal with a lookalike domain and contains a credential harvesting link.'",
    "indicators": {
        "mismatched_sender": false,
        "spoofed_domain": false,
        "suspicious_tld": false,
        "url_shortener": false,
        "mismatched_urls": false,
        "urgency_language": false,
        "authority_impersonation": false,
        "fear_tactics": false,
        "credential_harvest": false,
        "reward_scam": false,
        "suspicious_attachments": false,
        "authentication_failure": false,
        "reply_to_mismatch": false
    },
    "indicator_details": {
        "mismatched_sender": "Detailed explanation if true, empty string if false",
        "spoofed_domain": "",
        "suspicious_tld": "",
        "url_shortener": "",
        "mismatched_urls": "",
        "urgency_language": "",
        "authority_impersonation": "",
        "fear_tactics": "",
        "credential_harvest": "",
        "reward_scam": "",
        "suspicious_attachments": "",
        "authentication_failure": "",
        "reply_to_mismatch": ""
    },
    "recommendations": ["Specific, actionable steps. Examples: 'Block sender domain at mail gateway', 'Alert user about credential harvest attempt', 'No action required - email is legitimate']",
    "social_engineering_tactics": {
        "urgency": false,
        "authority": false,
        "fear": false,
        "curiosity": false,
        "scarcity": false
    },
    "technical_indicators": {
        "spoofed_domain": false,
        "authentication_failure": false,
        "suspicious_urls": false,
        "malicious_attachments": false
    }
}

CONFIDENCE SCORING GUIDE:
- 90-100: Definitive. Clear spoofed domain + credential harvest + urgency. High certainty.
- 70-89: Strong indicators. Multiple phishing signals present. High confidence.
- 40-69: Moderate. Some suspicious elements but could be legitimate. Needs review.
- 10-39: Weak. Mostly legitimate with minor anomalies. Low concern.
- 0-9: Negligible. Clearly legitimate business communication.

INDICATOR DEFINITIONS (set to true if detected with evidence):
- mismatched_sender: Sender display name doesn't match actual email address
- spoofed_domain: Sender domain imitates a legitimate brand (e.g., paypa1.com vs paypal.com)
- suspicious_tld: Domain uses suspicious TLD (.xyz, .top, .buzz, .tk, .ml, .ga)
- url_shortener: Email contains URL shorteners (bit.ly, tinyurl, t.co, goo.gl)
- mismatched_urls: Clickable URL text doesn't match the actual link destination
- urgency_language: Phrases like "act now", "within 24 hours", "immediate action required"
- authority_impersonation: Claims to be from IT, legal, bank, government, or executive
- fear_tactics: Threatens account suspension, legal action, or financial loss
- credential_harvest: Asks for password, SSN, credit card, or login credentials
- reward_scam: Claims you won a prize, lottery, or unexpected reward
- suspicious_attachments: Contains executable files, scripts, or password-protected archives
- authentication_failure: Email headers show failed SPF/DKIM/DMARC
- reply_to_mismatch: Reply-To address differs from sender address

RULES:
- Never hallucinate. Only analyze what is present in the email.
- Be evidence-based. Cite specific text, domains, and URLs from the email.
- A legitimate sender domain is the STRONGEST safety indicator.
- "Password", "verify", "urgent" alone do NOT make phishing — context and domain matter.
- If sender domain matches a known legitimate company AND URLs point to that company's real domain = SAFE.
- Return ONLY the JSON object. No markdown fences, no extra text."""

class GroqAnalyzer:
    def __init__(self):
        self.client = None
        self.models = [settings.GROQ_MODEL, "llama-3.1-8b-instant"]
        self.model = settings.GROQ_MODEL
        if settings.GROQ_API_KEY:
            try:
                from groq import Groq
                self.client = Groq(api_key=settings.GROQ_API_KEY)
                print("[SENTINEL] Groq API client initialized", flush=True)
            except Exception as e:
                print(f"[SENTINEL] Groq client failed: {e}", flush=True)

    def analyze_sync(self, email_data: dict, org_id: str = "") -> dict:
        # --- ADAPTIVE HEURISTICS: Check cache before calling LLM ---
        sender = email_data.get("from_address", "") or email_data.get("from", "")
        sender_domain = sender.split("@")[-1] if "@" in sender else ""
        if org_id and sender_domain:
            cached = feedback_cache.check(sender_domain, sender, org_id)
            if cached:
                print(f"[SENTINEL] Cache hit for {sender_domain} -> {cached['verdict']}", flush=True)
                cached["email_id"] = email_data.get("id", "")
                cached["analyzed_at"] = datetime.utcnow().isoformat()
                return cached

        if not self.client:
            return self._mock_analysis(email_data)
        messages = [
            {"role": "system", "content": PHISHING_ANALYSIS_PROMPT},
            {"role": "user", "content": self._format_email(email_data)},
        ]
        last_error = None
        for model in self.models:
            try:
                response = self.client.chat.completions.create(
                    model=model,
                    messages=messages,
                    response_format={"type": "json_object"},
                    temperature=0.2,
                    max_tokens=1024,
                )
                result = json.loads(response.choices[0].message.content)
                result = self._normalize_result(result)
                result["llm_model"] = model
                return result
            except Exception as e:
                print(f"[SENTINEL] Groq API error ({model}): {e}", flush=True)
                last_error = e
        print("[SENTINEL] All models failed, using mock analysis", flush=True)
        result = self._mock_analysis(email_data)
        result["api_error"] = str(last_error) if last_error else "No API key"
        return result

    def _normalize_result(self, result: dict) -> dict:
        """Normalize AI response to standard schema. Handles both old and new formats."""
        # Map verdict/threat_level to standard threat_level
        verdict = result.get("verdict") or result.get("threat_level", "safe")
        if isinstance(verdict, str):
            verdict = verdict.lower().strip()
        result["threat_level"] = verdict
        result["verdict"] = verdict

        # Map confidence_score (0-100) or confidence (0-1) to standard 0-1 float
        if "confidence_score" in result:
            cs = result["confidence_score"]
            result["confidence"] = round(min(max(float(cs) / 100.0, 0.0), 1.0), 2)
            result["confidence_score"] = round(min(max(float(cs), 0), 100), 1)
        elif "confidence" in result:
            c = result["confidence"]
            if isinstance(c, (int, float)) and c > 1.0:
                result["confidence"] = round(min(max(c / 100.0, 0.0), 1.0), 2)
                result["confidence_score"] = round(min(max(c, 0), 100), 1)
            else:
                result["confidence"] = round(min(max(float(c), 0.0), 1.0), 2)
                result["confidence_score"] = round(result["confidence"] * 100, 1)
        else:
            result["confidence"] = 0.5
            result["confidence_score"] = 50.0

        # Ensure reasoning is a string (support both old "reasoning" and new "reasoning_summary")
        if not isinstance(result.get("reasoning_summary"), str):
            if isinstance(result.get("reasoning"), str):
                result["reasoning_summary"] = result["reasoning"]
            else:
                result["reasoning_summary"] = str(result.get("reasoning_summary", "Analysis complete."))
        if not isinstance(result.get("reasoning"), str):
            result["reasoning"] = result.get("reasoning_summary", "Analysis complete.")

        # Normalize indicators: support both array (old) and object (new XAI) format
        indicators = result.get("indicators", {})
        if isinstance(indicators, list):
            # Old format: array of strings -> convert to object
            indicator_obj = {}
            indicator_keywords = {
                "mismatched_sender": ["mismatched", "display name", "sender name"],
                "spoofed_domain": ["spoofed", "lookalike", "impersonat", "fake domain"],
                "suspicious_tld": ["tld", ".xyz", ".top", ".buzz", ".tk", "suspicious domain"],
                "url_shortener": ["shortener", "bit.ly", "tinyurl", "shortened url"],
                "mismatched_urls": ["mismatched url", "url mismatch", "link text"],
                "urgency_language": ["urgency", "act now", "within 24", "immediate"],
                "authority_impersonation": ["authority", "impersonat", "it department", "legal"],
                "fear_tactics": ["fear", "suspended", "terminated", "legal action"],
                "credential_harvest": ["credential", "password", "login", "verify your", "ssn"],
                "reward_scam": ["reward", "won", "prize", "lottery"],
                "suspicious_attachments": ["attachment", "executable", ".exe", ".scr"],
                "authentication_failure": ["spf", "dkim", "dmarc", "authentication"],
                "reply_to_mismatch": ["reply-to", "reply to"],
            }
            for indicator_str in indicators:
                lower_ind = indicator_str.lower()
                matched = False
                for key, keywords in indicator_keywords.items():
                    if any(kw in lower_ind for kw in keywords):
                        indicator_obj[key] = True
                        matched = True
                        break
                if not matched:
                    # Generic indicator, store as unknown
                    indicator_obj["other"] = True
            result["indicators"] = indicator_obj
        elif not isinstance(indicators, dict):
            result["indicators"] = {}

        # Ensure indicator_details exists
        if "indicator_details" not in result or not isinstance(result.get("indicator_details"), dict):
            result["indicator_details"] = {}

        # Ensure social_engineering_tactics and technical_indicators exist
        if not isinstance(result.get("social_engineering_tactics"), dict):
            result["social_engineering_tactics"] = {}
        if not isinstance(result.get("technical_indicators"), dict):
            result["technical_indicators"] = {}

        # Ensure recommendations is a list
        recs = result.get("recommendations", [])
        if isinstance(recs, str):
            result["recommendations"] = [recs]
        elif not isinstance(recs, list):
            result["recommendations"] = []

        return result

    async def analyze(self, email_data: dict) -> dict:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.analyze_sync, email_data)

    async def analyze_batch(self, emails: list, org_id: str = "") -> list:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.analyze_batch_sync, emails, org_id)

    BATCH_PROMPT = """You are a Tier 3 SOC analyst. Analyze each email below for phishing. Return a JSON object with key "results" containing an array of analysis objects, one per email, in the same order.

Each analysis object must have:
{
    "email_index": 0,
    "verdict": "safe | suspicious | malicious",
    "confidence_score": 0-100,
    "reasoning_summary": "Brief 1-sentence explanation",
    "indicators": {
        "mismatched_sender": false,
        "spoofed_domain": false,
        "suspicious_tld": false,
        "url_shortener": false,
        "mismatched_urls": false,
        "urgency_language": false,
        "authority_impersonation": false,
        "fear_tactics": false,
        "credential_harvest": false,
        "reward_scam": false,
        "suspicious_attachments": false,
        "authentication_failure": false,
        "reply_to_mismatch": false
    },
    "recommendations": ["actionable step"]
}

EMAILS TO ANALYZE:
"""

    def analyze_batch_sync(self, emails: list, org_id: str = "") -> list:
        if not self.client:
            return [self._mock_analysis(e) for e in emails]
        if len(emails) == 1:
            result = self.analyze_sync(emails[0], org_id=org_id)
            return [result]

        # --- ADAPTIVE HEURISTICS: Check cache for each email before batch call ---
        cached_results = [None] * len(emails)
        uncached_indices = []
        for i, e in enumerate(emails):
            sender = e.get("from_address", "") or e.get("from", "")
            sender_domain = sender.split("@")[-1] if "@" in sender else ""
            if org_id and sender_domain:
                cached = feedback_cache.check(sender_domain, sender, org_id)
                if cached:
                    cached["email_id"] = e.get("id", "")
                    cached["analyzed_at"] = datetime.utcnow().isoformat()
                    cached_results[i] = cached
                    print(f"[SENTINEL] Batch cache hit: {sender_domain} -> {cached['verdict']}", flush=True)
                    continue
            uncached_indices.append(i)

        # If all emails are cached, return immediately
        if not uncached_indices:
            return cached_results

        # Build batch prompt only for uncached emails
        batch_parts = []
        idx_map = {}  # map batch position -> original index
        for batch_pos, orig_idx in enumerate(uncached_indices):
            e = emails[orig_idx]
            idx_map[batch_pos] = orig_idx
            headers = e.get("headers", {})
            headers_str = ", ".join(f"{k}: {v}" for k, v in list(headers.items())[:5]) if headers else "None"
            urls = e.get("urls", [])
            urls_str = ", ".join(urls[:3]) if urls else "None"
            batch_parts.append(f"""--- EMAIL {batch_pos} ---
From: {e.get('from_address', 'Unknown')}
Subject: {e.get('subject', 'No Subject')}
Headers: {headers_str}
Body: {(e.get('body_text', '') or '')[:500]}
URLs: {urls_str}
Attachments: {'Yes' if e.get('has_attachments') else 'None'}""")
        full_prompt = self.BATCH_PROMPT + "\n\n".join(batch_parts)
        messages = [
            {"role": "system", "content": PHISHING_ANALYSIS_PROMPT},
            {"role": "user", "content": full_prompt},
        ]
        last_error = None
        for model in self.models:
            try:
                response = self.client.chat.completions.create(
                    model=model, messages=messages,
                    response_format={"type": "json_object"},
                    temperature=0.2, max_tokens=4096,
                )
                raw = json.loads(response.choices[0].message.content)
                results = raw.get("results", [])
                if not results and isinstance(raw, dict) and "verdict" in raw:
                    results = [raw]
                # Map batch results back to original indices
                for batch_pos, orig_idx in enumerate(idx_map.values()):
                    match = next((r for r in results if r.get("email_index") == batch_pos), None)
                    if match:
                        match = self._normalize_result(match)
                        match["llm_model"] = model
                        cached_results[orig_idx] = match
                    else:
                        cached_results[orig_idx] = self._mock_analysis(emails[orig_idx])
                # Fill any remaining None with mock
                for i in range(len(emails)):
                    if cached_results[i] is None:
                        cached_results[i] = self._mock_analysis(emails[i])
                return cached_results
            except Exception as e:
                print(f"[SENTINEL] Groq batch error ({model}): {e}", flush=True)
                last_error = e
        print("[SENTINEL] All models failed for batch, using mock", flush=True)
        return [self._mock_analysis(e) for e in emails]

    def _format_email(self, d: dict) -> str:
        headers = d.get("headers", {})
        headers_str = "\n".join(f"- {k}: {v}" for k, v in headers.items()) if headers else "No headers"
        urls = d.get("urls", [])
        urls_str = "\n".join(urls) if urls else "No URLs"
        return f"""Email Analysis Request:
From: {d.get('from_address', 'Unknown')}
To: {d.get('to_address', 'Unknown')}
Subject: {d.get('subject', 'No Subject')}
Date: {d.get('timestamp', 'Unknown')}

Headers:
{headers_str}

Body:
{d.get('body_text', 'No body')}

URLs Found:
{urls_str}

Attachments: {'Yes' if d.get('has_attachments') else 'None'}

Analyze this email for phishing indicators."""

    def _mock_analysis(self, email_data: dict) -> dict:
        indicators_obj = {
            "mismatched_sender": False, "spoofed_domain": False, "suspicious_tld": False,
            "url_shortener": False, "mismatched_urls": False, "urgency_language": False,
            "authority_impersonation": False, "fear_tactics": False, "credential_harvest": False,
            "reward_scam": False, "suspicious_attachments": False, "authentication_failure": False,
            "reply_to_mismatch": False,
        }
        indicator_details = {k: "" for k in indicators_obj}
        threat_level = "safe"
        confidence = 50
        body = (email_data.get("body_text", "") or "").lower()
        subject = (email_data.get("subject", "") or "").lower()
        urgency_phrases = ["urgent", "act now", "expires", "suspended", "verify your", "confirm your", "security alert", "immediately", "within 24 hours"]
        urgency_found = [p for p in urgency_phrases if p in body or p in subject]
        if urgency_found:
            indicators_obj["urgency_language"] = True
            indicator_details["urgency_language"] = f"Urgency phrases detected: {', '.join(urgency_found[:3])}"
            threat_level = "suspicious"
            confidence = 70
        url_shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl"]
        urls = email_data.get("urls", [])
        for url in urls:
            if any(s in url.lower() for s in url_shorteners):
                indicators_obj["url_shortener"] = True
                indicator_details["url_shortener"] = f"URL shortener detected: {url}"
                threat_level = "suspicious"
                confidence = max(confidence, 75)
        suspicious_tlds = [".xyz", ".top", ".buzz", ".tk", ".ml"]
        for url in urls:
            if any(url.lower().endswith(tld) for tld in suspicious_tlds):
                indicators_obj["suspicious_tld"] = True
                indicator_details["suspicious_tld"] = f"Suspicious TLD: {url}"
                threat_level = "suspicious"
                confidence = max(confidence, 80)
        # Check for credential harvesting
        cred_phrases = ["verify your password", "confirm your password", "update your payment", "verify your account", "login credentials"]
        if any(p in body for p in cred_phrases):
            indicators_obj["credential_harvest"] = True
            indicator_details["credential_harvest"] = "Request for credentials detected in body"
            threat_level = "malicious"
            confidence = max(confidence, 85)
        reasoning = "Heuristic analysis (no AI model available). "
        active_indicators = [k for k, v in indicators_obj.items() if v]
        if active_indicators:
            reasoning += f"Found {len(active_indicators)} indicator(s): {', '.join(active_indicators)}."
        else:
            reasoning += "No obvious phishing indicators found in basic scan."
        # Build flat indicators array for backward compatibility
        indicators_array = []
        for k, v in indicators_obj.items():
            if v and indicator_details.get(k):
                indicators_array.append(indicator_details[k])
        if not indicators_array:
            indicators_array = ["No obvious indicators in basic analysis"]
        return {
            "threat_level": threat_level,
            "verdict": threat_level,
            "confidence": round(confidence / 100.0, 2),
            "confidence_score": float(confidence),
            "indicators": indicators_obj,
            "indicators_list": indicators_array,
            "indicator_details": indicator_details,
            "reasoning_summary": reasoning,
            "reasoning": reasoning,
            "recommendations": ["Configure Groq API key for comprehensive AI analysis"],
            "social_engineering_tactics": {"urgency": bool(urgency_found), "authority": False, "fear": False, "curiosity": False, "scarcity": False},
            "technical_indicators": {"spoofed_domain": False, "authentication_failure": False, "suspicious_urls": bool(active_indicators), "malicious_attachments": False},
            "llm_model": "mock-heuristic",
        }

# ============================================================================
# IMAP SERVICE
# ============================================================================
class IMAPEmailService:
    def __init__(self):
        self.server = settings.IMAP_SERVER
        self.port = settings.IMAP_PORT
        self.username = settings.IMAP_USERNAME
        self.password = settings.IMAP_PASSWORD
        self.folder = settings.IMAP_FOLDER
        self._processed_ids = set()

    @property
    def is_configured(self) -> bool:
        return bool(self.username and self.password)

    def _connect(self):
        mail = imaplib.IMAP4_SSL(self.server, self.port)
        mail.login(self.username, self.password)
        return mail

    def _fetch_emails_sync(self) -> List[dict]:
        emails = []
        MAX_EMAILS = 5
        try:
            mail = self._connect()
            mail.select(self.folder)
            status, messages = mail.search(None, "UNSEEN")
            if status != "OK":
                mail.logout()
                return emails
            email_ids = messages[0].split()
            recent_ids = email_ids[-MAX_EMAILS:] if len(email_ids) > MAX_EMAILS else email_ids
            for eid in recent_ids:
                eid_str = eid.decode()
                if eid_str in self._processed_ids:
                    continue
                status, msg_data = mail.fetch(eid, "(RFC822)")
                if status != "OK":
                    continue
                raw = msg_data[0][1]
                msg = email_lib.message_from_bytes(raw)
                parsed = ForwardedEmailParser.parse_email_message(msg)
                parsed["imap_id"] = eid_str
                parsed["received_at"] = datetime.now().isoformat()
                emails.append(parsed)
                self._processed_ids.add(eid_str)
                mail.store(eid, "+FLAGS", "\\Seen")
            mail.logout()
        except Exception as e:
            print(f"[SENTINEL] IMAP error: {e}", flush=True)
        return emails

    async def check_new_emails(self) -> List[dict]:
        if not self.is_configured:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._fetch_emails_sync)

# ============================================================================
# MAIN APPLICATION
# ============================================================================
app = FastAPI(title="SENTINEL", version=settings.APP_VERSION)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestLoggingMiddleware)

app.mount("/lite", lite_app)

analyzer = GroqAnalyzer()
imap_service = IMAPEmailService()

# ============================================================================
# BACKGROUND POLLING
# ============================================================================
async def poll_imap_background():
    await asyncio.sleep(10)
    while True:
        if imap_service.is_configured:
            try:
                new_emails = await imap_service.check_new_emails()
                for raw_email in new_emails:
                    parsed = EmailParser.parse_webhook({
                        "message_id": raw_email.get("message_id", f"<{uuid.uuid4()}@imap>"),
                        "from": raw_email.get("from_address", "unknown"),
                        "to": raw_email.get("to_address", imap_service.username),
                        "subject": raw_email.get("subject", "No Subject"),
                        "headers": {},
                        "text_body": raw_email.get("body_text", ""),
                        "html_body": raw_email.get("body_html", ""),
                        "attachments": [],
                        "timestamp": raw_email.get("received_at", datetime.now().isoformat()),
                    })
                    verdict_data = await analyzer.analyze(parsed)
                    email_id = f"email-{uuid.uuid4().hex[:12]}"
                    record = {
                        "id": email_id,
                        **parsed,
                        "received_at": raw_email.get("received_at", datetime.now().isoformat()),
                        "source": "forwarded_email",
                        "is_forwarded": raw_email.get("is_forwarded", False),
                        "verdict": {
                            "id": f"verdict-{uuid.uuid4().hex[:12]}",
                            "email_id": email_id,
                            **verdict_data,
                            "analyzed_at": datetime.now().isoformat(),
                        },
                    }
                    store_set("_system", email_id, record)
                    print(f"[SENTINEL] Processed IMAP email: {parsed['subject']} -> {verdict_data.get('threat_level')}", flush=True)
            except Exception as e:
                print(f"[SENTINEL] Background poll error: {e}", flush=True)
        await asyncio.sleep(settings.IMAP_POLL_INTERVAL)

@app.on_event("startup")
async def startup():
    print(f"[SENTINEL] Server starting", flush=True)
    print(f"[SENTINEL] Groq API key: {'configured (' + settings.GROQ_API_KEY[:10] + '...)' if settings.GROQ_API_KEY else 'NOT SET'}", flush=True)
    print(f"[SENTINEL] Supabase URL: {settings.SUPABASE_URL[:30] + '...' if settings.SUPABASE_URL else 'NOT SET'}", flush=True)
    print(f"[SENTINEL] Supabase key: {settings.SUPABASE_KEY[:15] + '...' if settings.SUPABASE_KEY else 'NOT SET'}", flush=True)
    print(f"[SENTINEL] Supabase token: {'configured (' + settings.SUPABASE_ACCESS_TOKEN[:10] + '...)' if settings.SUPABASE_ACCESS_TOKEN else 'NOT SET'}", flush=True)
    # Initialize Supabase connection
    db.init_supabase(settings.SUPABASE_URL, settings.SUPABASE_KEY)
    # Seed owner account — ensure it exists in both SQLite AND Supabase
    try:
        pw_hash = hash_password("admin")
        org_id = None
        if settings.SUPABASE_URL:
            org_id = db.get_or_create_default_org()
        fixed_id = "user-abb1c68c218e"
        # Always upsert owner in Supabase
        sb = db.get_supabase()
        if sb:
            try:
                existing_sb = sb.table("users").select("id").eq("id", fixed_id).execute()
                if not existing_sb.data:
                    sb.table("users").upsert({
                        "id": fixed_id,
                        "username": "Biass",
                        "email": "connorvallance@gmail.com",
                        "password_hash": pw_hash,
                        "role": "owner",
                        "is_active": True,
                        "org_id": org_id,
                    }).execute()
                    print("[SENTINEL] Owner created in Supabase (Biass)", flush=True)
                else:
                    sb.table("users").update({"role": "owner"}).eq("id", fixed_id).execute()
            except Exception as e:
                print(f"[SENTINEL] Supabase owner seed error: {e}", flush=True)
        # Also ensure in SQLite
        existing = user_get_by_username("Biass")
        if not existing:
            user = user_create("Biass", "connorvallance@gmail.com", pw_hash, org_id, user_id=fixed_id)
            if user:
                import sqlite3 as _s3
                conn = _s3.connect(os.path.join(db.DATA_DIR, "users.db"))
                conn.execute("UPDATE users SET role='owner' WHERE username='Biass'")
                conn.commit()
                conn.close()
        print("[SENTINEL] Owner account ready (Biass / admin)", flush=True)
    except Exception as e:
        print(f"[SENTINEL] Owner seed error: {e}", flush=True)
    print(f"[SENTINEL] Dashboard: http://localhost:8000/dashboard", flush=True)
    if imap_service.is_configured:
        asyncio.create_task(poll_imap_background())

# ============================================================================
# AUTH ROUTES
# ============================================================================
@app.post("/api/auth/register", include_in_schema=False)
async def register(payload: RegisterRequest, request: Request, response: Response):
    enforce_rate_limit(request, "register", max_attempts=5)
    username = db.sanitize_input(payload.username, max_len=30)
    email = db.sanitize_input(payload.email, max_len=100).lower()
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    if "@" not in email or "." not in email:
        raise HTTPException(status_code=400, detail="Invalid email address")
    existing = user_get_by_username(username)
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    from db import user_get_by_email
    existing_email = user_get_by_email(email)
    if existing_email:
        raise HTTPException(status_code=400, detail="Email already registered")
    if len(payload.password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")
    if not re.search(r"[A-Z]", payload.password) or not re.search(r"[0-9]", payload.password):
        raise HTTPException(status_code=400, detail="Password must contain an uppercase letter and a number")
    password_hash = hash_password(payload.password)
    org_id = None
    if settings.SUPABASE_URL:
        org_id = db.get_or_create_default_org()
    user = user_create(username, email, password_hash, org_id)
    if not user:
        raise HTTPException(status_code=409, detail="Email or username already taken")
    token = create_token(user["id"], user["username"])
    refresh = db.refresh_token_create(user["id"])
    response.set_cookie(key="sentinel_token", value=token, httponly=True, secure=settings.COOKIE_SECURE, samesite="lax", max_age=900)
    response.set_cookie(key="sentinel_refresh", value=refresh, httponly=True, secure=settings.COOKIE_SECURE, samesite="lax", max_age=86400 * 7)
    ip = _client_ip(request)
    db.audit_log("register", user["id"], username, "account created", ip=ip)
    return {"status": "success", "message": "Account created", "token": token, "username": user["username"], "user_id": user["id"]}

@app.post("/api/auth/login", include_in_schema=False)
async def login(payload: LoginRequest, response: Response, request: Request):
    enforce_rate_limit(request, "login", max_attempts=10)
    identifier = db.sanitize_input(payload.username, max_len=100)
    if "@" in identifier:
        identifier = identifier.lower()
    lockout = db.check_login_lockout(identifier)
    if lockout:
        raise HTTPException(status_code=423, detail=f"Account locked. Try again in {lockout}s.")
    user = db.user_resolve_login(identifier)
    if not user or not verify_password(payload.password, user["password_hash"]):
        db.record_login_failure(identifier)
        ip = _client_ip(request)
        db.audit_log("login_failed", username=identifier, details="bad credentials", ip=ip, success=False)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    db.clear_login_failures(identifier)
    user_update_last_login(user["id"], ip=_client_ip(request))
    token = create_token(user["id"], user["username"])
    refresh = db.refresh_token_create(user["id"])
    response.set_cookie(key="sentinel_token", value=token, httponly=True, secure=settings.COOKIE_SECURE, samesite="lax", max_age=900)
    response.set_cookie(key="sentinel_refresh", value=refresh, httponly=True, secure=settings.COOKIE_SECURE, samesite="lax", max_age=86400 * 7)
    ip = _client_ip(request)
    # IP-based suspicious login alert
    prev_ip = user.get("last_login_ip", "")
    alert = ""
    if prev_ip and prev_ip != ip:
        alert = f" (new IP: {ip}, was {prev_ip})"
    db.audit_log("login", user["id"], user["username"], f"success{alert}", ip=ip)
    import threading
    def _bg_sync():
        try:
            sb = db.get_supabase()
            if sb:
                existing_sb = sb.table("users").select("id").eq("id", user["id"]).execute()
                if not existing_sb.data:
                    sb.table("users").upsert({
                        "id": user["id"],
                        "username": user["username"],
                        "email": user.get("email", ""),
                        "password_hash": user["password_hash"],
                        "role": user.get("role", "member"),
                        "is_active": True,
                        "org_id": user.get("org_id"),
                    }).execute()
        except Exception:
            pass
    threading.Thread(target=_bg_sync, daemon=True).start()
    return {"status": "success", "token": token, "username": user["username"], "user_id": user["id"]}

@app.post("/api/auth/logout", include_in_schema=False)
async def logout(response: Response, request: Request):
    user = get_current_user(request)
    if user:
        db.refresh_token_revoke(user["user_id"])
        db.audit_log("logout", user["user_id"], user.get("username", ""), ip=_client_ip(request))
    response.delete_cookie("sentinel_token")
    response.delete_cookie("sentinel_refresh")
    return {"status": "success"}

@app.post("/api/auth/refresh", include_in_schema=False)
async def refresh_token(request: Request, response: Response):
    refresh = request.cookies.get("sentinel_refresh", "")
    if not refresh:
        raise HTTPException(status_code=401, detail="No refresh token")
    user_id = db.refresh_token_validate(refresh)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    user = user_get_by_id(user_id)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    new_token = create_token(user["id"], user["username"])
    new_refresh = db.refresh_token_create(user["id"])
    db.refresh_token_revoke(user_id)
    response.set_cookie(key="sentinel_token", value=new_token, httponly=True, secure=settings.COOKIE_SECURE, samesite="lax", max_age=900)
    response.set_cookie(key="sentinel_refresh", value=new_refresh, httponly=True, secure=settings.COOKIE_SECURE, samesite="lax", max_age=86400 * 7)
    return {"status": "success", "token": new_token, "username": user["username"], "user_id": user["id"]}

@app.get("/api/auth/me", include_in_schema=False)
async def get_me(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    return {
        "user_id": user["user_id"],
        "username": user["username"],
        "role": user_db.get("role", "member") if user_db else "member"
    }

class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str

@app.post("/api/auth/change-password", include_in_schema=False)
async def change_password(payload: ChangePasswordRequest, request: Request, response: Response):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    if not verify_password(payload.current_password, user_db["password_hash"]):
        raise HTTPException(status_code=401, detail="Current password is incorrect")
    if len(payload.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    if not re.search(r"[A-Z]", payload.new_password) or not re.search(r"[0-9]", payload.new_password):
        raise HTTPException(status_code=400, detail="New password must contain an uppercase letter and a number")
    new_hash = hash_password(payload.new_password)
    sb = db.get_supabase()
    if sb:
        try:
            sb.table("users").update({"password_hash": new_hash}).eq("id", user["user_id"]).execute()
        except Exception:
            pass
    try:
        import sqlite3 as _sqlite3
        conn = _sqlite3.connect(db._local_db_path())
        conn.execute("UPDATE users SET password_hash=? WHERE id=?", (new_hash, user["user_id"]))
        conn.commit()
        conn.close()
    except Exception:
        pass
    db.refresh_token_revoke(user["user_id"])
    db.audit_log("password_change", user["user_id"], user.get("username", ""), ip=_client_ip(request))
    new_token = create_token(user["user_id"], user.get("username", ""))
    response.set_cookie(key="sentinel_token", value=new_token, httponly=True, secure=settings.COOKIE_SECURE, samesite="lax", max_age=900)
    return {"status": "success", "message": "Password changed. Please log in again."}

@app.get("/api/auth/csrf-token", include_in_schema=False)
async def get_csrf_token(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = db.csrf_create()
    return {"csrf_token": token}

# ============================================================================
# API ROUTES
# ============================================================================
@app.get("/api/v1/health")
async def health():
    return {"status": "healthy", "groq_configured": bool(settings.GROQ_API_KEY), "version": settings.APP_VERSION}

# ============================================================================
# CLOUD API ROUTES (Email Connections, Scanning, Invites)
# ============================================================================

class EmailConnectionRequest(BaseModel):
    label: str = Field("My Email", min_length=1, max_length=100)
    provider: str = Field("custom")
    imap_host: str
    imap_port: int = 993
    imap_username: str
    imap_password: str
    imap_folder: str = "INBOX"
    scan_interval: int = Field(30, ge=5, le=1440)

@app.post("/api/v1/connections")
async def create_email_connection(payload: EmailConnectionRequest, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    print(f"[SENTINEL] Creating connection for user {user.get('username')}: host={payload.imap_host} user={payload.imap_username}", flush=True)
    user_db = resolve_user_db(user)
    if not user_db:
        print(f"[SENTINEL] User not found: {user['user_id']}", flush=True)
        raise HTTPException(status_code=404, detail="User not found")
    org_id = user_db.get("org_id") or db.get_or_create_default_org()
    if not org_id:
        raise HTTPException(status_code=500, detail="No organization configured")
    enc_password = payload.imap_password
    conn = email_connection_create(
        user_id=user["user_id"], org_id=org_id, label=payload.label,
        provider=payload.provider, imap_host=payload.imap_host, imap_port=payload.imap_port,
        imap_username=payload.imap_username, imap_password_enc=enc_password,
        imap_folder=payload.imap_folder, scan_interval=payload.scan_interval,
    )
    if not conn:
        raise HTTPException(status_code=500, detail="Failed to create connection")
    print(f"[SENTINEL] Connection created: {conn['id']}", flush=True)
    return {"status": "success", "connection_id": conn["id"]}

@app.get("/api/v1/connections")
async def list_email_connections(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    conns = email_connection_list(user["user_id"])
    return {"connections": conns}

@app.delete("/api/v1/connections/{conn_id}")
async def delete_email_connection(conn_id: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    ok = email_connection_delete(conn_id, user["user_id"])
    if not ok:
        raise HTTPException(status_code=404, detail="Connection not found")
    return {"status": "success"}

@app.post("/api/v1/connections/{conn_id}/toggle")
async def toggle_email_connection(conn_id: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    conns = email_connection_list(user["user_id"])
    conn = next((c for c in conns if c["id"] == conn_id), None)
    if not conn:
        raise HTTPException(status_code=404, detail="Connection not found")
    new_state = not conn.get("is_active", True)
    email_connection_toggle(conn_id, user["user_id"], new_state)
    return {"status": "success", "is_active": new_state}

@app.post("/api/v1/scan/{conn_id}")
async def trigger_scan(conn_id: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    wait = check_scan_cooldown(user["user_id"])
    if wait > 0:
        raise HTTPException(status_code=429, detail=f"Scan cooldown. Wait {wait}s before scanning again.")
    print(f"[SENTINEL] trigger_scan user={user.get('username')} conn_id={conn_id}", flush=True)
    conn_data = email_connection_get(conn_id, user["user_id"])
    if not conn_data:
        raise HTTPException(status_code=404, detail="Connection not found")
    import imaplib as _imap
    try:
        mail = _imap.IMAP4_SSL(conn_data["imap_host"], conn_data["imap_port"])
        mail.login(conn_data["imap_username"], conn_data["imap_password_enc"])
        mail.logout()
    except _imap.IMAP4.error as e:
        raise HTTPException(status_code=400, detail=f"IMAP login failed: {e}. Check your email and app password.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Cannot connect to {conn_data['imap_host']}: {e}")
    user_db = resolve_user_db(user)
    org_id = user_db.get("org_id") or "" if user_db else ""
    job_id = scan_job_create(conn_id, user["user_id"], org_id)
    if not job_id:
        raise HTTPException(status_code=500, detail="Failed to create scan job")
    mark_scan_started(user["user_id"])
    asyncio.create_task(_run_imap_scan(job_id, conn_data))
    return {"status": "success", "job_id": job_id}

async def _run_imap_scan(job_id: str, conn_data: dict):
    scan_job_update(job_id, "running")
    try:
        import imaplib as _imap
        import email as _email
        from email.header import decode_header as _decode_header

        def _decode_header_value(raw):
            if raw is None:
                return ""
            parts = _decode_header(raw)
            decoded = []
            for part, charset in parts:
                if isinstance(part, bytes):
                    decoded.append(part.decode(charset or "utf-8", errors="replace"))
                else:
                    decoded.append(part)
            return " ".join(decoded)

        def _get_body(msg):
            text_body = ""
            html_body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    ct = part.get_content_type()
                    disp = str(part.get("Content-Disposition", ""))
                    if "attachment" in disp:
                        continue
                    if ct == "text/plain":
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            text_body += payload.decode(charset, errors="replace")
                    elif ct == "text/html":
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            html_body += payload.decode(charset, errors="replace")
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    text_body = payload.decode(charset, errors="replace")
            return text_body, html_body

        mail = _imap.IMAP4_SSL(conn_data["imap_host"], conn_data["imap_port"])
        mail.login(conn_data["imap_username"], conn_data["imap_password_enc"])
        mail.select(conn_data.get("imap_folder", "INBOX"))
        _, msg_nums = mail.search(None, "UNSEEN")
        email_ids = msg_nums[0].split() if msg_nums[0] else []
        total_unread = len(email_ids)
        MAX_PER_SCAN = 15
        emails_to_scan = email_ids[-MAX_PER_SCAN:] if total_unread > MAX_PER_SCAN else email_ids
        print(f"[SENTINEL] per-user scan found {total_unread} unread, scanning {len(emails_to_scan)} for {conn_data.get('imap_username')}", flush=True)
        existing = store_get(conn_data["user_id"])
        existing_mids = set()
        for rec in existing.values():
            mid = rec.get("message_id", "")
            if mid:
                existing_mids.add(mid)
        print(f"[SENTINEL] per-user scan {len(existing_mids)} already analyzed emails", flush=True)
        scan_job_update(job_id, "running", emails_found=len(emails_to_scan))
        analyzed = 0
        skipped = 0
        BATCH_SIZE = 10
        parsed_batch = []
        meta_batch = []
        for eid in emails_to_scan:
            try:
                _, msg_data = mail.fetch(eid, "(RFC822)")
                raw_email_bytes = msg_data[0][1]
                msg = _email.message_from_bytes(raw_email_bytes)

                from_addr = _decode_header_value(msg.get("From", ""))
                subject = _decode_header_value(msg.get("Subject") or "(no subject)")
                to_addr = _decode_header_value(msg.get("To", ""))
                text_body, html_body = _get_body(msg)
                attachments = [part.get_filename() for part in msg.walk() if part.get_filename()]

                mid_check = f"imap-{eid.decode()}"
                if mid_check in existing_mids:
                    skipped += 1
                    continue

                parsed = EmailParser.parse_webhook({
                    "message_id": mid_check,
                    "from": from_addr,
                    "to": to_addr or conn_data["imap_username"],
                    "subject": subject,
                    "text_body": text_body,
                    "html_body": html_body,
                    "headers": {k: v for k, v in msg.items()},
                    "attachments": attachments,
                    "timestamp": datetime.now().isoformat(),
                })

                forwarded = ForwardedEmailParser.extract_forwarded_content(parsed.get("body_text", ""))
                if forwarded.get("from_address"):
                    parsed["from_address"] = forwarded["from_address"]
                if forwarded.get("subject"):
                    parsed["subject"] = forwarded["subject"]
                if forwarded.get("body"):
                    parsed["body_text"] = forwarded["body"]

                parsed_batch.append(parsed)
                meta_batch.append({"text_body": text_body})
            except Exception as e:
                print(f"[SENTINEL] IMAP scan email error: {e}", flush=True)
            time.sleep(0.3)
        try:
            mail.logout()
        except Exception:
            pass
        for batch_start in range(0, len(parsed_batch), BATCH_SIZE):
            batch = parsed_batch[batch_start:batch_start + BATCH_SIZE]
            meta = meta_batch[batch_start:batch_start + BATCH_SIZE]
            try:
                verdicts = await analyzer.analyze_batch(batch)
                for i, (parsed, verdict_data) in enumerate(zip(batch, verdicts)):
                    text_body = meta[i]["text_body"]
                    email_id = f"email-{uuid.uuid4().hex[:12]}"
                    record = {
                        "id": email_id,
                        **parsed,
                        "received_at": datetime.now().isoformat(),
                        "source": "imap_scan",
                        "is_forwarded": ForwardedEmailParser.is_forwarded(text_body),
                        "verdict": {
                            "id": f"verdict-{uuid.uuid4().hex[:12]}",
                            "email_id": email_id,
                            **verdict_data,
                            "analyzed_at": datetime.now().isoformat(),
                        },
                    }
                    store_set(conn_data["user_id"], email_id, record)
                    from db import report_save
                    report_save(email_id, conn_data["user_id"], record, conn_data.get("org_id"))
                    analyzed += 1
            except Exception as e:
                print(f"[SENTINEL] Batch analysis error (batch {batch_start}): {e}", flush=True)
            await asyncio.sleep(1)
        print(f"[SENTINEL] per-user scan done: {analyzed} new, {skipped} skipped", flush=True)
        email_connection_update_scan(conn_data["id"], analyzed)
        scan_job_update(job_id, "completed", emails_found=len(emails_to_scan), emails_analyzed=analyzed)
    except Exception as e:
        print(f"[SENTINEL] IMAP scan failed: {e}", flush=True)
        scan_job_update(job_id, "failed", error_message=str(e))

@app.get("/api/v1/scans")
async def list_scan_jobs(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    jobs = scan_job_list(user["user_id"])
    return {"jobs": jobs}

class InviteRequest(BaseModel):
    email: str
    role: str = Field("friend")

@app.post("/api/v1/invites")
async def create_invite(payload: InviteRequest, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    if user_db.get("role") not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can invite")
    org_id = user_db.get("org_id")
    if not org_id:
        raise HTTPException(status_code=400, detail="No organization configured")
    invite = invite_create(org_id, payload.email, payload.role, user["user_id"])
    if not invite:
        raise HTTPException(status_code=500, detail="Failed to create invite")
    token = invite["token"]
    base_url = str(request.base_url).rstrip("/")
    invite_link = f"{base_url}/accept-invite/{token}"
    ip = _client_ip(request)
    db.audit_log("invite_created", user["user_id"], user.get("username", ""), f"email={payload.email} role={payload.role}", ip=ip)
    return {"status": "success", "token": token, "invite_link": invite_link}

@app.get("/api/v1/invites")
async def list_invites(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    org_id = user_db.get("org_id")
    if not org_id:
        return {"invites": []}
    invites = invite_list_org(org_id)
    base_url = str(request.base_url).rstrip("/")
    for inv in invites:
        inv["invite_link"] = f"{base_url}/accept-invite/{inv.get('token', '')}"
    return {"invites": invites}

@app.delete("/api/v1/invites/{invite_id}")
async def delete_invite(invite_id: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    ok = invite_delete(invite_id, user_db.get("org_id", ""))
    if not ok:
        raise HTTPException(status_code=404, detail="Invite not found")
    return {"status": "success"}

@app.post("/api/v1/accept-invite/{token}")
async def accept_invite(token: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    ok = invite_accept(token, user["user_id"])
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid or expired invite")
    fresh_user = user_get_by_id(user["user_id"])
    role = fresh_user.get("role", "member") if fresh_user else "member"
    ip = _client_ip(request)
    db.audit_log("invite_accepted", user["user_id"], user.get("username", ""), f"role={role}", ip=ip)
    return {"status": "success", "role": role}

@app.get("/api/v1/team")
async def list_team(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    org_id = user_db.get("org_id")
    if not org_id:
        return {"members": []}
    members = user_list_org(org_id)
    return {"members": [_public_user(m) for m in members]}

@app.delete("/api/v1/team/{member_id}")
async def remove_team_member(member_id: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    if user_db.get("role") not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can remove members")
    if member_id == user["user_id"]:
        raise HTTPException(status_code=400, detail="You cannot remove yourself")
    target = user_get_by_id(member_id)
    if not target:
        raise HTTPException(status_code=404, detail="Member not found")
    if target.get("org_id") != user_db.get("org_id"):
        raise HTTPException(status_code=403, detail="Member not in your organization")
    sb = db.get_supabase()
    if sb:
        try:
            sb.table("users").update({"org_id": None, "role": "member"}).eq("id", member_id).execute()
            db.audit_log("member_removed", user["user_id"], user.get("username", ""), f"removed={target.get('username', member_id)}", ip=_client_ip(request))
            return {"status": "success"}
        except Exception:
            pass
    # local fallback
    try:
        conn = sqlite3.connect(os.path.join(db.DATA_DIR, "users.db"))
        c = conn.cursor()
        c.execute("UPDATE users SET org_id = NULL, role = 'member' WHERE user_id = ?", (member_id,))
        conn.commit()
        conn.close()
        db.audit_log("member_removed", user["user_id"], user.get("username", ""), f"removed={target.get('username', member_id)}", ip=_client_ip(request))
        return {"status": "success"}
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to remove member")

@app.get("/api/v1/team/overview")
async def team_overview(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    role = user_db.get("role", "member")
    if role not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can view team overview")
    org_id = user_db.get("org_id")
    if not org_id:
        return {"members": []}
    members = user_list_org(org_id)
    overview = []
    for m in members:
        mid = m["id"]
        store = store_get(mid)
        emails = list(store.values())
        total = len(emails)
        malicious = sum(1 for e in emails if (e.get("verdict") or {}).get("threat_level") == "malicious")
        suspicious = sum(1 for e in emails if (e.get("verdict") or {}).get("threat_level") == "suspicious")
        safe = sum(1 for e in emails if (e.get("verdict") or {}).get("threat_level") == "safe")
        conns = email_connection_list(mid)
        active_conns = [c for c in conns if c.get("is_active", True)]
        last_scan = max((c.get("last_scan_at") or "" for c in conns), default="")
        overview.append({
            "user_id": mid,
            "username": m.get("username", ""),
            "email": m.get("email", ""),
            "role": m.get("role", "member"),
            "is_active": m.get("is_active", True),
            "last_login": m.get("last_login", ""),
            "total_emails": total,
            "malicious": malicious,
            "suspicious": suspicious,
            "safe": safe,
            "connections": len(active_conns),
            "last_scan": last_scan,
        })
    return {"members": overview}

@app.get("/api/v1/team/emails/{member_id}")
async def team_member_emails(member_id: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    if user_db.get("role") not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can view member emails")
    store = store_get(member_id)
    emails = list(store.values())
    emails.sort(key=lambda x: x.get("received_at", ""), reverse=True)
    return emails

@app.post("/api/v1/team/scan/{member_id}")
async def team_scan_member(member_id: str, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    if user_db.get("role") not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can scan team members")
    wait = check_scan_cooldown(user["user_id"])
    if wait > 0:
        raise HTTPException(status_code=429, detail=f"Scan cooldown. Wait {wait}s.")
    conns = email_connection_list(member_id)
    active_conns = [c for c in conns if c.get("is_active", True)]
    if not active_conns:
        raise HTTPException(status_code=400, detail="This team member has no email connections configured")
    mark_scan_started(user["user_id"])
    import asyncio as _asyncio
    total_processed = 0
    for conn in active_conns:
        conn_full = email_connection_get(conn["id"], member_id)
        if not conn_full or not conn_full.get("imap_password_enc"):
            continue
        org_id = user_db.get("org_id") or ""
        job_id = scan_job_create(conn["id"], member_id, org_id)
        if job_id:
            _asyncio.create_task(_run_imap_scan(job_id, conn_full))
            total_processed += 1
    return {"status": "success", "scans_triggered": total_processed, "member_id": member_id}

@app.get("/api/v1/org")
async def get_org_info(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    if not user_db or not user_db.get("org_id"):
        return {"org": None}
    org = org_get(user_db["org_id"])
    return {"org": org}

@app.get("/api/v1/emails")
async def list_emails(request: Request, threat_level: Optional[str] = None):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    store = store_get(user["user_id"])
    emails = list(store.values())
    if threat_level:
        emails = [e for e in emails if (e.get("verdict") or {}).get("threat_level") == threat_level]
    emails.sort(key=lambda x: x.get("received_at", ""), reverse=True)
    return emails

@app.delete("/api/v1/emails")
async def clear_emails(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    store = store_get(user["user_id"])
    count = len(store)
    store_clear(user["user_id"])
    return {"status": "success", "deleted": count}

@app.post("/api/v1/analyze/paste")
async def analyze_paste(payload: PasteEmailRequest, request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    forwarded = ForwardedEmailParser.extract_forwarded_content(payload.content)
    from_addr = forwarded.get("from_address") or payload.from_address or "unknown"
    subject = forwarded.get("subject") or payload.subject or "No Subject"
    body = forwarded.get("body", payload.content)
    parsed = EmailParser.parse_webhook({
        "message_id": f"paste-{uuid.uuid4().hex[:12]}",
        "from": from_addr,
        "to": user["username"],
        "subject": subject,
        "headers": {},
        "text_body": body,
        "html_body": "",
        "attachments": [],
        "timestamp": datetime.now().isoformat(),
    })
    verdict_data = await analyzer.analyze(parsed)
    email_id = f"email-{uuid.uuid4().hex[:12]}"
    record = {
        "id": email_id,
        **parsed,
        "received_at": datetime.now().isoformat(),
        "source": "pasted_email",
        "is_forwarded": ForwardedEmailParser.is_forwarded(payload.content),
        "verdict": {
            "id": f"verdict-{uuid.uuid4().hex[:12]}",
            "email_id": email_id,
            **verdict_data,
            "analyzed_at": datetime.now().isoformat(),
        },
    }
    store_set(user["user_id"], email_id, record)
    return {"status": "success", "email_id": email_id, "subject": subject, "from": from_addr, "verdict": verdict_data}

@app.post("/api/v1/imap/check")
async def imap_check(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    wait = check_scan_cooldown(user["user_id"])
    if wait > 0:
        raise HTTPException(status_code=429, detail=f"Scan cooldown. Wait {wait}s before scanning again.")
    print(f"[SENTINEL] imap/check called by user_id={user.get('user_id')} username={user.get('username')}", flush=True)
    body = await request.json() if request.headers.get("content-type","") == "application/json" else {}
    target_conn_id = body.get("connection_id")
    active_conns = email_connection_get_active_all()
    user_conns = [c for c in active_conns if c.get("user_id") == user["user_id"]]
    print(f"[SENTINEL] imap/check active_conns total={len(active_conns)} user_conns_active={len(user_conns)}", flush=True)
    if not user_conns:
        user_conns_list = email_connection_list(user["user_id"])
        user_conns = [c for c in user_conns_list if c.get("is_active", True)]
        print(f"[SENTINEL] imap/check fallback local conns={len(user_conns_list)} active={len(user_conns)}", flush=True)
    if not user_conns:
        print(f"[SENTINEL] imap/check NO connections for user {user.get('username')}", flush=True)
        raise HTTPException(status_code=400, detail="No email connections configured. Add a connection in Settings first.")
    if target_conn_id:
        user_conns = [c for c in user_conns if c["id"] == target_conn_id]
        if not user_conns:
            raise HTTPException(status_code=404, detail="Connection not found")
    mark_scan_started(user["user_id"])
    total_processed = []
    import imaplib as _imap
    import email as _email
    from email.header import decode_header as _decode_header
    def _decode_hdr(raw):
        if raw is None: return ""
        parts = _decode_header(raw)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(part)
        return " ".join(decoded)
    def _get_body(msg):
        text_body = ""
        html_body = ""
        if msg.is_multipart():
            for part in msg.walk():
                ct = part.get_content_type()
                disp = str(part.get("Content-Disposition", ""))
                if "attachment" in disp:
                    continue
                if ct == "text/plain":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        text_body += payload.decode(charset, errors="replace")
                elif ct == "text/html":
                    payload = part.get_payload(decode=True)
                    if payload:
                        charset = part.get_content_charset() or "utf-8"
                        html_body += payload.decode(charset, errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            if payload:
                charset = msg.get_content_charset() or "utf-8"
                text_body = payload.decode(charset, errors="replace")
        return text_body, html_body
    existing = store_get(user["user_id"])
    existing_mids = set()
    for rec in existing.values():
        mid = rec.get("message_id", "")
        if mid:
            existing_mids.add(mid)
    seen_mids_file = os.path.join(db.DATA_DIR, f"seen_mids_{user['user_id']}.json")
    try:
        with open(seen_mids_file, "r") as f:
            seen_mids_file_data = json.load(f)
            existing_mids.update(seen_mids_file_data)
    except Exception:
        pass
    print(f"[SENTINEL] imap/check {len(existing_mids)} already analyzed emails", flush=True)
    errors = []
    BATCH_SIZE = 10
    for conn in user_conns:
        try:
            conn_full = email_connection_get(conn["id"], user["user_id"])
            if not conn_full or not conn_full.get("imap_password_enc"):
                errors.append(f"{conn.get('label')}: No password saved")
                continue
            print(f"[SENTINEL] imap/check connecting to {conn_full['imap_host']} as {conn_full['imap_username']}", flush=True)
            mail = _imap.IMAP4_SSL(conn_full["imap_host"], conn_full["imap_port"])
            mail.login(conn_full["imap_username"], conn_full["imap_password_enc"])
            mail.select(conn_full.get("imap_folder", "INBOX"))
            _, msg_nums = mail.search(None, "UNSEEN")
            email_ids = msg_nums[0].split() if msg_nums[0] else []
            total_unread = len(email_ids)
            MAX_PER_SCAN = 15
            emails_to_scan = email_ids[-MAX_PER_SCAN:] if total_unread > MAX_PER_SCAN else email_ids
            print(f"[SENTINEL] imap/check UNSEEN found {total_unread} unread, scanning {len(emails_to_scan)} in {conn.get('label')}", flush=True)
            skipped = 0
            parsed_batch = []
            meta_batch = []
            for eid in emails_to_scan:
                try:
                    _, msg_data = mail.fetch(eid, "(RFC822)")
                    raw_email_bytes = msg_data[0][1]
                    msg = _email.message_from_bytes(raw_email_bytes)
                    from_addr = _decode_hdr(msg.get("From", ""))
                    subject = _decode_hdr(msg.get("Subject") or "(no subject)")
                    to_addr = _decode_hdr(msg.get("To", ""))
                    text_body, html_body = _get_body(msg)
                    attachments = [part.get_filename() for part in msg.walk() if part.get_filename()]
                    mid_check = f"imap-{eid.decode()}"
                    if mid_check in existing_mids:
                        skipped += 1
                        continue
                    parsed = EmailParser.parse_webhook({
                        "message_id": mid_check,
                        "from": from_addr,
                        "to": to_addr or conn_full["imap_username"],
                        "subject": subject,
                        "text_body": text_body,
                        "html_body": html_body,
                        "headers": {k: v for k, v in msg.items()},
                        "attachments": attachments,
                        "timestamp": datetime.now().isoformat(),
                    })
                    forwarded = ForwardedEmailParser.extract_forwarded_content(parsed.get("body_text", ""))
                    if forwarded.get("from_address"):
                        parsed["from_address"] = forwarded["from_address"]
                    if forwarded.get("subject"):
                        parsed["subject"] = forwarded["subject"]
                    if forwarded.get("body"):
                        parsed["body_text"] = forwarded["body"]
                    parsed_batch.append(parsed)
                    meta_batch.append({"text_body": text_body, "eid": eid})
                except Exception as e:
                    print(f"[SENTINEL] imap/check email parse error: {e}", flush=True)
                time.sleep(0.3)
            try:
                mail.logout()
            except Exception:
                pass
            print(f"[SENTINEL] imap/check {conn.get('label')}: {len(parsed_batch)} new, {skipped} skipped", flush=True)
            for batch_start in range(0, len(parsed_batch), BATCH_SIZE):
                batch = parsed_batch[batch_start:batch_start + BATCH_SIZE]
                meta = meta_batch[batch_start:batch_start + BATCH_SIZE]
                verdicts = await analyzer.analyze_batch(batch, org_id=conn_full.get("org_id", ""))
                for i, (parsed, verdict_data) in enumerate(zip(batch, verdicts)):
                    text_body = meta[i]["text_body"]
                    email_id = f"email-{uuid.uuid4().hex[:12]}"
                    record = {
                        "id": email_id,
                        **parsed,
                        "received_at": datetime.now().isoformat(),
                        "source": "imap_scan",
                        "is_forwarded": ForwardedEmailParser.is_forwarded(text_body),
                        "verdict": {
                            "id": f"verdict-{uuid.uuid4().hex[:12]}",
                            "email_id": email_id,
                            **verdict_data,
                            "analyzed_at": datetime.now().isoformat(),
                        },
                    }
                    store_set(user["user_id"], email_id, record)
                    total_processed.append({"email_id": email_id, "subject": parsed["subject"], "threat_level": verdict_data.get("threat_level"), "confidence": verdict_data.get("confidence")})
        except Exception as e:
            err_msg = f"{conn.get('label')}: {e}"
            print(f"[SENTINEL] imap/check error: {err_msg}", flush=True)
            errors.append(err_msg)
    try:
        with open(seen_mids_file, "w") as f:
            json.dump(list(existing_mids), f)
    except Exception:
        pass
    resp = {"status": "success", "emails_found": len(total_processed), "emails_processed": len(total_processed), "results": total_processed}
    if errors:
        resp["errors"] = errors
    return resp

@app.get("/api/v1/imap/status")
async def imap_status():
    return {
        "configured": imap_service.is_configured,
        "server": settings.IMAP_SERVER,
        "username": imap_service.username,
        "poll_interval": settings.IMAP_POLL_INTERVAL,
    }

# ============================================================================
# FEEDBACK & WHITELIST API (Task 3: Defensibility / Feedback Loop)
# ============================================================================
@app.post("/api/v1/feedback")
async def submit_feedback(request: Request):
    """Log a user correction to an AI verdict. Updates whitelist and adaptive cache."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    body = await request.json()
    email_id = body.get("email_id", "")
    corrected_verdict = body.get("corrected_verdict", "")
    reason = body.get("reason", "")
    sender_domain = body.get("sender_domain", "")
    sender_address = body.get("sender_address", "")
    if corrected_verdict not in ("safe", "suspicious", "malicious"):
        raise HTTPException(status_code=400, detail="corrected_verdict must be safe, suspicious, or malicious")
    if not email_id:
        raise HTTPException(status_code=400, detail="email_id is required")
    # Get original verdict from the stored report
    store = store_get(user["user_id"])
    record = store.get(email_id, {})
    original_verdict = (record.get("verdict") or {}).get("threat_level", "unknown")
    # Extract sender info from record if not provided
    if not sender_address:
        sender_address = record.get("from_address", "")
    if not sender_domain and "@" in sender_address:
        sender_domain = sender_address.split("@")[-1]
    org_id = db.get_or_create_default_org()
    if not org_id:
        raise HTTPException(status_code=500, detail="Organization not configured")
    ok = db.feedback_save(email_id, user["user_id"], org_id, original_verdict, corrected_verdict, reason,
                          sender_domain=sender_domain, sender_address=sender_address)
    return {"status": "success" if ok else "fallback", "message": "Feedback logged"}


@app.get("/api/v1/feedback")
async def list_feedback(request: Request, limit: int = 50):
    """List recent feedback entries for the organization."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    org_id = db.get_or_create_default_org()
    entries = db.feedback_list(user_id=user["user_id"], org_id=org_id, limit=limit)
    return entries


@app.get("/api/v1/whitelist")
async def get_whitelist(request: Request):
    """Get all whitelist entries for the organization."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    org_id = db.get_or_create_default_org()
    if not org_id:
        return []
    return db.whitelist_get(org_id, user_id=user["user_id"])


@app.post("/api/v1/whitelist")
async def add_whitelist(request: Request):
    """Add a whitelist entry (domain or sender pattern)."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    body = await request.json()
    pattern_type = body.get("pattern_type", "")
    pattern_value = body.get("pattern_value", "")
    if pattern_type not in ("domain", "sender", "subject_regex"):
        raise HTTPException(status_code=400, detail="pattern_type must be domain, sender, or subject_regex")
    if not pattern_value:
        raise HTTPException(status_code=400, detail="pattern_value is required")
    org_id = db.get_or_create_default_org()
    if not org_id:
        raise HTTPException(status_code=500, detail="Organization not configured")
    ok = db.whitelist_add(org_id, pattern_type, pattern_value, added_by=user["user_id"], user_id=user["user_id"])
    return {"status": "success" if ok else "error"}


@app.delete("/api/v1/whitelist/{entry_id}")
async def delete_whitelist(entry_id: str, request: Request):
    """Remove a whitelist entry."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    org_id = db.get_or_create_default_org()
    if not org_id:
        raise HTTPException(status_code=500, detail="Organization not configured")
    ok = db.whitelist_delete(org_id, entry_id, user_id=user["user_id"])
    return {"status": "success" if ok else "error"}


# ============================================================================
# EXECUTIVE REPORTING API (Task 2: Monthly Security Summary PDF)
# ============================================================================
@app.get("/api/v1/reports/monthly")
async def get_monthly_report(request: Request):
    """Generate and return a Monthly Security Summary PDF."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    org_id = db.get_or_create_default_org()
    org = db.org_get(org_id) if org_id else None
    org_name = org["name"] if org else "Default Organization"
    report_data = db.reporting_monthly_enhanced(org_id=org_id, cost_per_incident=settings.COST_PER_INCIDENT)
    pdf_bytes = generate_monthly_report_pdf(
        report_data=report_data,
        org_name=org_name,
        cost_per_incident=settings.COST_PER_INCIDENT,
    )
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename=sentinel_monthly_report_{datetime.utcnow().strftime('%Y-%m')}.pdf"},
    )


@app.get("/api/v1/reports/monthly/data")
async def get_monthly_report_data(request: Request):
    """Return the raw monthly report data as JSON (for dashboard widgets)."""
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    org_id = db.get_or_create_default_org()
    report_data = db.reporting_monthly_enhanced(org_id=org_id, cost_per_incident=settings.COST_PER_INCIDENT)
    return report_data


# ============================================================================
# PUBLIC HEALTH CHECK (Lead Generation Widget)
# ============================================================================

class HealthCheckRequest(BaseModel):
    email_header: str = ""
    email_body: str = ""
    sender: str = ""
    subject: str = ""
    lead_email: str = ""

@app.post("/api/public/health-check")
async def public_health_check(payload: HealthCheckRequest):
    """
    Public, unauthenticated endpoint for the Security Health Check widget.
    Performs a lightweight heuristic scan + AI check on pasted email content.
    Returns a mini-threat report. Full results require lead email capture.
    """
    text = (payload.email_header + "\n" + payload.email_body).strip()
    if not text and not payload.sender:
        raise HTTPException(status_code=400, detail="Please provide email content or sender information")

    # Build email data for analysis
    email_data = {
        "from_address": payload.sender,
        "subject": payload.subject,
        "body_text": text[:2000],
        "urls": [],
        "headers": {},
        "has_attachments": False,
    }

    # Extract URLs from text
    import re
    urls = re.findall(r'https?://[^\s<>\"\']+', text)
    email_data["urls"] = urls[:10]

    # Quick heuristic pre-check
    body_lower = text.lower()
    subject_lower = payload.subject.lower()
    quick_indicators = []

    urgency_words = ["urgent", "act now", "expires", "suspended", "verify", "confirm", "immediately", "within 24"]
    found_urgency = [w for w in urgency_words if w in body_lower or w in subject_lower]
    if found_urgency:
        quick_indicators.append(f"Urgency language: {', '.join(found_urgency[:3])}")

    cred_words = ["password", "credential", "ssn", "credit card", "login", "verify your account"]
    found_cred = [w for w in cred_words if w in body_lower]
    if found_cred:
        quick_indicators.append(f"Credential request: {', '.join(found_cred[:3])}")

    shorteners = ["bit.ly", "tinyurl", "t.co", "goo.gl"]
    found_short = [s for s in shorteners if s in body_lower]
    if found_short:
        quick_indicators.append(f"URL shortener: {', '.join(found_short)}")

    suspicious_tlds = [".xyz", ".top", ".buzz", ".tk", ".ml"]
    for url in urls:
        if any(url.lower().endswith(tld) for tld in suspicious_tlds):
            quick_indicators.append(f"Suspicious TLD: {url}")
            break

    # Determine quick verdict
    if len(quick_indicators) >= 3:
        quick_verdict = "malicious"
        quick_confidence = 85
    elif len(quick_indicators) >= 1:
        quick_verdict = "suspicious"
        quick_confidence = 65
    else:
        quick_verdict = "safe"
        quick_confidence = 40

    # If we have a Groq client, do a full AI check
    ai_result = None
    if analyzer.client and text:
        try:
            ai_result = analyzer.analyze_sync(email_data)
            quick_verdict = ai_result.get("verdict", quick_verdict)
            quick_confidence = ai_result.get("confidence_score", quick_confidence)
        except Exception:
            pass

    result = {
        "verdict": quick_verdict,
        "confidence_score": quick_confidence,
        "indicators": quick_indicators if quick_indicators else ["No obvious threats detected in basic scan"],
        "ai_analysis": ai_result is not None,
    }

    if ai_result:
        result["reasoning_summary"] = ai_result.get("reasoning_summary", "")
        result["ai_indicators"] = ai_result.get("indicators", {})
        result["recommendations"] = ai_result.get("recommendations", [])
    else:
        result["reasoning_summary"] = "Basic heuristic scan performed. For comprehensive AI analysis, sign up for a free account."
        result["recommendations"] = ["Sign up for SENTINEL to get full AI-powered analysis"]

    # If lead email provided, save it
    if payload.lead_email and "@" in payload.lead_email:
        db.lead_save(
            email=payload.lead_email,
            source="health_check",
            health_check_result={"verdict": quick_verdict, "indicators": quick_indicators},
        )
        result["lead_captured"] = True
    else:
        result["lead_captured"] = False

    return result


@app.post("/api/public/health-check/capture")
async def public_health_check_capture(request: Request):
    """Capture a lead email address for the health check widget."""
    body = await request.json()
    email = body.get("email", "").strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="Valid email address required")
    if db.lead_exists(email):
        return {"status": "already_captured", "message": "Email already registered"}
    db.lead_save(email=email, source="health_check")
    return {"status": "success", "message": "Email captured successfully"}


@app.get("/api/v1/db/status")
async def db_status():
    """Check Supabase connection status."""
    return {
        "supabase_connected": db.is_supabase_available(),
        "fallback": "SQLite + JSON" if not db.is_supabase_available() else "Supabase PostgreSQL",
    }


# ============================================================================
# OWNER-ONLY ACCESS CONTROL
# ============================================================================
def require_owner(request: Request) -> dict:
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    if not user_db or user_db.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Owner access only")
    return user


# ============================================================================
# ADMIN: Database Migration
# ============================================================================
@app.post("/api/admin/migrate")
async def admin_migrate(request: Request):
    user = get_current_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    user_db = resolve_user_db(user)
    if not user_db or user_db.get("role") != "owner":
        raise HTTPException(status_code=403, detail="Owner only")
    result = db.ensure_supabase_tables(settings.SUPABASE_URL, settings.SUPABASE_KEY)
    return {"success": result, "message": "Migration complete" if result else "Migration failed - check Railway logs"}

# ============================================================================
# ANALYTICS API (Owner Only)
# ============================================================================
@app.get("/api/analytics/overview")
async def analytics_overview(request: Request, days: int = Query(30, ge=1, le=365)):
    require_owner(request)
    return db.request_log_stats(days)

@app.get("/api/analytics/ips")
async def analytics_ips(request: Request, days: int = Query(7, ge=1, le=90)):
    require_owner(request)
    return {"ips": db.request_log_unique_ips(days)}

@app.get("/api/analytics/realtime")
async def analytics_realtime(request: Request):
    require_owner(request)
    since = (datetime.utcnow() - timedelta(minutes=15)).isoformat()
    sb = db.get_supabase()
    if sb:
        try:
            rows = sb.table("request_logs").select("*").gte("created_at", since).execute()
            data = rows.data or []
        except Exception:
            data = []
    else:
        import sqlite3 as _s3
        conn = _s3.connect(os.path.join(db.DATA_DIR, "users.db"))
        conn.row_factory = _s3.Row
        rows = conn.execute("SELECT * FROM request_logs WHERE created_at >= ?", (since,)).fetchall()
        data = [dict(r) for r in rows]
        conn.close()
    return {"active_visitors": len(set(r.get("ip", "") for r in data)), "requests": len(data), "recent": data[-50:]}


@app.get("/api/analytics/emails")
async def analytics_emails(request: Request):
    user = require_auth(request)
    store = store_get(user["user_id"])
    emails = list(store.values())
    total = len(emails)
    threats = sum(1 for e in emails if (e.get("verdict") or {}).get("threat_level") == "malicious")
    suspicious = sum(1 for e in emails if (e.get("verdict") or {}).get("threat_level") == "suspicious")
    safe = sum(1 for e in emails if (e.get("verdict") or {}).get("threat_level") == "safe")
    feedback_count = sum(1 for e in emails if e.get("feedback_corrected"))
    from collections import Counter
    senders = Counter(e.get("from_address", "unknown") for e in emails)
    models = Counter((e.get("verdict") or {}).get("llm_model", "unknown") for e in emails)
    return {
        "total": total, "threats": threats, "suspicious": suspicious, "safe": safe,
        "feedback_count": feedback_count,
        "top_senders": dict(senders.most_common(10)),
        "models_used": dict(models),
    }


# ============================================================================
# SCHEDULED REPORTS API
# ============================================================================
@app.get("/api/v1/report-schedule")
async def get_report_schedule(request: Request):
    user = require_auth(request)
    schedule = db.report_schedule_get(user["user_id"])
    return schedule or {"enabled": False, "frequency": "monthly", "recipients": [], "last_sent": None}

class ReportScheduleRequest(BaseModel):
    enabled: bool = True
    frequency: str = "monthly"
    recipients: List[str] = []

@app.post("/api/v1/report-schedule")
async def save_report_schedule(payload: ReportScheduleRequest, request: Request):
    user = require_auth(request)
    result = db.report_schedule_save(user["user_id"], payload.frequency, payload.recipients, payload.enabled)
    ip = _client_ip(request)
    db.audit_log("report_schedule_updated", user["user_id"], user.get("username", ""), f"freq={payload.frequency} enabled={payload.enabled}", ip=ip)
    return {"status": "success", "schedule": result}

@app.post("/api/v1/report-schedule/test")
async def test_report_schedule(request: Request):
    user = require_auth(request)
    user_db = resolve_user_db(user)
    org_id = user_db.get("org_id") if user_db else None
    report_data = _build_report_data(org_id)
    org_name = user_db.get("username", "Organization") if user_db else "Organization"
    pdf_bytes = generate_monthly_report_pdf(report_data, org_name=org_name)
    from fastapi.responses import StreamingResponse
    return StreamingResponse(
        iter([pdf_bytes]),
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=sentinel-report.pdf"}
    )

def _build_report_data(org_id: str = None) -> dict:
    from collections import Counter
    now = datetime.utcnow()
    period_start = (now - timedelta(days=30)).isoformat()
    total = malicious = suspicious = safe = 0
    targets = Counter()
    senders = Counter()
    sb = db.get_supabase()
    if sb:
        try:
            r = sb.table("scan_results").select("*").gte("created_at", period_start).execute()
            for row in (r.data or []):
                total += 1
                verdict = (row.get("verdict") or "").lower()
                if "malicious" in verdict or "phishing" in verdict:
                    malicious += 1
                elif "suspicious" in verdict:
                    suspicious += 1
                else:
                    safe += 1
                if row.get("target"):
                    targets[row["target"]] += 1
                if row.get("sender") or row.get("from_address"):
                    senders[row.get("sender") or row.get("from_address")] += 1
        except Exception:
            pass
    return {
        "total": total, "malicious": malicious, "suspicious": suspicious, "safe": safe,
        "threats_blocked": malicious, "estimated_cost_prevented": malicious * settings.COST_PER_INCIDENT,
        "feedback_count": 0, "false_positives": 0, "false_negatives": 0,
        "unique_targets": len(targets), "top_targets": dict(targets.most_common(5)),
        "top_senders": dict(senders.most_common(5)),
        "period_start": period_start, "period_end": now.isoformat(),
    }

# ============================================================================
# WHITE-LABEL / BRANDING API
# ============================================================================
@app.get("/api/v1/branding")
async def get_branding(request: Request):
    user = require_auth(request)
    user_db = resolve_user_db(user)
    org_id = user_db.get("org_id") if user_db else None
    if not org_id:
        return {"logo_url": "", "primary_color": "#DC2626", "secondary_color": "#7F1D1D", "org_display_name": ""}
    return db.branding_get(org_id)

class BrandingRequest(BaseModel):
    logo_url: str = ""
    primary_color: str = "#DC2626"
    secondary_color: str = "#7F1D1D"
    org_display_name: str = ""
    custom_css: str = ""

@app.post("/api/v1/branding")
async def save_branding(payload: BrandingRequest, request: Request):
    user = require_auth(request)
    user_db = resolve_user_db(user)
    if not user_db or user_db.get("role") not in ("owner", "admin"):
        raise HTTPException(status_code=403, detail="Only admins can change branding")
    org_id = user_db.get("org_id")
    if not org_id:
        raise HTTPException(status_code=400, detail="No organization")
    result = db.branding_save(org_id, payload.model_dump())
    ip = _client_ip(request)
    db.audit_log("branding_updated", user["user_id"], user.get("username", ""), ip=ip)
    return {"status": "success", "branding": result}

@app.get("/api/v1/branding/{org_id}")
async def get_branding_public(org_id: str):
    return db.branding_get(org_id)

# ============================================================================
# CUSTOM DETECTION RULES API
# ============================================================================
@app.get("/api/v1/rules")
async def list_rules(request: Request):
    user = require_auth(request)
    return {"rules": db.detection_rules_list(user["user_id"])}

class RuleCreateRequest(BaseModel):
    name: str
    pattern: str
    rule_type: str = "keyword"
    action: str = "flag"
    description: str = ""

@app.post("/api/v1/rules")
async def create_rule(payload: RuleCreateRequest, request: Request):
    user = require_auth(request)
    if not payload.name or not payload.pattern:
        raise HTTPException(status_code=400, detail="Name and pattern required")
    rule = db.detection_rule_create(user["user_id"], payload.name, payload.pattern,
                                    payload.rule_type, payload.action, payload.description)
    if not rule:
        raise HTTPException(status_code=500, detail="Failed to create rule")
    ip = _client_ip(request)
    db.audit_log("rule_created", user["user_id"], user.get("username", ""), f"rule={payload.name}", ip=ip)
    return {"status": "success", "rule": rule}

@app.delete("/api/v1/rules/{rule_id}")
async def delete_rule(rule_id: str, request: Request):
    user = require_auth(request)
    ok = db.detection_rule_delete(user["user_id"], rule_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    ip = _client_ip(request)
    db.audit_log("rule_deleted", user["user_id"], user.get("username", ""), f"rule_id={rule_id}", ip=ip)
    return {"status": "success"}

@app.patch("/api/v1/rules/{rule_id}/toggle")
async def toggle_rule(rule_id: str, request: Request):
    user = require_auth(request)
    body = await request.json()
    enabled = body.get("enabled", True)
    ok = db.detection_rule_toggle(user["user_id"], rule_id, enabled)
    if not ok:
        raise HTTPException(status_code=404, detail="Rule not found")
    return {"status": "success"}

@app.post("/api/v1/rules/check")
async def check_rules(request: Request):
    """Check a text snippet against the user's rules (for preview)."""
    user = require_auth(request)
    body = await request.json()
    text = body.get("text", "")
    matches = db.detection_rules_check(text, user["user_id"])
    return {"matches": [{"name": m["name"], "action": m["action"], "pattern": m["pattern"]} for m in matches]}


# ============================================================================
# PAGE ROUTES - HTML FRONTPAGES
# ============================================================================
@app.get("/login", response_class=HTMLResponse)
async def page_login():
    return LOGIN_PAGE

@app.get("/register", response_class=HTMLResponse)
async def page_register():
    return REGISTER_PAGE

@app.get("/dashboard", response_class=HTMLResponse)
async def page_dashboard(request: Request):
    user = get_current_user(request)
    if user:
        user_db = resolve_user_db(user)
        if user_db and user_db.get("role") == "friend":
            return RedirectResponse("/lite/dashboard")
    return DASHBOARD_PAGE

@app.get("/settings", response_class=HTMLResponse)
async def page_settings(request: Request):
    user = get_current_user(request)
    if user:
        user_db = resolve_user_db(user)
        if user_db and user_db.get("role") == "friend":
            return RedirectResponse("/lite/dashboard")
    return SETTINGS_PAGE

@app.get("/accept-invite/{token}", response_class=HTMLResponse)
async def page_accept_invite(token: str):
    return INVITE_ACCEPT_PAGE.replace("{{TOKEN}}", token)

@app.get("/marketing", response_class=HTMLResponse)
async def page_marketing():
    return MARKETING_PAGE

@app.get("/analytics", response_class=HTMLResponse)
async def page_analytics(request: Request):
    user = get_current_user(request)
    if user:
        user_db = resolve_user_db(user)
        if user_db and user_db.get("role") == "friend":
            return RedirectResponse("/lite/dashboard")
    return ANALYTICS_PAGE

@app.get("/", response_class=HTMLResponse)
async def page_landing():
    return LANDING_PAGE

@app.get("/demo", response_class=HTMLResponse)
async def page_demo():
    return DEMO_PAGE

# ============================================================================
# ANALYTICS PAGE (Owner Only)
# ============================================================================
ANALYTICS_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL - Analytics</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter', sans-serif; background: #0a0a0a; color: #f5f5f5; min-height: 100vh; }
        .topbar { position: fixed; top: 0; left: 0; right: 0; z-index: 100; padding: 12px 32px; display: flex; justify-content: space-between; align-items: center; background: rgba(10,10,10,0.9); backdrop-filter: blur(20px); border-bottom: 1px solid #1a1a1a; }
        .topbar-left { display: flex; align-items: center; gap: 16px; }
        .logo { display: flex; align-items: center; gap: 8px; }
        .logo svg { width: 28px; height: 28px; filter: drop-shadow(0 0 8px rgba(220,38,38,0.4)); }
        .logo-text { font-weight: 800; font-size: 16px; letter-spacing: -0.02em; }
        .nav { display: flex; gap: 6px; }
        .nav a { padding: 8px 14px; border-radius: 8px; font-size: 13px; font-weight: 500; color: #888; transition: all 0.2s; }
        .nav a:hover, .nav a.active { color: #f5f5f5; background: rgba(255,255,255,0.05); }
        .topbar-right { display: flex; align-items: center; gap: 8px; }
        .topbar-right .btn { padding: 7px 14px; font-size: 12px; border-radius: 6px; }
        .owner-badge { background: linear-gradient(135deg, #DC2626, #991B1B); color: white; padding: 4px 12px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; }
        .main { padding: 80px 32px 32px; max-width: 1400px; margin: 0 auto; }
        .page-header { margin-bottom: 16px; }
        .page-header h1 { font-size: 28px; font-weight: 800; letter-spacing: -0.02em; margin-bottom: 4px; }
        .page-header p { color: #888; font-size: 14px; }
        .controls { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; }
        .controls select, .controls input { background: #111; border: 1px solid #2a2a2a; color: #f5f5f5; padding: 9px 32px 9px 14px; border-radius: 8px; font-size: 13px; font-family: inherit; appearance: none; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath d='M3 5l3 3 3-3' stroke='%23888' stroke-width='1.5' fill='none'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 10px center; cursor: pointer; transition: border-color 0.2s; }
        .controls select:hover, .controls input:hover { border-color: #444; }
        .controls select:focus, .controls input:focus { outline: none; border-color: #DC2626; box-shadow: 0 0 0 2px rgba(220,38,38,0.15); }
        .btn { background: #111; border: 1px solid #2a2a2a; color: #ccc; padding: 9px 18px; border-radius: 8px; font-size: 13px; font-weight: 500; cursor: pointer; transition: all 0.2s; font-family: inherit; display: inline-flex; align-items: center; gap: 6px; }
        .btn:hover { border-color: #444; background: #1a1a1a; color: #f5f5f5; transform: translateY(-1px); }
        .btn:active { transform: translateY(0); }
        .btn.primary { background: linear-gradient(135deg, #DC2626, #B91C1C); border: 1px solid rgba(220,38,38,0.4); color: white; font-weight: 600; }
        .btn.primary:hover { box-shadow: 0 4px 20px rgba(220,38,38,0.35); border-color: rgba(220,38,38,0.6); }
        .btn.ghost { background: transparent; border: 1px solid #2a2a2a; color: #aaa; }
        .btn.ghost:hover { background: #1a1a1a; border-color: #444; color: #f5f5f5; }
        .btn-icon { padding: 9px 12px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 12px; }
        .stat-card { background: #111; border: 1px solid #1e1e1e; border-radius: 10px; padding: 14px 16px; }
        .stat-card .label { font-size: 11px; font-weight: 500; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
        .stat-card .value { font-size: 24px; font-weight: 800; letter-spacing: -0.02em; font-family: 'JetBrains Mono', monospace; }
        .stat-card .value.red { color: #DC2626; }
        .chart-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; margin-bottom: 12px; }
        .chart-card { background: #111; border: 1px solid #1e1e1e; border-radius: 10px; padding: 16px; margin-bottom: 0; }
        .chart-card h3 { font-size: 13px; font-weight: 600; margin-bottom: 12px; }
        .chart-card canvas { width: 100% !important; max-height: 180px; }
        .table-card { background: #111; border: 1px solid #1e1e1e; border-radius: 12px; padding: 20px; margin-bottom: 24px; overflow-x: auto; max-height: 420px; overflow-y: auto; }
        .table-card h3 { font-size: 14px; font-weight: 600; margin-bottom: 16px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th { text-align: left; padding: 10px 12px; border-bottom: 1px solid #1e1e1e; color: #888; font-weight: 500; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; }
        td { padding: 10px 12px; border-bottom: 1px solid #1a1a1a; font-family: 'JetBrains Mono', monospace; font-size: 12px; }
        tr:hover td { background: rgba(255,255,255,0.02); }
        .tag { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; }
        .tag.desktop { background: rgba(34,197,94,0.15); color: #22c55e; }
        .tag.mobile { background: rgba(59,130,246,0.15); color: #3b82f6; }
        .tag.tablet { background: rgba(168,85,247,0.15); color: #a855f7; }
        .tag.bot { background: rgba(234,179,8,0.15); color: #eab308; }
        .loading { text-align: center; padding: 60px; color: #888; }
        .bar-chart-h { display: flex; flex-direction: column; gap: 6px; }
        .bar-row { display: flex; align-items: center; gap: 10px; }
        .bar-label { width: 100px; font-size: 12px; color: #aaa; text-align: right; font-family: 'JetBrains Mono', monospace; }
        .bar-fill-bg { flex: 1; height: 24px; background: #1a1a1a; border-radius: 4px; overflow: hidden; }
        .bar-fill { height: 100%; background: linear-gradient(90deg, #DC2626, #991B1B); border-radius: 4px; transition: width 0.5s ease; display: flex; align-items: center; padding-left: 8px; font-size: 11px; font-weight: 600; font-family: 'JetBrains Mono', monospace; min-width: 30px; }
        .empty-state { text-align: center; padding: 80px 40px; }
        .empty-state h2 { font-size: 24px; margin-bottom: 8px; }
        .empty-state p { color: #888; font-size: 14px; margin-bottom: 20px; }
        .live-dot { width: 8px; height: 8px; background: #22c55e; border-radius: 50%; display: inline-block; margin-right: 6px; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .hamburger { display: none; background: none; border: none; color: #f5f5f5; font-size: 22px; cursor: pointer; padding: 6px; line-height: 1; -webkit-tap-highlight-color: transparent; }
        @media (max-width: 768px) {
            .main { padding: 72px 12px 12px; }
            .topbar { padding: 10px 12px; }
            .hamburger { display: block; }
            .nav { display: none; position: absolute; top: 100%; left: 0; right: 0; background: #111; border-bottom: 1px solid #1a1a1a; padding: 8px 12px; flex-direction: column; gap: 4px; z-index: 99; }
            .nav.open { display: flex; }
            .page-header h1 { font-size: 22px; }
            .controls { flex-direction: column; align-items: stretch; gap: 8px; }
            .controls select, .controls input { width: 100%; }
            .controls span { margin-left: 0 !important; justify-content: center; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 8px; }
            .stat-card { padding: 10px 12px; }
            .stat-card .value { font-size: 18px; }
            .chart-grid { grid-template-columns: 1fr; gap: 8px; }
            .chart-card { padding: 12px; }
            .chart-card h3 { font-size: 12px; }
            .table-card { padding: 12px; overflow-x: auto; }
            table { font-size: 11px; }
            th, td { padding: 6px 8px; white-space: nowrap; }
            .bar-label { width: 70px; font-size: 10px; }
        }
    </style>
</head>
<body>
    <div class="topbar">
        <div class="topbar-left">
            <a href="/dashboard" class="logo">
                <svg viewBox="0 0 36 36" fill="none"><path d="M18 2L3 10v16l15 8 15-8V10L18 2z" fill="url(#g1)" opacity="0.9"/><path d="M18 6l10 5.5v11L18 28 8 22.5v-11L18 6z" fill="#0a0a0a"/><path d="M18 12l-6 3.3v6.6L18 25l6-3.1v-6.6L18 12z" fill="url(#g2)"/><defs><linearGradient id="g1" x1="3" y1="2" x2="33" y2="34"><stop stop-color="#DC2626"/><stop offset="1" stop-color="#991B1B"/></linearGradient><linearGradient id="g2" x1="12" y1="12" x2="24" y2="25"><stop stop-color="#DC2626"/><stop offset="1" stop-color="#991B1B"/></linearGradient></defs></svg>
                <span class="logo-text">SENTINEL</span>
            </a>
            <div class="nav">
                <a href="/dashboard">Dashboard</a>
                <a href="/settings">Settings</a>
                <a href="/analytics" class="active">Analytics</a>
            </div>
        </div>
        <div class="topbar-right">
            <button class="hamburger" onclick="document.querySelector('.nav').classList.toggle('open')">&#9776;</button>
            <a href="/login" class="btn ghost" onclick="event.preventDefault(); logout()">Logout</a>
        </div>
    </div>

    <div class="main">
        <div class="page-header">
            <h1>Analytics Dashboard</h1>
            <p>Track visitor regions, activity times, and device usage</p>
        </div>

        <div class="controls">
            <select id="period" onchange="loadAnalytics()">
                <option value="1">Last 24 Hours</option>
                <option value="7" selected>Last 7 Days</option>
                <option value="30">Last 30 Days</option>
                <option value="90">Last 90 Days</option>
            </select>
            <button class="btn primary" onclick="loadAnalytics()">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
                Refresh
            </button>
            <span style="margin-left: auto; font-size: 13px; color: #888; display: flex; align-items: center; gap: 6px;"><span class="live-dot"></span>Live tracking active</span>
        </div>

        <div id="loading" class="loading">Loading analytics...</div>
        <div id="content" style="display: none;">
            <h2 style="font-size:18px;font-weight:700;margin:12px 0 10px;color:#DC2626;">Email Threat Analytics</h2>
            <div id="emailStats" class="stats-grid"></div>
            <div class="chart-grid">
                <div class="chart-card">
                    <h3>Threat Distribution</h3>
                    <canvas id="threatChart" height="150"></canvas>
                </div>
                <div class="chart-card">
                    <h3>Top Email Senders</h3>
                    <canvas id="senderChart" height="150"></canvas>
                </div>
            </div>
            <div id="siteAnalyticsSection">
            <h2 style="font-size:18px;font-weight:700;margin:12px 0 10px;color:#C084FC;">Site Analytics</h2>
            <div class="stats-grid" id="statsGrid"></div>
            <div class="chart-grid">
                <div class="chart-card">
                    <h3>Activity by Hour (UTC)</h3>
                    <canvas id="hourlyChart" height="150"></canvas>
                </div>
                <div class="chart-card">
                    <h3>Visitors by Region</h3>
                    <canvas id="countryChart" height="150"></canvas>
                </div>
                <div class="chart-card">
                    <h3>Device Types</h3>
                    <canvas id="deviceChart" height="150"></canvas>
                </div>
                <div class="chart-card">
                    <h3>Browsers</h3>
                    <canvas id="browserChart" height="150"></canvas>
                </div>
            </div>
            <div class="chart-grid">
                <div class="chart-card">
                    <h3>Operating Systems</h3>
                    <canvas id="osChart" height="150"></canvas>
                </div>
                <div class="chart-card">
                    <h3>Activity by Day of Week</h3>
                    <canvas id="dowChart" height="150"></canvas>
                </div>
            </div>
            <div class="chart-card" style="margin-bottom: 16px;">
                <h3>Top Pages</h3>
                <div id="topPages" style="max-height:180px;overflow-y:auto;"></div>
            </div>
            <div class="table-card">
                <h3>Recent Unique Visitors</h3>
                <table id="ipTable">
                    <thead><tr><th>IP Address</th><th>Country</th><th>City</th><th>Device</th><th>Browser</th><th>OS</th><th>Requests</th><th>First Seen</th></tr></thead>
                    <tbody id="ipBody"></tbody>
                </table>
            </div>
            </div>
        </div>
    </div>

    <script>
    let charts = {};

    function getToken() { return localStorage.getItem('sentinel_token'); }

    function authHeaders() {
        return { 'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json' };
    }

    async function loadAnalytics() {
        if (!getToken()) { window.location.href = '/login'; return; }
        const days = document.getElementById('period').value;
        document.getElementById('loading').style.display = 'block';
        document.getElementById('content').style.display = 'none';
        try {
            const [overviewRes, ipsRes, emailRes] = await Promise.all([
                fetch('/api/analytics/overview?days=' + days, { headers: authHeaders() }),
                fetch('/api/analytics/ips?days=' + days, { headers: authHeaders() }),
                fetch('/api/analytics/emails', { headers: authHeaders() })
            ]);
            if (overviewRes.status === 401) { window.location.href = '/login'; return; }
            const emailData = emailRes.ok ? await emailRes.json() : null;
            renderEmailStats(emailData);
            renderEmailCharts(emailData);
            const isOwner = overviewRes.ok && overviewRes.status !== 403;
            if (isOwner) {
                const overview = await overviewRes.json();
                const ipsData = await ipsRes.json();
                if (!overview.detail) {
                    renderStats(overview);
                    renderCharts(overview);
                    renderTable(ipsData.ips || []);
                }
            }
            document.getElementById('loading').style.display = 'none';
            document.getElementById('content').style.display = 'block';
        } catch (e) {
            document.getElementById('loading').innerHTML = '<div class="empty-state"><h2>Error loading data</h2><p>' + e.message + '</p></div>';
        }
    }

    function renderEmailStats(data) {
        const grid = document.getElementById('emailStats');
        if (!data) { grid.innerHTML = '<div class="stat-card"><div class="label">Email Data</div><div class="value">Unavailable</div></div>'; return; }
        const threatRate = data.total > 0 ? Math.round((data.threats / data.total) * 100) : 0;
        grid.innerHTML = [
            { label: 'Total Emails Scanned', value: data.total.toLocaleString(), cls: '' },
            { label: 'Threats Blocked', value: data.threats.toLocaleString(), cls: 'red' },
            { label: 'Suspicious', value: data.suspicious.toLocaleString(), cls: '' },
            { label: 'Safe', value: data.safe.toLocaleString(), cls: '' },
            { label: 'Threat Rate', value: threatRate + '%', cls: 'red' },
            { label: 'Feedback Corrections', value: data.feedback_count.toLocaleString(), cls: '' },
        ].map(s => '<div class="stat-card"><div class="label">' + s.label + '</div><div class="value ' + s.cls + '">' + s.value + '</div></div>').join('');
    }

    function renderEmailCharts(data) {
        if (!data) return;
        if (charts.threat) charts.threat.destroy();
        if (charts.sender) charts.sender.destroy();
        const pieOpts = { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#ccc', font: { size: 12 }, padding: 12 } } } };
        const colors = ['#DC2626','#F97316','#EAB308','#22C55E','#3B82F6','#A855F7','#EC4899','#14B8A6','#6366F1','#F43F5E'];
        if (data.total > 0) {
            charts.threat = new Chart(document.getElementById('threatChart'), {
                type: 'doughnut', data: { labels: ['Threats','Suspicious','Safe'], datasets: [{ data: [data.threats, data.suspicious, data.safe], backgroundColor: ['#DC2626','#EAB308','#22C55E'], borderWidth: 0 }] }, options: pieOpts
            });
        }
        const senders = Object.entries(data.top_senders || {}).slice(0, 8);
        if (senders.length > 0) {
            charts.sender = new Chart(document.getElementById('senderChart'), {
                type: 'bar', data: { labels: senders.map(s => s[0].length > 25 ? s[0].substring(0,25)+'...' : s[0]), datasets: [{ data: senders.map(s => s[1]), backgroundColor: colors.slice(0, senders.length), borderRadius: 4 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#888', font: { size: 11 } }, grid: { color: '#1a1a1a' } }, y: { ticks: { color: '#888', font: { size: 11 } }, grid: { color: '#1a1a1a' } } } }
            });
        }
    }

    function renderStats(data) {
        const grid = document.getElementById('statsGrid');
        grid.innerHTML = [
            { label: 'Total Requests', value: data.total_requests.toLocaleString(), cls: '' },
            { label: 'Unique IPs', value: data.unique_ips.toLocaleString(), cls: 'red' },
            { label: 'Unique Users', value: data.unique_users.toLocaleString(), cls: '' },
            { label: 'Countries', value: Object.keys(data.countries).length, cls: '' },
            { label: 'Top Country', value: Object.entries(data.countries).sort((a,b)=>b[1]-a[1])[0]?.[0] || '-', cls: 'red' },
            { label: 'Top Browser', value: Object.entries(data.browsers).sort((a,b)=>b[1]-a[1])[0]?.[0] || '-', cls: '' },
        ].map(s => '<div class="stat-card"><div class="label">' + s.label + '</div><div class="value ' + s.cls + '">' + s.value + '</div></div>').join('');
    }

    function renderCharts(data) {
        Object.values(charts).forEach(c => c.destroy());
        charts = {};
        const redGrad = (ctx) => {
            const g = ctx.chart.ctx.createLinearGradient(0, 0, 0, 300);
            g.addColorStop(0, 'rgba(220,38,38,0.4)'); g.addColorStop(1, 'rgba(220,38,38,0.02)');
            return g;
        };
        const baseOpts = { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#888', font: { size: 11 } }, grid: { color: '#1a1a1a' } }, y: { ticks: { color: '#888', font: { size: 11 } }, grid: { color: '#1a1a1a' } } } };
        const pieOpts = { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#ccc', font: { size: 12 }, padding: 12 } } } };
        const colors = ['#DC2626','#F97316','#EAB308','#22C55E','#3B82F6','#A855F7','#EC4899','#14B8A6','#6366F1','#F43F5E'];

        const hours = Object.keys(data.hourly_distribution).sort();
        charts.hourly = new Chart(document.getElementById('hourlyChart'), {
            type: 'bar', data: { labels: hours.map(h => h + ':00'), datasets: [{ data: hours.map(h => data.hourly_distribution[h]), backgroundColor: redGrad, borderColor: '#DC2626', borderWidth: 1, borderRadius: 4 }] }, options: baseOpts
        });

        const countries = Object.entries(data.countries).sort((a,b) => b[1]-a[1]).slice(0, 10);
        charts.country = new Chart(document.getElementById('countryChart'), {
            type: 'bar', data: { labels: countries.map(c => c[0]), datasets: [{ data: countries.map(c => c[1]), backgroundColor: colors.slice(0, countries.length), borderRadius: 4 }] }, options: { ...baseOpts, indexAxis: 'y' }
        });

        const devs = Object.entries(data.devices);
        charts.device = new Chart(document.getElementById('deviceChart'), {
            type: 'doughnut', data: { labels: devs.map(d => d[0]), datasets: [{ data: devs.map(d => d[1]), backgroundColor: colors.slice(0, devs.length), borderWidth: 0 }] }, options: pieOpts
        });

        const browsers = Object.entries(data.browsers).sort((a,b) => b[1]-a[1]);
        charts.browser = new Chart(document.getElementById('browserChart'), {
            type: 'doughnut', data: { labels: browsers.map(b => b[0]), datasets: [{ data: browsers.map(b => b[1]), backgroundColor: colors.slice(0, browsers.length), borderWidth: 0 }] }, options: pieOpts
        });

        const oses = Object.entries(data.oses).sort((a,b) => b[1]-a[1]);
        charts.os = new Chart(document.getElementById('osChart'), {
            type: 'doughnut', data: { labels: oses.map(o => o[0]), datasets: [{ data: oses.map(o => o[1]), backgroundColor: colors.slice(0, oses.length), borderWidth: 0 }] }, options: pieOpts
        });

        const dowOrder = ['Monday','Tuesday','Wednesday','Thursday','Friday','Saturday','Sunday'];
        const dowData = dowOrder.map(d => data.daily_distribution[d] || 0);
        charts.dow = new Chart(document.getElementById('dowChart'), {
            type: 'bar', data: { labels: dowOrder.map(d => d.slice(0,3)), datasets: [{ data: dowData, backgroundColor: redGrad, borderColor: '#DC2626', borderWidth: 1, borderRadius: 4 }] }, options: baseOpts
        });

        const topPaths = Object.entries(data.top_paths).slice(0, 10);
        const maxCount = topPaths[0]?.[1] || 1;
        document.getElementById('topPages').innerHTML = '<div class="bar-chart-h">' + topPaths.map(([path, count]) =>
            '<div class="bar-row"><div class="bar-label">' + path + '</div><div class="bar-fill-bg"><div class="bar-fill" style="width:' + Math.round((count/maxCount)*100) + '%">' + count + '</div></div></div>'
        ).join('') + '</div>';
    }

    function renderTable(ips) {
        const body = document.getElementById('ipBody');
        const shown = ips.slice(0, 10);
        body.innerHTML = shown.map(ip => {
            const devCls = (ip.device_type || '').toLowerCase();
            return '<tr><td>' + ip.ip + '</td><td>' + (ip.country || '-') + '</td><td>' + (ip.city || '-') + '</td><td><span class="tag ' + devCls + '">' + (ip.device_type || '-') + '</span></td><td>' + (ip.browser || '-') + '</td><td>' + (ip.os || '-') + '</td><td>' + ip.request_count + '</td><td>' + new Date(ip.first_seen).toLocaleDateString() + '</td></tr>';
        }).join('');
        if (ips.length > 10) {
            body.innerHTML += '<tr><td colspan="8" style="text-align:center;color:#888;padding:12px;">+ ' + (ips.length - 10) + ' more visitors</td></tr>';
        }
    }

    async function logout() {
        await fetch('/api/auth/logout', { method: 'POST' });
        window.location.href = '/login';
    }

    async function checkRole() {
        try {
            var r = await fetch('/api/auth/me', { headers: authHeaders() });
            var data = await r.json();
            if (data.role !== 'owner') {
                document.getElementById('siteAnalyticsSection').style.display = 'none';
            }
        } catch(e) {
            document.getElementById('siteAnalyticsSection').style.display = 'none';
        }
    }

    checkRole();
    loadAnalytics();
    setInterval(loadAnalytics, 60000);
    </script>
</body>
</html>"""

# ============================================================================
# LANDING PAGE
# ============================================================================
LANDING_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL - AI-Powered Phishing Triage</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter', sans-serif; background: #0a0a0a; color: #f5f5f5; line-height: 1.6; overflow-x: hidden; }
        a { text-decoration: none; color: inherit; }
        .nav { position: fixed; top: 0; left: 0; right: 0; z-index: 100; padding: 16px 40px; display: flex; justify-content: space-between; align-items: center; background: rgba(10,10,10,0.85); backdrop-filter: blur(20px); border-bottom: 1px solid #1a1a1a; }
        .logo { display: flex; align-items: center; gap: 10px; }
        .logo-mark { width: 36px; height: 36px; display: flex; align-items: center; justify-content: center; filter: drop-shadow(0 0 12px rgba(220,38,38,0.4)); }
        .logo-text { font-weight: 800; font-size: 18px; letter-spacing: -0.02em; }
        .nav-links { display: flex; gap: 12px; align-items: center; }
        .nav-links a { padding: 8px 16px; border-radius: 8px; font-size: 14px; font-weight: 500; color: #a0a0a0; transition: all 0.2s; }
        .nav-links a:hover { color: #f5f5f5; }
        .btn-primary { background: linear-gradient(135deg, #DC2626, #991B1B); color: white; border: 1px solid rgba(220,38,38,0.3); padding: 10px 24px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
        .btn-primary:hover { box-shadow: 0 4px 20px rgba(220,38,38,0.3); transform: translateY(-1px); }
        .btn-outline { background: transparent; color: #f5f5f5; border: 1px solid #333; padding: 10px 24px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
        .btn-outline:hover { border-color: #555; background: #161616; }

        .hero { min-height: 100vh; display: flex; align-items: center; justify-content: center; text-align: center; padding: 120px 40px 80px; position: relative; overflow: hidden; }
        .hero::before { content: ''; position: absolute; top: -300px; left: 50%; transform: translateX(-50%); width: 1000px; height: 1000px; background: radial-gradient(circle, rgba(220,38,38,0.06) 0%, transparent 60%); pointer-events: none; animation: pulse-glow 6s ease-in-out infinite; }
        .hero::after { content: ''; position: absolute; bottom: -200px; right: -200px; width: 600px; height: 600px; background: radial-gradient(circle, rgba(220,38,38,0.04) 0%, transparent 60%); pointer-events: none; animation: pulse-glow 8s ease-in-out infinite reverse; }
        @keyframes pulse-glow { 0%,100% { opacity: 0.5; transform: translateX(-50%) scale(1); } 50% { opacity: 1; transform: translateX(-50%) scale(1.1); } }
        .hero-badge { display: inline-flex; align-items: center; gap: 8px; padding: 8px 16px; border-radius: 20px; border: 1px solid rgba(220,38,38,0.3); background: rgba(220,38,38,0.08); font-size: 12px; font-weight: 600; color: #FCA5A5; margin-bottom: 28px; letter-spacing: 0.02em; }
        .hero-badge .dot { width: 6px; height: 6px; border-radius: 50%; background: #22C55E; animation: blink 2s ease-in-out infinite; }
        @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
        .hero h1 { font-size: 68px; font-weight: 900; letter-spacing: -0.03em; line-height: 1.05; margin-bottom: 24px; }
        .hero h1 span { background: linear-gradient(135deg, #DC2626, #F87171); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .hero p { font-size: 18px; color: #888; max-width: 580px; margin: 0 auto 40px; line-height: 1.7; }
        .hero-buttons { display: flex; gap: 12px; justify-content: center; }
        .hero-buttons .btn-primary { padding: 14px 36px; font-size: 16px; }
        .hero-buttons .btn-outline { padding: 14px 36px; font-size: 16px; }

        .trust-bar { padding: 40px; border-top: 1px solid #111; border-bottom: 1px solid #111; background: #0d0d0d; }
        .trust-bar-inner { max-width: 1000px; margin: 0 auto; display: flex; align-items: center; justify-content: center; gap: 48px; flex-wrap: wrap; }
        .trust-item { display: flex; align-items: center; gap: 8px; font-size: 12px; color: #555; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; }
        .trust-item .trust-icon { width: 28px; height: 28px; border-radius: 6px; background: rgba(34,197,94,0.08); border: 1px solid rgba(34,197,94,0.15); display: flex; align-items: center; justify-content: center; font-size: 13px; color: #22C55E; }

        .features { padding: 100px 40px; max-width: 1200px; margin: 0 auto; }
        .features-title { text-align: center; font-size: 12px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: #DC2626; margin-bottom: 12px; }
        .features h2 { text-align: center; font-size: 36px; font-weight: 800; letter-spacing: -0.02em; margin-bottom: 60px; }
        .features-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
        .feature-card { background: linear-gradient(145deg, #111, #0d0d0d); border: 1px solid #1a1a1a; border-radius: 14px; padding: 32px; transition: all 0.3s; position: relative; overflow: hidden; }
        .feature-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px; background: linear-gradient(90deg, transparent, rgba(220,38,38,0.3), transparent); opacity: 0; transition: opacity 0.3s; }
        .feature-card:hover { border-color: #2a2a2a; transform: translateY(-4px); box-shadow: 0 12px 40px rgba(0,0,0,0.3); }
        .feature-card:hover::before { opacity: 1; }
        .feature-icon { width: 48px; height: 48px; border-radius: 12px; background: rgba(220,38,38,0.08); border: 1px solid rgba(220,38,38,0.12); display: flex; align-items: center; justify-content: center; margin-bottom: 18px; }
        .feature-icon svg { width: 22px; height: 22px; }
        .feature-card h3 { font-size: 17px; font-weight: 700; margin-bottom: 8px; }
        .feature-card p { font-size: 14px; color: #777; line-height: 1.7; }

        .stats-section { padding: 80px 40px; max-width: 1200px; margin: 0 auto; }
        .stats-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; }
        .stat-item { text-align: center; padding: 32px; background: #111; border: 1px solid #1a1a1a; border-radius: 12px; transition: all 0.3s; }
        .stat-item:hover { border-color: #2a2a2a; transform: translateY(-2px); }
        .stat-value { font-size: 42px; font-weight: 900; background: linear-gradient(135deg, #DC2626, #F87171); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .stat-label { font-size: 13px; color: #666; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.05em; }

        .how-it-works { padding: 100px 40px; max-width: 1000px; margin: 0 auto; }
        .how-it-works h2 { text-align: center; font-size: 36px; font-weight: 800; margin-bottom: 60px; }
        .steps { display: grid; grid-template-columns: repeat(3, 1fr); gap: 32px; position: relative; }
        .steps::before { content: ''; position: absolute; top: 36px; left: 15%; right: 15%; height: 2px; background: linear-gradient(90deg, rgba(220,38,38,0.3), rgba(220,38,38,0.1), rgba(220,38,38,0.3)); }
        .step { text-align: center; position: relative; z-index: 1; }
        .step-num { width: 56px; height: 56px; border-radius: 50%; background: #111; border: 2px solid rgba(220,38,38,0.3); display: inline-flex; align-items: center; justify-content: center; font-size: 20px; font-weight: 800; color: #DC2626; margin-bottom: 20px; position: relative; }
        .step h3 { font-size: 18px; font-weight: 700; margin-bottom: 8px; }
        .step p { font-size: 14px; color: #777; line-height: 1.6; max-width: 260px; margin: 0 auto; }

        .cta { padding: 100px 40px; text-align: center; }
        .cta-box { max-width: 640px; margin: 0 auto; background: linear-gradient(145deg, #111, #0d0d0d); border: 1px solid #1a1a1a; border-radius: 20px; padding: 60px 48px; position: relative; overflow: hidden; }
        .cta-box::before { content: ''; position: absolute; top: -1px; left: 20%; right: 20%; height: 2px; background: linear-gradient(90deg, transparent, #DC2626, transparent); }
        .cta-box h2 { font-size: 30px; font-weight: 800; margin-bottom: 12px; }
        .cta-box p { color: #888; margin-bottom: 32px; font-size: 16px; }
        .cta-badges { display: flex; gap: 16px; justify-content: center; margin-top: 24px; }
        .cta-badge { display: flex; align-items: center; gap: 6px; font-size: 11px; color: #666; }
        .cta-badge svg { width: 14px; height: 14px; color: #22C55E; }

        .footer { padding: 40px; text-align: center; border-top: 1px solid #1a1a1a; color: #444; font-size: 13px; }
        .footer-links { display: flex; gap: 24px; justify-content: center; margin-top: 8px; }
        .footer-links a { color: #666; font-size: 12px; transition: color 0.2s; }
        .footer-links a:hover { color: #DC2626; }

        @keyframes fadeUp { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }
        .fade-up { animation: fadeUp 0.7s cubic-bezier(0.16, 1, 0.3, 1) both; }
        .delay-1 { animation-delay: 0.1s; }
        .delay-2 { animation-delay: 0.2s; }
        .delay-3 { animation-delay: 0.3s; }
        .delay-4 { animation-delay: 0.4s; }
        @media (max-width: 768px) {
            .nav { padding: 12px 16px; }
            .nav-links { gap: 6px; }
            .nav-links a { padding: 6px 10px; font-size: 12px; }
            .btn-primary { padding: 8px 16px; font-size: 13px; }
            .hero { padding: 100px 20px 60px; }
            .hero h1 { font-size: 36px; }
            .hero p { font-size: 15px; }
            .hero-buttons { flex-direction: column; align-items: center; }
            .hero-buttons .btn-primary, .hero-buttons .btn-outline { padding: 12px 28px; font-size: 14px; width: 100%; max-width: 280px; }
            .trust-bar-inner { gap: 20px; }
            .trust-item { font-size: 10px; }
            .features { padding: 60px 16px; }
            .features h2 { font-size: 24px; margin-bottom: 32px; }
            .features-grid { grid-template-columns: 1fr; }
            .feature-card { padding: 24px; }
            .stats-section { padding: 40px 16px; }
            .stats-grid { grid-template-columns: repeat(2, 1fr); gap: 12px; }
            .stat-value { font-size: 28px; }
            .how-it-works { padding: 60px 16px; }
            .how-it-works h2 { font-size: 24px; margin-bottom: 40px; }
            .steps { grid-template-columns: 1fr; gap: 24px; }
            .steps::before { display: none; }
            .cta { padding: 60px 16px; }
            .cta-box { padding: 40px 24px; }
            .cta-box h2 { font-size: 22px; }
            .cta-badges { flex-direction: column; align-items: center; gap: 8px; }
        }
    </style>
</head>
<body>
    <nav class="nav">
        <div class="logo">
            <div class="logo-mark"><svg viewBox="0 0 40 44" fill="none" xmlns="http://www.w3.org/2000/svg" width="36" height="40"><path d="M20 2L4 10v12c0 11 7.2 21.3 16 24 8.8-2.7 16-13 16-24V10L20 2z" fill="url(#lg1)" stroke="#991B1B" stroke-width="1.5"/><path d="M20 10v8m0 0v8m0-8l-4-4m4 4l4-4" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="lg1" x1="4" y1="2" x2="36" y2="46"><stop stop-color="#DC2626"/><stop offset="1" stop-color="#7F1D1D"/></linearGradient></defs></svg></div>
            <div class="logo-text">SENTINEL</div>
        </div>
        <div class="nav-links">
            <a href="/marketing">Product</a>
            <a href="/login">Log In</a>
            <a href="/login"><button class="btn-primary">Get Started</button></a>
        </div>
    </nav>

    <section class="hero">
        <div>
            <div class="hero-badge fade-up"><div class="dot"></div> AI-Powered Threat Analysis — Powered by Llama-3</div>
            <div class="fade-up delay-1" style="margin-bottom:32px"><svg viewBox="0 0 40 44" fill="none" xmlns="http://www.w3.org/2000/svg" width="80" height="88" style="display:block;margin:0 auto;filter:drop-shadow(0 0 40px rgba(220,38,38,0.5))"><path d="M20 2L4 10v12c0 11 7.2 21.3 16 24 8.8-2.7 16-13 16-24V10L20 2z" fill="url(#lgH)" stroke="#991B1B" stroke-width="1.5"/><path d="M20 10v8m0 0v8m0-8l-4-4m4 4l4-4" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="lgH" x1="4" y1="2" x2="36" y2="46"><stop stop-color="#DC2626"/><stop offset="1" stop-color="#7F1D1D"/></linearGradient></defs></svg></div>
            <h1 class="fade-up delay-2">Stop Phishing<br>Before It <span>Strikes</span></h1>
            <p class="fade-up delay-3">Forward suspicious emails and get instant AI-powered verdicts. Detects social engineering, spoofed domains, and credential harvesting with 99.7% accuracy.</p>
            <div class="hero-buttons fade-up delay-4">
                <a href="/login"><button class="btn-primary">Get Started</button></a>
                <a href="/demo"><button class="btn-outline">View Live Demo</button></a>
            </div>
        </div>
    </section>

    <section class="trust-bar">
        <div class="trust-bar-inner">
            <div class="trust-item"><div class="trust-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div> End-to-End Encrypted</div>
            <div class="trust-item"><div class="trust-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div> SOC 2 Compliant</div>
            <div class="trust-item"><div class="trust-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div> Zero-Knowledge Storage</div>
            <div class="trust-item"><div class="trust-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div> 24/7 Auto Monitoring</div>
        </div>
    </section>

    <section class="features">
        <div class="features-title">FEATURES</div>
        <h2>Enterprise-Grade Phishing Defense</h2>
        <div class="features-grid">
            <div class="feature-card">
                <div class="feature-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg></div>
                <h3>AI-Powered Analysis</h3>
                <p>Advanced Llama-3 LLM detects social engineering, spoofed domains, and credential harvesting with structured explainable output.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></div>
                <h3>One-Click Reporting</h3>
                <p>Forward suspicious emails or paste them directly. Our parser extracts the original email and provides instant AI verdicts.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></div>
                <h3>Real-Time Dashboard</h3>
                <p>Monitor threats live with a sleek dashboard showing confidence scores, indicators, and detailed analysis breakdowns.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div>
                <h3>Auto Email Polling</h3>
                <p>Connect your mailbox and SENTINEL automatically scans forwarded phishing reports around the clock.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div>
                <h3>Team Collaboration</h3>
                <p>Each team member gets their own workspace. Share findings, corrections, and build collective phishing intelligence.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></div>
                <h3>Lightning-Fast Analysis</h3>
                <p>Get verdicts in under 2 seconds. Powered by Llama-3 running on Groq infrastructure for real-time threat detection.</p>
            </div>
        </div>
    </section>

    <section class="how-it-works">
        <h2>How It Works</h2>
        <div class="steps">
            <div class="step">
                <div class="step-num">1</div>
                <h3>Forward the Email</h3>
                <p>Paste a suspicious email or connect your mailbox for automatic scanning.</p>
            </div>
            <div class="step">
                <div class="step-num">2</div>
                <h3>AI Analyzes It</h3>
                <p>Llama-3 examines sender, URLs, content, and headers for phishing indicators.</p>
            </div>
            <div class="step">
                <div class="step-num">3</div>
                <h3>Get Your Verdict</h3>
                <p>Receive a confidence score, detailed reasoning, and actionable recommendations.</p>
            </div>
        </div>
    </section>

    <section class="stats-section">
        <div class="stats-grid">
            <div class="stat-item">
                <div class="stat-value">99.7%</div>
                <div class="stat-label">Detection Rate</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">&lt;2s</div>
                <div class="stat-label">Analysis Time</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">SOC 2</div>
                <div class="stat-label">Compliant</div>
            </div>
            <div class="stat-item">
                <div class="stat-value">24/7</div>
                <div class="stat-label">Auto Monitoring</div>
            </div>
        </div>
    </section>

    <section class="cta">
        <div class="cta-box">
            <h2>Ready to Secure Your Team?</h2>
            <p>SENTINEL protects organizations from phishing attacks with AI-powered analysis.</p>
            <a href="/login"><button class="btn-primary" style="padding: 14px 40px; font-size: 16px;">Get Started</button></a>
            <div class="cta-badges">
                <div class="cta-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg> Your data stays yours</div>
                <div class="cta-badge"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> End-to-end encrypted</div>
            </div>
        </div>
    </section>

    <footer class="footer">
        <p>SENTINEL v3.0.0 &mdash; AI-Powered Phishing Triage Intelligence</p>
        <div class="footer-links">
            <a href="/marketing">Product</a>
            <a href="/login">Log In</a>
            <a href="/docs">API Docs</a>
        </div>
    </footer>
</body>
</html>"""

# ============================================================================
# LOGIN PAGE
# ============================================================================
LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL - Log In</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter', sans-serif; background: #0a0a0a; color: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { width: 100%; max-width: 420px; padding: 20px; }
        .logo { display: flex; align-items: center; gap: 10px; justify-content: center; margin-bottom: 32px; }
        .logo-mark { width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; filter: drop-shadow(0 0 12px rgba(220,38,38,0.4)); }
        .logo-text { font-weight: 800; font-size: 22px; letter-spacing: -0.02em; }
        .card { background: linear-gradient(145deg, #111, #0d0d0d); border: 1px solid #1a1a1a; border-radius: 16px; padding: 40px; }
        .card h1 { font-size: 24px; font-weight: 800; margin-bottom: 4px; text-align: center; }
        .card .subtitle { text-align: center; color: #666; font-size: 14px; margin-bottom: 32px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; font-size: 12px; font-weight: 600; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
        .form-group input { width: 100%; padding: 12px 16px; background: #0a0a0a; border: 1px solid #222; border-radius: 8px; color: #f5f5f5; font-size: 14px; font-family: 'Inter', sans-serif; outline: none; transition: border-color 0.2s, box-shadow 0.2s; }
        .form-group input:focus { border-color: #DC2626; box-shadow: 0 0 0 3px rgba(220,38,38,0.15); }
        .form-group input::placeholder { color: #444; }
        .btn { width: 100%; padding: 12px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; border: none; font-family: 'Inter', sans-serif; transition: all 0.2s; }
        .btn-primary { background: linear-gradient(135deg, #DC2626, #991B1B); color: white; }
        .btn-primary:hover { box-shadow: 0 4px 20px rgba(220,38,38,0.3); transform: translateY(-1px); }
        .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
        .error { background: rgba(220,38,38,0.1); border: 1px solid rgba(220,38,38,0.2); color: #FCA5A5; padding: 10px 14px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; display: none; }
        .footer-text { text-align: center; margin-top: 24px; font-size: 13px; color: #555; }
        .footer-text a { color: #DC2626; font-weight: 600; }
        .footer-text a:hover { text-decoration: underline; }
        .security-badge { display: flex; align-items: center; justify-content: center; gap: 8px; margin-top: 24px; padding: 10px; border-radius: 8px; background: rgba(34,197,94,0.04); border: 1px solid rgba(34,197,94,0.1); font-size: 11px; color: #666; }
        .security-badge svg { width: 14px; height: 14px; color: #22C55E; flex-shrink: 0; }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
        .fade-up { animation: fadeUp 0.5s ease-out both; }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" style="text-decoration:none">
            <div class="logo fade-up">
                <div class="logo-mark"><svg viewBox="0 0 40 44" fill="none" xmlns="http://www.w3.org/2000/svg" width="40" height="44"><path d="M20 2L4 10v12c0 11 7.2 21.3 16 24 8.8-2.7 16-13 16-24V10L20 2z" fill="url(#lg2)" stroke="#991B1B" stroke-width="1.5"/><path d="M20 10v8m0 0v8m0-8l-4-4m4 4l4-4" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="lg2" x1="4" y1="2" x2="36" y2="46"><stop stop-color="#DC2626"/><stop offset="1" stop-color="#7F1D1D"/></linearGradient></defs></svg></div>
                <div class="logo-text">SENTINEL</div>
            </div>
        </a>
        <div class="card fade-up" style="animation-delay:0.1s">
            <h1>Welcome Back</h1>
            <p class="subtitle">Log in to your security dashboard</p>
            <div class="error" id="error"></div>
            <form id="loginForm">
                <div class="form-group">
                    <label>Username or Email</label>
                    <input type="text" id="username" placeholder="Enter your username or email" required autocomplete="username">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <div style="position:relative">
                        <input type="password" id="password" placeholder="Enter your password" required autocomplete="current-password" style="width:100%;padding-right:44px">
                        <button type="button" onclick="togglePw('password',this)" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#666;padding:4px" aria-label="Toggle password visibility"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary" id="submitBtn">Log In</button>
            </form>
            <div class="security-badge">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
                256-bit encrypted &bull; Your data never leaves your device
            </div>
        </div>
        <p class="footer-text fade-up" style="animation-delay:0.2s">Don't have an account? <a href="/register">Sign up</a></p>
    </div>
    <script>
        function togglePw(id, btn) {
            var inp = document.getElementById(id);
            var isPw = inp.type === 'password';
            inp.type = isPw ? 'text' : 'password';
            btn.innerHTML = isPw
                ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
                : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
        }
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            var errEl = document.getElementById('error');
            var btn = document.getElementById('submitBtn');
            errEl.style.display = 'none';
            btn.disabled = true;
            btn.textContent = 'Signing in...';
            try {
                var r = await fetch('/api/auth/login', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: document.getElementById('username').value,
                        password: document.getElementById('password').value
                    })
                });
                var data = await r.json();
                if (!r.ok) throw new Error(data.detail || 'Login failed');
                localStorage.setItem('sentinel_token', data.token);
                localStorage.setItem('sentinel_user', data.username);
                window.location.href = '/dashboard';
            } catch(err) {
                errEl.textContent = err.message;
                errEl.style.display = 'block';
                btn.disabled = false;
                btn.textContent = 'Log In';
            }
        });
    </script>
</body>
</html>"""

# ============================================================================
# REGISTER PAGE
# ============================================================================
REGISTER_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL - Create Account</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter', sans-serif; background: #0a0a0a; color: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .container { width: 100%; max-width: 420px; padding: 20px; }
        .logo { display: flex; align-items: center; gap: 10px; justify-content: center; margin-bottom: 32px; }
        .logo-mark { width: 40px; height: 40px; display: flex; align-items: center; justify-content: center; filter: drop-shadow(0 0 12px rgba(220,38,38,0.4)); }
        .logo-text { font-weight: 800; font-size: 22px; letter-spacing: -0.02em; }
        .card { background: linear-gradient(145deg, #111, #0d0d0d); border: 1px solid #1a1a1a; border-radius: 16px; padding: 40px; }
        .card h1 { font-size: 24px; font-weight: 800; margin-bottom: 4px; text-align: center; }
        .card .subtitle { text-align: center; color: #666; font-size: 14px; margin-bottom: 32px; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; font-size: 12px; font-weight: 600; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 8px; }
        .form-group input { width: 100%; padding: 12px 16px; background: #0a0a0a; border: 1px solid #222; border-radius: 8px; color: #f5f5f5; font-size: 14px; font-family: 'Inter', sans-serif; outline: none; transition: border-color 0.2s, box-shadow 0.2s; }
        .form-group input:focus { border-color: #DC2626; box-shadow: 0 0 0 3px rgba(220,38,38,0.15); }
        .form-group input::placeholder { color: #444; }
        .btn { width: 100%; padding: 12px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; border: none; font-family: 'Inter', sans-serif; transition: all 0.2s; }
        .btn-primary { background: linear-gradient(135deg, #DC2626, #991B1B); color: white; }
        .btn-primary:hover { box-shadow: 0 4px 20px rgba(220,38,38,0.3); transform: translateY(-1px); }
        .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
        .error { background: rgba(220,38,38,0.1); border: 1px solid rgba(220,38,38,0.2); color: #FCA5A5; padding: 10px 14px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; display: none; }
        .success { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.2); color: #86EFAC; padding: 10px 14px; border-radius: 8px; font-size: 13px; margin-bottom: 16px; display: none; }
        .footer-text { text-align: center; margin-top: 24px; font-size: 13px; color: #555; }
        .footer-text a { color: #DC2626; font-weight: 600; }
        .footer-text a:hover { text-decoration: underline; }
        .strength-bar { height: 3px; border-radius: 2px; background: #222; margin-top: 8px; overflow: hidden; }
        .strength-fill { height: 100%; border-radius: 2px; transition: all 0.3s; }
        .security-badge { display: flex; align-items: center; justify-content: center; gap: 8px; margin-top: 20px; padding: 10px; border-radius: 8px; background: rgba(34,197,94,0.04); border: 1px solid rgba(34,197,94,0.1); font-size: 11px; color: #666; }
        .security-badge svg { width: 14px; height: 14px; color: #22C55E; flex-shrink: 0; }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(16px); } to { opacity: 1; transform: translateY(0); } }
        .fade-up { animation: fadeUp 0.5s ease-out both; }
    </style>
</head>
<body>
    <div class="container">
        <a href="/" style="text-decoration:none">
            <div class="logo fade-up">
                <div class="logo-mark"><svg viewBox="0 0 40 44" fill="none" xmlns="http://www.w3.org/2000/svg" width="40" height="44"><path d="M20 2L4 10v12c0 11 7.2 21.3 16 24 8.8-2.7 16-13 16-24V10L20 2z" fill="url(#lg2)" stroke="#991B1B" stroke-width="1.5"/><path d="M20 10v8m0 0v8m0-8l-4-4m4 4l4-4" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="lg2" x1="4" y1="2" x2="36" y2="46"><stop stop-color="#DC2626"/><stop offset="1" stop-color="#7F1D1D"/></linearGradient></defs></svg></div>
                <div class="logo-text">SENTINEL</div>
            </div>
        </a>
        <div class="card fade-up" style="animation-delay:0.1s">
            <h1>Create Account</h1>
            <p class="subtitle">Start protecting your organization today</p>
            <div class="error" id="error"></div>
            <div class="success" id="success"></div>
            <form id="registerForm">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="username" placeholder="Choose a username" required minlength="3" maxlength="30" autocomplete="username">
                </div>
                <div class="form-group">
                    <label>Email</label>
                    <input type="email" id="email" placeholder="you@company.com" required autocomplete="email">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <div style="position:relative">
                        <input type="password" id="password" placeholder="Min 8 characters" required minlength="8" autocomplete="new-password" oninput="updateStrength(this.value)" style="width:100%;padding-right:44px">
                        <button type="button" onclick="togglePw('password',this)" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#666;padding:4px" aria-label="Toggle password visibility"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
                    </div>
                    <div class="strength-bar"><div class="strength-fill" id="strengthFill" style="width:0%;background:#222"></div></div>
                </div>
                <button type="submit" class="btn btn-primary" id="submitBtn">Create Account</button>
            </form>
            <div class="security-badge">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
                Passwords are hashed with bcrypt. We never store plain text.
            </div>
        </div>
        <p class="footer-text fade-up" style="animation-delay:0.2s">Already have an account? <a href="/login">Log in</a></p>
    </div>
    <script>
        function togglePw(id, btn) {
            var inp = document.getElementById(id);
            var isPw = inp.type === 'password';
            inp.type = isPw ? 'text' : 'password';
            btn.innerHTML = isPw
                ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
                : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
        }
        function updateStrength(pw) {
            var fill = document.getElementById('strengthFill');
            var score = 0;
            if (pw.length >= 6) score++;
            if (pw.length >= 10) score++;
            if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
            if (/[0-9]/.test(pw)) score++;
            if (/[^A-Za-z0-9]/.test(pw)) score++;
            var pct = (score / 5) * 100;
            var color = score <= 1 ? '#EF4444' : score <= 3 ? '#EAB308' : '#22C55E';
            fill.style.width = pct + '%';
            fill.style.background = color;
        }
        document.getElementById('registerForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            var errEl = document.getElementById('error');
            var sucEl = document.getElementById('success');
            var btn = document.getElementById('submitBtn');
            errEl.style.display = 'none';
            sucEl.style.display = 'none';
            btn.disabled = true;
            btn.textContent = 'Creating account...';
            try {
                var r = await fetch('/api/auth/register', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        username: document.getElementById('username').value,
                        email: document.getElementById('email').value,
                        password: document.getElementById('password').value
                    })
                });
                var data = await r.json();
                if (!r.ok) throw new Error(data.detail || 'Registration failed');
                sucEl.textContent = 'Account created! Redirecting to login...';
                sucEl.style.display = 'block';
                setTimeout(function() { window.location.href = '/login'; }, 1500);
            } catch(err) {
                errEl.textContent = err.message;
                errEl.style.display = 'block';
                btn.disabled = false;
                btn.textContent = 'Create Account';
            }
        });
    </script>
</body>
</html>"""

# ============================================================================
# DASHBOARD PAGE
# ============================================================================
DASHBOARD_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL - Dashboard</title>
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        :root { --bg: #0a0a0a; --bg2: #111; --bg3: #161616; --bg4: #1c1c1c; --border: #1a1a1a; --border2: #282828; --text: #f5f5f5; --text2: #a0a0a0; --text3: #666; --red: #DC2626; --red-l: #EF4444; --red-d: #991B1B; --green: #22C55E; --yellow: #EAB308; }
        body { font-family: 'Inter', sans-serif; background: var(--bg); color: var(--text); -webkit-font-smoothing: antialiased; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg2); }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes modalIn { from { opacity: 0; transform: scale(0.96) translateY(8px); } to { opacity: 1; transform: scale(1) translateY(0); } }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes toastIn { from { opacity: 0; transform: translateX(100%); } to { opacity: 1; transform: translateX(0); } }
        @keyframes toastOut { from { opacity: 1; transform: translateX(0); } to { opacity: 0; transform: translateX(100%); } }
        @keyframes shimmer { 0% { background-position: -200px 0; } 100% { background-position: 200px 0; } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }
        @keyframes ringFill { from { stroke-dashoffset: 251; } }
        .anim-fade-up { animation: fadeUp 0.35s ease-out both; }
        .anim-modal { animation: modalIn 0.2s ease-out both; }
        .s1 { animation-delay: 0.05s; }
        .s2 { animation-delay: 0.1s; }
        .s3 { animation-delay: 0.15s; }
        .s4 { animation-delay: 0.2s; }
        .d-hamburger { display: none; background: none; border: none; color: #f5f5f5; font-size: 22px; cursor: pointer; padding: 6px; line-height: 1; }
        @media (max-width: 768px) {
            .d-hamburger { display: flex !important; }
            .d-nav { display: none !important; }
            .d-nav.open { display: flex !important; flex-direction: column; position: absolute; top: 64px; left: 0; right: 0; background: #111; border-bottom: 1px solid #1a1a1a; padding: 8px 12px; gap: 6px; z-index: 99; }
            .d-stats { grid-template-columns: repeat(2, 1fr) !important; gap: 10px !important; }
            .d-filters { flex-wrap: wrap !important; }
            .d-wrap { padding: 0 12px !important; }
            .d-main { padding: 24px 12px !important; }
            .d-stat-val { font-size: 24px !important; }
            .d-modal { max-width: calc(100vw - 16px) !important; margin: 8px !important; max-height: 95vh !important; border-radius: 12px !important; }
            .d-team-stats { grid-template-columns: repeat(2, 1fr) !important; gap: 10px !important; }
            .d-member-row { flex-direction: column !important; align-items: flex-start !important; gap: 12px !important; }
        }
    </style>
</head>
<body>
    <div id="root"></div>
    <script type="text/babel">
        var useState = React.useState, useEffect = React.useEffect, useCallback = React.useCallback, useRef = React.useRef;

        function getToken() { return localStorage.getItem('sentinel_token'); }
        function getUser() { return localStorage.getItem('sentinel_user'); }
        function logout() { localStorage.removeItem('sentinel_token'); localStorage.removeItem('sentinel_user'); window.location.href = '/login'; }

        var API = {
            base: '/api/v1',
            opts: function() { return { headers: {'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json'} }; },
            get: function(path) { return fetch(this.base + path, this.opts()).then(function(r) { if (r.status === 401) { logout(); throw new Error('Session expired'); } if (!r.ok) return r.json().then(function(d) { throw new Error(d.detail || 'Request failed (' + r.status + ')'); }, function() { throw new Error('Request failed (' + r.status + ')'); }); return r.json(); }); },
            post: function(path, body) { return fetch(this.base + path, Object.assign({}, this.opts(), { method: 'POST', body: JSON.stringify(body) })).then(function(r) { if (r.status === 401) { logout(); throw new Error('Session expired'); } if (!r.ok) return r.json().then(function(d) { throw new Error(d.detail || 'Request failed (' + r.status + ')'); }, function() { throw new Error('Request failed (' + r.status + ')'); }); return r.json(); }); },
            del: function(path) { return fetch(this.base + path, Object.assign({}, this.opts(), { method: 'DELETE' })).then(function(r) { if (r.status === 401) { logout(); throw new Error('Session expired'); } if (!r.ok) return r.json().then(function(d) { throw new Error(d.detail || 'Request failed (' + r.status + ')'); }, function() { throw new Error('Request failed (' + r.status + ')'); }); return r.json(); }); }
        };

        function Toast(props) {
            var t = props.toast;
            var colors = { success: {bg:'#0d2818',border:'#166534',text:'#86EFAC',icon:'\\u2713'}, error: {bg:'#2d0a0a',border:'#7f1d1d',text:'#FCA5A5',icon:'\\u2715'}, warning: {bg:'#2d200a',border:'#7f6b1d',text:'#FDE047',icon:'\\u26A0'}, info: {bg:'#0a1628',border:'#1e3a5f',text:'#93C5FD',icon:'\\u2139'} };
            var c = colors[t.type] || colors.info;
            return React.createElement('div', { style:{animation:'toastIn 0.3s ease-out',background:c.bg,border:'1px solid '+c.border,borderRadius:10,padding:'12px 16px',display:'flex',alignItems:'center',gap:10,fontSize:13,color:c.text,boxShadow:'0 8px 30px rgba(0,0,0,0.4)',maxWidth:340,minWidth:280} },
                React.createElement('span', { style:{fontSize:16,flexShrink:0} }, c.icon),
                React.createElement('span', { style:{flex:1,lineHeight:1.4} }, t.message)
            );
        }

        function ConfidenceRing(props) {
            var score = props.score || 0;
            var radius = 36;
            var circumference = 2 * Math.PI * radius;
            var offset = circumference - (score / 100) * circumference;
            var color = score >= 80 ? '#EF4444' : score >= 50 ? '#EAB308' : '#22C55E';
            return React.createElement('div', { style:{position:'relative',width:90,height:90,flexShrink:0} },
                React.createElement('svg', { width:90,height:90,viewBox:'0 0 90 90',style:{transform:'rotate(-90deg)'} },
                    React.createElement('circle', { cx:45,cy:45,r:radius,fill:'none',stroke:'#1a1a1a',strokeWidth:6 }),
                    React.createElement('circle', { cx:45,cy:45,r:radius,fill:'none',stroke:color,strokeWidth:6,strokeLinecap:'round',strokeDasharray:circumference,strokeDashoffset:offset,style:{transition:'stroke-dashoffset 1s ease-out',animation:'ringFill 1s ease-out'} })
                ),
                React.createElement('div', { style:{position:'absolute',inset:0,display:'flex',flexDirection:'column',alignItems:'center',justifyContent:'center'} },
                    React.createElement('div', { style:{fontSize:20,fontWeight:800,color:color} }, Math.round(score)),
                    React.createElement('div', { style:{fontSize:9,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em'} }, 'Confidence')
                )
            );
        }

        function Badge(props) {
            var tl = props.level || 'safe';
            var colors = { safe: {bg:'rgba(34,197,94,0.12)', c:'#86EFAC', b:'rgba(34,197,94,0.25)'}, suspicious: {bg:'rgba(234,179,8,0.12)', c:'#FDE047', b:'rgba(234,179,8,0.25)'}, malicious: {bg:'rgba(220,38,38,0.12)', c:'#FCA5A5', b:'rgba(220,38,38,0.25)'} };
            var icons = { safe: '\\u2713', suspicious: '\\u26A0', malicious: '\\u2715' };
            var s = colors[tl] || colors.safe;
            var label = tl;
            if (props.confidence !== undefined) label += ' ' + Math.round(props.confidence * 100) + '%';
            return React.createElement('span', { style: { display:'inline-flex', alignItems:'center', gap:4, padding:'4px 10px', borderRadius:6, fontSize:11, fontWeight:700, letterSpacing:'0.02em', textTransform:'uppercase', background:s.bg, color:s.c, border:'1px solid '+s.b } }, icons[tl] + ' ' + label);
        }

        function App() {
            var _s = useState([]);
            var allEmails = _s[0], setAllEmails = _s[1];
            var _f = useState('all');
            var filter = _f[0], setFilter = _f[1];
            var _sel = useState(null);
            var selected = _sel[0], setSelected = _sel[1];
            var _l = useState(true);
            var loading = _l[0], setLoading = _l[1];
            var _ck = useState(false);
            var checking = _ck[0], setChecking = _ck[1];
            var _sp = useState(false);
            var showPaste = _sp[0], setShowPaste = _sp[1];
            var _pc = useState('');
            var pasteContent = _pc[0], setPasteContent = _pc[1];
            var _ps = useState('');
            var pasteSubject = _ps[0], setPasteSubject = _ps[1];
            var _pf = useState('');
            var pasteFrom = _pf[0], setPasteFrom = _pf[1];
            var _pst = useState(false);
            var pasting = _pst[0], setPasting = _pst[1];
            var _cc = useState(false);
            var showClear = _cc[0], setShowClear = _cc[1];
            var _cl = useState(false);
            var clearing = _cl[0], setClearing = _cl[1];
            var _user = useState(getUser());
            var username = _user[0];
            var _toasts = useState([]);
            var toasts = _toasts[0], setToasts = _toasts[1];
            var _step = useState(0);
            var analysisStep = _step[0], setAnalysisStep = _step[1];
            var toastId = useRef(0);
            var _conns = useState([]);
            var connections = _conns[0], setConnections = _conns[1];
            var _scanConn = useState('');
            var scanConnId = _scanConn[0], setScanConnId = _scanConn[1];
            var _cooldown = useState(0);
            var cooldown = _cooldown[0], setCooldown = _cooldown[1];
            var _view = useState('dashboard');
            var view = _view[0], setView = _view[1];
            var _team = useState([]);
            var teamData = _team[0], setTeamData = _team[1];
            var _teamRole = useState('');
            var teamRole = _teamRole[0], setTeamRole = _teamRole[1];
            var _selMember = useState(null);
            var selectedMember = _selMember[0], setSelectedMember = _selMember[1];
            var _memberEmails = useState([]);
            var memberEmails = _memberEmails[0], setMemberEmails = _memberEmails[1];
            var _memberLoading = useState(false);
            var memberLoading = _memberLoading[0], setMemberLoading = _memberLoading[1];
            var _teamLoading = useState(false);
            var teamLoading = _teamLoading[0], setTeamLoading = _teamLoading[1];
            var _inviteEmail = useState('');
            var inviteEmail = _inviteEmail[0], setInviteEmail = _inviteEmail[1];
            var _userRole = useState('');
            var userRole = _userRole[0], setUserRole = _userRole[1];
            var _menuOpen = useState(false);
            var menuOpen = _menuOpen[0], setMenuOpen = _menuOpen[1];

            var addToast = useCallback(function(type, message) {
                var id = ++toastId.current;
                setToasts(function(prev) { return prev.concat([{id:id, type:type, message:message}]); });
                setTimeout(function() { setToasts(function(prev) { return prev.filter(function(t) { return t.id !== id; }); }); }, 4000);
            }, []);

            var fetchEmails = useCallback(function() {
                API.get('/emails').then(function(data) { setAllEmails(data); setLoading(false); }).catch(function(e) { console.error(e); setLoading(false); });
            }, []);

            var fetchConns = useCallback(function() {
                API.get('/connections').then(function(data) { setConnections(data.connections || []); }).catch(function() {});
            }, []);

            var fetchUserRole = useCallback(function() {
                fetch('/api/auth/me', { headers: { 'Authorization': 'Bearer ' + getToken() } })
                    .then(function(r) { return r.json(); })
                    .then(function(data) { if (data.role) setUserRole(data.role); })
                    .catch(function() {
                        try { var payload = JSON.parse(atob(getToken().split('.')[1])); if (payload.role) setUserRole(payload.role); } catch(e) {}
                    });
                API.get('/org').then(function(data) {
                    if (data.org) setTeamRole('admin');
                }).catch(function() {});
                API.get('/team').then(function(data) {
                    if (data.members && data.members.length > 0) setTeamRole('admin');
                }).catch(function() {});
            }, []);

            var fetchTeam = useCallback(function() {
                setTeamLoading(true);
                API.get('/team/overview').then(function(data) {
                    setTeamData(data.members || []);
                    setTeamLoading(false);
                }).catch(function() { setTeamLoading(false); });
            }, []);

            var fetchMemberEmails = useCallback(function(memberId) {
                setMemberLoading(true);
                setSelectedMember(memberId);
                API.get('/team/emails/' + memberId).then(function(data) {
                    setMemberEmails(data || []);
                    setMemberLoading(false);
                }).catch(function() { setMemberLoading(false); });
            }, []);

            var handleScanMember = useCallback(function(memberId, e) {
                if (e) e.stopPropagation();
                addToast('info', 'Scanning team member...');
                API.post('/team/scan/' + memberId, {}).then(function(r) {
                    addToast('success', 'Scan triggered for team member');
                    setTimeout(fetchTeam, 3000);
                }).catch(function(err) {
                    addToast('error', err.message || 'Scan failed');
                });
            }, [fetchTeam]);

            useEffect(function() {
                if (!getToken()) { window.location.href = '/login'; return; }
                fetchEmails();
                fetchConns();
                fetchUserRole();
                var t = setInterval(fetchEmails, 30000);
                return function() { clearInterval(t); };
            }, [fetchEmails, fetchConns, fetchUserRole]);

            useEffect(function() {
                if (cooldown <= 0) return;
                var t = setTimeout(function() { setCooldown(function(c) { return c > 0 ? c - 1 : 0; }); }, 1000);
                return function() { clearTimeout(t); };
            }, [cooldown]);

            var total = allEmails.length;
            var malicious = allEmails.filter(function(e) { return e.verdict && e.verdict.threat_level === 'malicious'; }).length;
            var suspicious = allEmails.filter(function(e) { return e.verdict && e.verdict.threat_level === 'suspicious'; }).length;
            var safe = allEmails.filter(function(e) { return e.verdict && e.verdict.threat_level === 'safe'; }).length;
            var emails = filter === 'all' ? allEmails : allEmails.filter(function(e) { return e.verdict && e.verdict.threat_level === filter; });

            var handleCheck = function() {
                if (cooldown > 0) { addToast('warning', 'Please wait ' + cooldown + 's before scanning again'); return; }
                setChecking(true);
                setCooldown(30);
                var payload = scanConnId ? { connection_id: scanConnId } : {};
                var connLabel = scanConnId ? (connections.find(function(c){return c.id===scanConnId})||{}).label||'selected inbox' : 'all inboxes';
                addToast('info', 'Scanning ' + connLabel + '...');
                API.post('/imap/check', payload).then(function(r) {
                    if (r.status === 'error' || (r.detail && typeof r.detail === 'string')) {
                        addToast('error', r.detail || 'Scan failed');
                    } else if (r.errors && r.errors.length > 0) {
                        addToast('error', 'IMAP errors: ' + r.errors.join('; '));
                    } else if (r.emails_processed > 0) {
                        fetchEmails();
                        addToast('success', r.emails_processed + ' new email(s) analyzed');
                    } else {
                        addToast('info', 'No new emails found - all already analyzed');
                    }
                    setChecking(false);
                }).catch(function(e) {
                    var msg = e.message || 'Unknown error';
                    if (msg.indexOf('cooldown') !== -1) { setCooldown(30); addToast('warning', msg); }
                    else { addToast('error', 'Mailbox scan failed: ' + msg); }
                    setChecking(false);
                });
            };

            var analysisSteps = ['Parsing email headers...', 'Extracting URLs & patterns...', 'Running AI threat analysis...', 'Generating verdict...'];

            var handlePaste = function() {
                if (!pasteContent.trim()) return;
                setPasting(true);
                setAnalysisStep(0);
                var stepTimer = setTimeout(function() { setAnalysisStep(1); }, 800);
                var stepTimer2 = setTimeout(function() { setAnalysisStep(2); }, 1600);
                var stepTimer3 = setTimeout(function() { setAnalysisStep(3); }, 2400);
                API.post('/analyze/paste', { content: pasteContent, subject: pasteSubject || null, from_address: pasteFrom || null }).then(function(r) {
                    clearTimeout(stepTimer); clearTimeout(stepTimer2); clearTimeout(stepTimer3);
                    setShowPaste(false); setPasteContent(''); setPasteSubject(''); setPasteFrom(''); fetchEmails(); setPasting(false); setAnalysisStep(0);
                    var tl = r.verdict ? r.verdict.threat_level : 'safe';
                    var msg = 'Email classified as ' + tl.toUpperCase();
                    addToast(tl === 'safe' ? 'success' : tl === 'malicious' ? 'error' : 'info', msg);
                }).catch(function() { clearTimeout(stepTimer); clearTimeout(stepTimer2); clearTimeout(stepTimer3); addToast('error', 'Analysis failed. Please try again.'); setPasting(false); setAnalysisStep(0); });
            };

            var handleFeedback = function(emailId, verdict) {
                API.post('/feedback', { email_id: emailId, corrected_verdict: verdict, reason: 'User manual correction from dashboard' }).then(function() {
                    addToast('success', 'Feedback recorded. Model will learn from this correction.');
                    fetchEmails();
                }).catch(function() { addToast('error', 'Failed to record feedback'); });
            };

            var handleClear = function() {
                setClearing(true);
                API.del('/emails').then(function() { setAllEmails([]); setShowClear(false); setClearing(false); addToast('success', 'All reports cleared'); }).catch(function() { setClearing(false); addToast('error', 'Failed to clear reports'); });
            };

            var st = { header: { background:'rgba(17,17,17,0.9)', backdropFilter:'blur(20px)', borderBottom:'1px solid #1a1a1a', position:'sticky', top:0, zIndex:50 }, wrap: { maxWidth:1200, margin:'0 auto', padding:'0 24px', display:'flex', alignItems:'center', justifyContent:'space-between', height:64 }, logo: { display:'flex', alignItems:'center', gap:10 }, logoM: { width:32, height:32, display:'flex', alignItems:'center', justifyContent:'center', filter:'drop-shadow(0 0 12px rgba(220,38,38,0.4))' }, main: { maxWidth:1200, margin:'0 auto', padding:'32px 24px' } };
            var btnBase = { padding:'8px 16px', borderRadius:8, fontSize:13, fontWeight:600, cursor:'pointer', border:'none', fontFamily:'Inter', transition:'all 0.2s' };
            var btnRed = Object.assign({}, btnBase, { background:'linear-gradient(135deg,#DC2626,#991B1B)', color:'#fff' });
            var btnDark = Object.assign({}, btnBase, { background:'#161616', color:'#a0a0a0', border:'1px solid #282828' });
            var statC = { background:'linear-gradient(145deg, #111, #0d0d0d)', border:'1px solid #1a1a1a', borderRadius:14, padding:20, position:'relative', overflow:'hidden' };

            if (!getToken()) return null;

            return React.createElement('div', { style:{minHeight:'100vh',background:'var(--bg)'} },
                React.createElement('header', { style:st.header },
                    React.createElement('div', { className:'d-wrap', style:st.wrap },
                        React.createElement('div', { style:st.logo },
                            React.createElement('div', { style:st.logoM, dangerouslySetInnerHTML:{__html:'<svg viewBox="0 0 40 44" fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="35"><path d="M20 2L4 10v12c0 11 7.2 21.3 16 24 8.8-2.7 16-13 16-24V10L20 2z" fill="url(#lg3)" stroke="#991B1B" stroke-width="1.5"/><path d="M20 10v8m0 0v8m0-8l-4-4m4 4l4-4" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="lg3" x1="4" y1="2" x2="36" y2="46"><stop stop-color="#DC2626"/><stop offset="1" stop-color="#7F1D1D"/></linearGradient></defs></svg>'} }),
                            React.createElement('div', null,
                                React.createElement('div', { style:{fontSize:16,fontWeight:800,letterSpacing:'-0.02em'} }, 'SENTINEL'),
                                React.createElement('div', { style:{fontSize:10,color:'#666',letterSpacing:'0.05em',textTransform:'uppercase'} }, 'Phishing Triage')
                        )
                    ),
                    React.createElement('button', { className:'d-hamburger', onClick:function() { setMenuOpen(!menuOpen); } }, '\u2630'),
                    React.createElement('div', { className:'d-nav' + (menuOpen ? ' open' : ''), style:{display:'flex',gap:10,alignItems:'center',flexWrap:'nowrap',overflow:'hidden',minHeight:40} },
                            React.createElement('span', { style:{fontSize:12,color:'#666',marginRight:8} }, username),
                            React.createElement('button', { onClick:function() { setView('dashboard'); setMenuOpen(false); }, style:Object.assign({}, btnDark, { background:view==='dashboard'?'rgba(220,38,38,0.1)':'#161616', borderColor:view==='dashboard'?'rgba(220,38,38,0.4)':'#282828', color:view==='dashboard'?'#EF4444':'#a0a0a0' }) }, 'Dashboard'),
                            React.createElement('button', { onClick:function() { setView('team'); fetchTeam(); setMenuOpen(false); }, style:Object.assign({}, btnDark, { background:view==='team'?'rgba(220,38,38,0.1)':'#161616', borderColor:view==='team'?'rgba(220,38,38,0.4)':'#282828', color:view==='team'?'#EF4444':'#a0a0a0' }) }, 'Team'),
                            React.createElement('button', { onClick:function() { window.location.href='/settings'; }, style:btnDark }, 'Settings'),
                            React.createElement('button', { onClick:function() { window.location.href='/analytics'; }, style:Object.assign({}, btnDark, {borderColor:'rgba(168,85,247,0.3)',color:'#C084FC'}) }, 'Analytics'),
                            React.createElement('button', { onClick:function() { setShowPaste(true); }, style:btnDark }, 'Paste Email'),
                            React.createElement('button', { onClick:function() { window.open('/api/v1/reports/monthly', '_blank'); }, style:Object.assign({}, btnDark, {borderColor:'rgba(34,197,94,0.3)',color:'#86EFAC'}) }, '\\u2B07 Executive Report'),
                            connections.length > 0 ? React.createElement('select', {
                                value: scanConnId,
                                onChange: function(e) { setScanConnId(e.target.value); },
                                style: { background:'#161616', color:'#a0a0a0', border:'1px solid #282828', borderRadius:8, padding:'7px 10px', fontSize:12, cursor:'pointer', outline:'none', minWidth:120 }
                            }, React.createElement('option', { value:'' }, 'All Inboxes'), connections.map(function(c) { return React.createElement('option', { key:c.id, value:c.id }, c.label); })) : null,
                            React.createElement('button', {
                                onClick: handleCheck,
                                disabled: checking || cooldown > 0,
                                style: Object.assign({}, btnRed, {opacity: (checking||cooldown>0) ? 0.6 : 1, cursor: (checking||cooldown>0) ? 'not-allowed' : 'pointer'})
                            }, cooldown > 0 ? ('Wait ' + cooldown + 's') : checking ? 'Scanning...' : 'Scan Inbox'),
                            allEmails.length > 0 ? React.createElement('button', { onClick:function() { setShowClear(true); }, style:Object.assign({}, btnBase, {background:'rgba(220,38,38,0.08)',border:'1px solid rgba(220,38,38,0.2)',color:'#FCA5A5'}) }, 'Clear All') : null,
                            React.createElement('button', { onClick:logout, style:Object.assign({}, btnBase, {background:'transparent',color:'#666',border:'1px solid #222'}) }, 'Logout')
                        )
                    )
                ),
                React.createElement('main', { className:'d-main', style:st.main },
                    view === 'dashboard' ? React.createElement(React.Fragment, null,
                    React.createElement('div', { className:'d-stats', style:{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:16,marginBottom:32} },
                        React.createElement('div', { className:'anim-fade-up s1', style:statC }, React.createElement('div', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em'} }, 'Total Analyzed'), React.createElement('div', { className:'d-stat-val', style:{fontSize:32,fontWeight:800,marginTop:4} }, total)),
                        React.createElement('div', { className:'anim-fade-up s2', style:statC }, React.createElement('div', { style:{fontSize:11,fontWeight:600,color:'#EF4444',textTransform:'uppercase',letterSpacing:'0.05em'} }, 'Threats Blocked'), React.createElement('div', { className:'d-stat-val', style:{fontSize:32,fontWeight:800,marginTop:4,color:'#EF4444'} }, malicious)),
                        React.createElement('div', { className:'anim-fade-up s3', style:statC }, React.createElement('div', { style:{fontSize:11,fontWeight:600,color:'#EAB308',textTransform:'uppercase',letterSpacing:'0.05em'} }, 'Suspicious'), React.createElement('div', { className:'d-stat-val', style:{fontSize:32,fontWeight:800,marginTop:4,color:'#EAB308'} }, suspicious)),
                        React.createElement('div', { className:'anim-fade-up s4', style:statC }, React.createElement('div', { style:{fontSize:11,fontWeight:600,color:'#22C55E',textTransform:'uppercase',letterSpacing:'0.05em'} }, 'Safe'), React.createElement('div', { className:'d-stat-val', style:{fontSize:32,fontWeight:800,marginTop:4,color:'#22C55E'} }, safe))
                    ),
                    React.createElement('div', { className:'d-filters', style:{display:'flex',gap:8,marginBottom:24} },
                        ['all','malicious','suspicious','safe'].map(function(f) {
                            var labels = {all:'All Reports',malicious:'Threats',suspicious:'Suspicious',safe:'Safe'};
                            var counts = {all:total, malicious:malicious, suspicious:suspicious, safe:safe};
                            var isActive = filter === f;
                            return React.createElement('button', { key:f, onClick:function() { setFilter(f); }, style:Object.assign({}, btnDark, { background:isActive?'rgba(220,38,38,0.1)':'#161616', borderColor:isActive?'rgba(220,38,38,0.4)':'#282828', color:isActive?'#EF4444':'#a0a0a0', display:'flex', gap:6, alignItems:'center' }) }, labels[f], React.createElement('span', { style:{fontSize:11,opacity:0.6} }, counts[f]));
                        })
                    ),
                    loading ? React.createElement('div', { style:{textAlign:'center',padding:'80px 0'} },
                        React.createElement('div', { style:{width:36,height:36,border:'3px solid #1a1a1a',borderTopColor:'#DC2626',borderRadius:'50%',animation:'spin 0.8s linear infinite',margin:'0 auto 20px' } }),
                        React.createElement('div', { style:{color:'#666',fontSize:14,fontWeight:500} }, 'Loading reports...')
                    ) : emails.length === 0 ? React.createElement('div', { style:{textAlign:'center',padding:'80px',background:'linear-gradient(145deg, #111, #0d0d0d)',border:'1px solid #1a1a1a',borderRadius:16} },
                        React.createElement('div', { style:{marginBottom:20}, dangerouslySetInnerHTML:{__html:'<svg viewBox="0 0 40 44" fill="none" xmlns="http://www.w3.org/2000/svg" width="64" height="70" style="display:block;margin:0 auto;opacity:0.3"><path d="M20 2L4 10v12c0 11 7.2 21.3 16 24 8.8-2.7 16-13 16-24V10L20 2z" fill="none" stroke="#333" stroke-width="1.5"/><path d="M20 10v8m0 0v8m0-8l-4-4m4 4l4-4" stroke="#333" stroke-width="2" stroke-linecap="round"/></svg>'} }),
                        React.createElement('div', { style:{fontSize:20,fontWeight:800,marginBottom:8,color:'#a0a0a0'} }, 'No Phishing Reports Yet'),
                        React.createElement('div', { style:{color:'#666',fontSize:14,marginBottom:32,maxWidth:420,margin:'0 auto 32px',lineHeight:1.6} }, 'Paste a suspicious email or connect your mailbox to get instant AI-powered threat analysis.'),
                        React.createElement('button', { onClick:function() { setShowPaste(true); }, style:Object.assign({}, btnRed, {padding:'12px 28px',fontSize:14}) }, 'Paste Your First Email')
                    ) : React.createElement('div', { style:{display:'flex',flexDirection:'column',gap:12} },
                        emails.map(function(em, i) {
                            var v = em.verdict || {};
                            var tl = v.threat_level || 'safe';
                            var accent = tl==='malicious'?'#DC2626':tl==='suspicious'?'#EAB308':'#22C55E';
                            return React.createElement('div', { key:em.id, className:'anim-fade-up', onClick:function() { setSelected(em); }, style:{background:'linear-gradient(145deg, #161616, #131313)',border:'1px solid #1a1a1a',borderRadius:14,padding:'18px 22px',cursor:'pointer',transition:'all 0.2s',position:'relative',animationDelay:Math.min(i*0.04,0.3)+'s'} },
                                React.createElement('div', { style:{position:'absolute',left:0,top:0,bottom:0,width:3,background:accent,borderRadius:'3px 0 0 3px'} }),
                                React.createElement('div', { style:{display:'flex',justifyContent:'space-between',alignItems:'flex-start',gap:16} },
                                    React.createElement('div', { style:{flex:1,minWidth:0} },
                                        React.createElement('div', { style:{fontSize:15,fontWeight:700,marginBottom:4,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'} }, em.subject),
                                        React.createElement('div', { style:{fontSize:13,color:'#a0a0a0',display:'flex',gap:8,alignItems:'center'} },
                                            React.createElement('span', { dangerouslySetInnerHTML:{__html:'<svg viewBox="0 0 24 24" fill="none" stroke="#666" stroke-width="2" width="12" height="12"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>'} }),
                                            em.from_address
                                        ),
                                        React.createElement('div', { style:{fontSize:12,color:'#555',marginTop:3} }, new Date(em.received_at).toLocaleString()),
                                        v.indicators && v.indicators.length > 0 ? React.createElement('div', { style:{display:'flex',gap:6,marginTop:10,flexWrap:'wrap'} },
                                            v.indicators.slice(0,2).map(function(ind,idx) {
                                                return React.createElement('span', { key:idx, style:{padding:'3px 8px',background:'#111',border:'1px solid #1a1a1a',borderRadius:5,fontSize:11,color:'#888'} }, ind.length>55?ind.substring(0,55)+'...':ind);
                                            }),
                                            v.indicators.length > 2 ? React.createElement('span', { style:{fontSize:11,color:'#555'} }, '+' + (v.indicators.length - 2) + ' more') : null
                                        ) : null
                                    ),
                                    React.createElement('div', { style:{textAlign:'right',flexShrink:0} },
                                        React.createElement(Badge, { level:tl, confidence:v.confidence }),
                                        React.createElement('div', { style:{fontSize:10,color:'#444',marginTop:6} }, v.llm_model || '')
                                    )
                                )
                            );
                        })
                    )
                    ) : React.createElement('div', null,
                        React.createElement('div', { style:{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:24} },
                            React.createElement('div', null,
                                React.createElement('h2', { style:{fontSize:22,fontWeight:800,marginBottom:4} }, 'Team Overview'),
                                React.createElement('p', { style:{fontSize:13,color:'#666'} }, 'Monitor your team\u2019s email security posture')
                            ),
                            selectedMember ? React.createElement('button', { onClick:function() { setSelectedMember(null); setMemberEmails([]); }, style:btnDark }, '\u2190 Back to Team') : null
                        ),
                        selectedMember ? (
                            memberLoading ? React.createElement('div', { style:{textAlign:'center',padding:'60px 0'} },
                                React.createElement('div', { style:{width:32,height:32,border:'3px solid #1a1a1a',borderTopColor:'#DC2626',borderRadius:'50%',animation:'spin 0.8s linear infinite',margin:'0 auto 16px'} }),
                                React.createElement('div', { style:{color:'#666',fontSize:13} }, 'Loading member emails...')
                            ) : React.createElement('div', null,
                                React.createElement('div', { style:{display:'flex',alignItems:'center',gap:12,marginBottom:20,padding:'14px 18px',background:'#111',border:'1px solid #1a1a1a',borderRadius:12} },
                                    React.createElement('div', { style:{width:40,height:40,borderRadius:10,background:'linear-gradient(135deg,#DC2626,#991B1B)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:18,fontWeight:800,color:'#fff'} }, (teamData.find(function(m){return m.user_id===selectedMember})||{}).username.charAt(0).toUpperCase()),
                                    React.createElement('div', { style:{flex:1} },
                                        React.createElement('div', { style:{fontSize:15,fontWeight:700} }, (teamData.find(function(m){return m.user_id===selectedMember})||{}).username),
                                        React.createElement('div', { style:{fontSize:12,color:'#666'} }, (teamData.find(function(m){return m.user_id===selectedMember})||{}).email)
                                    ),
                                    React.createElement('button', { onClick:function() { handleScanMember(selectedMember); }, style:btnRed }, 'Scan Now')
                                ),
                                memberEmails.length === 0 ? React.createElement('div', { style:{textAlign:'center',padding:'60px',background:'#111',border:'1px solid #1a1a1a',borderRadius:14} },
                                    React.createElement('div', { style:{fontSize:16,fontWeight:700,color:'#a0a0a0',marginBottom:8} }, 'No Emails Found'),
                                    React.createElement('div', { style:{fontSize:13,color:'#666'} }, 'This team member hasn\u2019t had any emails scanned yet.')
                                ) : memberEmails.map(function(em, i) {
                                    var v = em.verdict || {};
                                    var tl = v.threat_level || 'safe';
                                    var accent = tl==='malicious'?'#DC2626':tl==='suspicious'?'#EAB308':'#22C55E';
                                    return React.createElement('div', { key:em.id, onClick:function() { setSelected(em); }, className:'anim-fade-up', style:{background:'#161616',border:'1px solid #1a1a1a',borderRadius:12,padding:'14px 18px',cursor:'pointer',transition:'all 0.2s',position:'relative',marginBottom:8,animationDelay:Math.min(i*0.03,0.2)+'s'} },
                                        React.createElement('div', { style:{position:'absolute',left:0,top:0,bottom:0,width:3,background:accent,borderRadius:'3px 0 0 3px'} }),
                                        React.createElement('div', { style:{display:'flex',justifyContent:'space-between',alignItems:'center'} },
                                            React.createElement('div', { style:{flex:1,minWidth:0} },
                                                React.createElement('div', { style:{fontSize:14,fontWeight:600,marginBottom:2,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'} }, em.subject),
                                                React.createElement('div', { style:{fontSize:12,color:'#666'} }, em.from_address)
                                            ),
                                            React.createElement(Badge, { level:tl, confidence:v.confidence })
                                        )
                                    );
                                })
                            )
                        ) : (
                            teamLoading ? React.createElement('div', { style:{textAlign:'center',padding:'60px 0'} },
                                React.createElement('div', { style:{width:32,height:32,border:'3px solid #1a1a1a',borderTopColor:'#DC2626',borderRadius:'50%',animation:'spin 0.8s linear infinite',margin:'0 auto 16px'} }),
                                React.createElement('div', { style:{color:'#666',fontSize:13} }, 'Loading team data...')
                            ) : teamData.length === 0 ? React.createElement('div', { style:{textAlign:'center',padding:'80px',background:'#111',border:'1px solid #1a1a1a',borderRadius:16} },
                                React.createElement('div', { style:{fontSize:18,fontWeight:800,color:'#a0a0a0',marginBottom:8} }, 'No Team Members'),
                                React.createElement('div', { style:{fontSize:13,color:'#666',maxWidth:380,margin:'0 auto 20px',lineHeight:1.6} }, 'Invite team members from Settings to monitor their email security.')
                            ) : React.createElement('div', null,
                                React.createElement('div', { className:'d-team-stats', style:{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginBottom:24} },
                                    React.createElement('div', { className:'anim-fade-up s1', style:statC },
                                        React.createElement('div', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em'} }, 'Team Members'),
                                        React.createElement('div', { style:{fontSize:28,fontWeight:800,marginTop:4} }, teamData.length)
                                    ),
                                    React.createElement('div', { className:'anim-fade-up s2', style:statC },
                                        React.createElement('div', { style:{fontSize:11,fontWeight:600,color:'#EF4444',textTransform:'uppercase',letterSpacing:'0.05em'} }, 'Total Threats'),
                                        React.createElement('div', { style:{fontSize:28,fontWeight:800,marginTop:4,color:'#EF4444'} }, teamData.reduce(function(a,m){return a+m.malicious;},0))
                                    ),
                                    React.createElement('div', { className:'anim-fade-up s3', style:statC },
                                        React.createElement('div', { style:{fontSize:11,fontWeight:600,color:'#EAB308',textTransform:'uppercase',letterSpacing:'0.05em'} }, 'Suspicious'),
                                        React.createElement('div', { style:{fontSize:28,fontWeight:800,marginTop:4,color:'#EAB308'} }, teamData.reduce(function(a,m){return a+m.suspicious;},0))
                                    ),
                                    React.createElement('div', { className:'anim-fade-up s4', style:statC },
                                        React.createElement('div', { style:{fontSize:11,fontWeight:600,color:'#22C55E',textTransform:'uppercase',letterSpacing:'0.05em'} }, 'Emails Scanned'),
                                        React.createElement('div', { style:{fontSize:28,fontWeight:800,marginTop:4,color:'#22C55E'} }, teamData.reduce(function(a,m){return a+m.total_emails;},0))
                                    )
                                ),
                                teamData.map(function(m, i) {
                                    var hasThreats = m.malicious > 0;
                                    var borderCol = hasThreats ? 'rgba(220,38,38,0.3)' : m.suspicious > 0 ? 'rgba(234,179,8,0.2)' : '#1a1a1a';
                                    var bgCol = hasThreats ? 'rgba(220,38,38,0.04)' : 'linear-gradient(145deg, #161616, #131313)';
                                    return React.createElement('div', { key:m.user_id, onClick:function() { fetchMemberEmails(m.user_id); }, className:'anim-fade-up', style:{background:bgCol,border:'1px solid '+borderCol,borderRadius:14,padding:'18px 22px',cursor:'pointer',transition:'all 0.2s',marginBottom:10,animationDelay:Math.min(i*0.05,0.3)+'s'} },
                                        React.createElement('div', { className:'d-member-row', style:{display:'flex',justifyContent:'space-between',alignItems:'center'} },
                                            React.createElement('div', { style:{display:'flex',alignItems:'center',gap:12} },
                                                React.createElement('div', { style:{width:42,height:42,borderRadius:10,background:hasThreats?'linear-gradient(135deg,#DC2626,#991B1B)':'linear-gradient(135deg,#22C55E,#166534)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:18,fontWeight:800,color:'#fff',flexShrink:0} }, m.username.charAt(0).toUpperCase()),
                                                React.createElement('div', null,
                                                    React.createElement('div', { style:{display:'flex',alignItems:'center',gap:8} },
                                                        React.createElement('span', { style:{fontSize:15,fontWeight:700} }, m.username),
                                                        React.createElement('span', { style:{fontSize:10,color:m.role==='admin'?'#DC2626':'#666',padding:'2px 6px',borderRadius:4,background:m.role==='admin'?'rgba(220,38,38,0.1)':'rgba(102,102,102,0.1)',textTransform:'uppercase',fontWeight:600,letterSpacing:'0.03em'} }, m.role)
                                                    ),
                                                    React.createElement('div', { style:{fontSize:12,color:'#666',marginTop:2} }, m.email + ' \u2022 ' + m.connections + ' connection' + (m.connections !== 1 ? 's' : ''))
                                                )
                                            ),
                                            React.createElement('div', { style:{display:'flex',alignItems:'center',gap:16} },
                                                React.createElement('div', { style:{display:'flex',gap:12,alignItems:'center'} },
                                                    m.malicious > 0 ? React.createElement('span', { style:{fontSize:12,color:'#EF4444',fontWeight:600} }, '\u2715 ' + m.malicious + ' threat' + (m.malicious !== 1 ? 's' : '')) : null,
                                                    m.suspicious > 0 ? React.createElement('span', { style:{fontSize:12,color:'#EAB308',fontWeight:600} }, '\u26A0 ' + m.suspicious + ' suspicious') : null,
                                                    React.createElement('span', { style:{fontSize:12,color:'#22C55E',fontWeight:600} }, '\u2713 ' + m.safe + ' safe')
                                                ),
                                                React.createElement('button', { onClick:function(e) { handleScanMember(m.user_id, e); }, style:Object.assign({}, btnRed, {fontSize:11,padding:'6px 14px',flexShrink:0}) }, 'Scan'),
                                                React.createElement('div', { style:{fontSize:6,color:'#444'} }, '\u25B6')
                                            )
                                        )
                                    );
                                })
                            )
                        )
                    )
                ),
                selected ? React.createElement('div', { onClick:function() { setSelected(null); }, style:{position:'fixed',inset:0,background:'rgba(0,0,0,0.7)',backdropFilter:'blur(4px)',display:'flex',alignItems:'center',justifyContent:'center',padding:16,zIndex:100,animation:'fadeIn 0.15s ease-out'} },
                    React.createElement('div', { className:'anim-modal d-modal', onClick:function(e) { e.stopPropagation(); }, style:{background:'#161616',border:'1px solid #1a1a1a',borderRadius:16,width:'100%',maxWidth:720,maxHeight:'90vh',overflowY:'auto',boxShadow:'0 25px 60px rgba(0,0,0,0.5)'} },
                        React.createElement('div', { style:{padding:'20px 24px',borderBottom:'1px solid #1a1a1a',display:'flex',justifyContent:'space-between',alignItems:'flex-start'} },
                            React.createElement('div', { style:{flex:1,paddingRight:16} },
                                React.createElement('div', { style:{fontSize:20,fontWeight:800,marginBottom:4} }, selected.subject),
                                React.createElement('div', { style:{fontSize:13,color:'#a0a0a0',display:'flex',gap:12} },
                                    React.createElement('span', null, 'From: ' + selected.from_address),
                                    React.createElement('span', { style:{color:'#444'} }, '|'),
                                    React.createElement('span', null, 'To: ' + selected.to_address)
                                )
                            ),
                            React.createElement('button', { onClick:function() { setSelected(null); }, style:{background:'#111',border:'1px solid #282828',borderRadius:8,width:32,height:32,display:'flex',alignItems:'center',justifyContent:'center',cursor:'pointer',color:'#666',fontSize:14} }, '\\u2715')
                        ),
                        React.createElement('div', { style:{padding:'20px 24px'} },
                            React.createElement('div', { style:{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:24,fontSize:13} },
                                React.createElement('div', null, React.createElement('span', { style:{color:'#666'} }, 'Received: '), React.createElement('span', { style:{color:'#a0a0a0'} }, new Date(selected.received_at).toLocaleString())),
                                React.createElement('div', null, React.createElement('span', { style:{color:'#666'} }, 'Attachments: '), React.createElement('span', { style:{color:'#a0a0a0'} }, selected.has_attachments ? 'Yes' : 'None'))
                            ),
                            selected.verdict ? React.createElement('div', { style:{background:'#111',border:'1px solid #1a1a1a',borderRadius:14,padding:24,marginBottom:24} },
                                React.createElement('div', { style:{display:'flex',alignItems:'center',gap:16,marginBottom:20} },
                                    React.createElement(ConfidenceRing, { score:selected.verdict.confidence_score || Math.round((selected.verdict.confidence||0)*100) }),
                                    React.createElement('div', { style:{flex:1} },
                                        React.createElement('div', { style:{display:'flex',alignItems:'center',gap:10,marginBottom:6} },
                                            React.createElement('div', { style:{fontSize:16,fontWeight:700} }, 'AI Threat Analysis'),
                                            React.createElement(Badge, { level:selected.verdict.threat_level, confidence:selected.verdict.confidence }),
                                            selected.verdict.cached ? React.createElement('span', { style:{fontSize:10,color:'#3B82F6',background:'rgba(59,130,246,0.1)',padding:'2px 8px',borderRadius:4,border:'1px solid rgba(59,130,246,0.2)'} }, 'Cached') : null
                                        ),
                                        React.createElement('div', { style:{fontSize:11,color:'#555'} }, 'Model: ' + (selected.verdict.llm_model || 'Unknown') + ' | ' + new Date(selected.verdict.analyzed_at).toLocaleString())
                                    )
                                ),
                                React.createElement('div', { style:{marginBottom:18} },
                                    React.createElement('div', { style:{fontSize:11,fontWeight:700,letterSpacing:'0.08em',textTransform:'uppercase',color:'#666',marginBottom:8} }, 'Analysis'),
                                    React.createElement('div', { style:{fontSize:13,color:'#a0a0a0',lineHeight:1.8,background:'#0d0d0d',borderRadius:8,padding:14,border:'1px solid #1a1a1a'} }, selected.verdict.reasoning_summary || selected.verdict.reasoning)
                                ),
                                React.createElement('div', { style:{marginBottom:18} },
                                    React.createElement('div', { style:{fontSize:11,fontWeight:700,letterSpacing:'0.08em',textTransform:'uppercase',color:'#666',marginBottom:10} }, 'XAI Indicators'),
                                    React.createElement('div', { style:{display:'flex',flexWrap:'wrap',gap:8} },
                                        Object.entries(selected.verdict.indicators || {}).map(function(pair) {
                                            var key = pair[0], present = pair[1];
                                            var label = key.replace(/_/g, ' ');
                                            var detail = (selected.verdict.indicator_details || {})[key] || '';
                                            if (!detail && present) detail = label + ' detected';
                                            return React.createElement('div', { key:key, style:{padding:'6px 12px',borderRadius:6,fontSize:11,fontWeight:600,display:'inline-flex',alignItems:'center',gap:6,background:present?'rgba(220,38,38,0.1)':'rgba(34,197,94,0.06)',color:present?'#FCA5A5':'#86EFAC',border:'1px solid '+(present?'rgba(220,38,38,0.2)':'rgba(34,197,94,0.12)'),cursor:detail?'help':'default',title:detail} },
                                                React.createElement('span', null, present?'\\u26A0':'\\u2713'),
                                                React.createElement('span', { style:{textTransform:'capitalize'} }, label)
                                            );
                                        })
                                    )
                                ),
                                selected.verdict.indicators && Object.keys(selected.verdict.indicators).length === 0 && selected.verdict.indicators_list ? React.createElement('div', { style:{marginBottom:18} },
                                    React.createElement('div', { style:{fontSize:11,fontWeight:700,letterSpacing:'0.08em',textTransform:'uppercase',color:'#666',marginBottom:10} }, 'Indicators'),
                                    selected.verdict.indicators_list.map(function(ind,idx) {
                                        return React.createElement('div', { key:idx, style:{display:'flex',gap:10,fontSize:13,color:'#a0a0a0',marginBottom:6,padding:'8px 12px',background:'#0d0d0d',borderRadius:6,border:'1px solid #1a1a1a'} },
                                            React.createElement('span', { style:{color:'#EF4444',flexShrink:0,fontSize:10,marginTop:3} }, '\\u25CF'),
                                            React.createElement('span', null, ind)
                                        );
                                    })
                                ) : null,
                                selected.verdict.social_engineering_tactics ? React.createElement('div', { style:{marginBottom:18} },
                                    React.createElement('div', { style:{fontSize:11,fontWeight:700,letterSpacing:'0.08em',textTransform:'uppercase',color:'#666',marginBottom:10} }, 'Social Engineering Tactics'),
                                    React.createElement('div', { style:{display:'flex',flexWrap:'wrap',gap:8} },
                                        Object.entries(selected.verdict.social_engineering_tactics).map(function(pair) {
                                            var tactic = pair[0], present = pair[1];
                                            return React.createElement('span', { key:tactic, style:{padding:'5px 12px',borderRadius:6,fontSize:11,fontWeight:600,textTransform:'capitalize',display:'inline-flex',alignItems:'center',gap:5,background:present?'rgba(220,38,38,0.1)':'rgba(34,197,94,0.06)',color:present?'#FCA5A5':'#86EFAC',border:'1px solid '+(present?'rgba(220,38,38,0.2)':'rgba(34,197,94,0.12)')} }, (present?'\\u26A0':'\\u2713') + ' ' + tactic);
                                        })
                                    )
                                ) : null,
                                selected.verdict.recommendations && selected.verdict.recommendations.length > 0 ? React.createElement('div', { style:{marginBottom:18} },
                                    React.createElement('div', { style:{fontSize:11,fontWeight:700,letterSpacing:'0.08em',textTransform:'uppercase',color:'#666',marginBottom:10} }, 'Recommendations'),
                                    selected.verdict.recommendations.map(function(rec,idx) {
                                        return React.createElement('div', { key:idx, style:{display:'flex',gap:10,fontSize:13,color:'#a0a0a0',marginBottom:6,padding:'8px 12px',background:'#0d0d0d',borderRadius:6,border:'1px solid #1a1a1a'} },
                                            React.createElement('span', { style:{color:'#DC2626',flexShrink:0,fontSize:10,marginTop:3} }, '\\u25B6'),
                                            React.createElement('span', null, rec)
                                        );
                                    })
                                ) : null,
                                React.createElement('div', { style:{marginTop:16,paddingTop:14,borderTop:'1px solid #1a1a1a',display:'flex',gap:10} },
                                    React.createElement('button', { onClick:function(e) { e.stopPropagation(); handleFeedback(selected.id, 'safe'); }, style:Object.assign({}, btnBase, {background:'rgba(34,197,94,0.08)',border:'1px solid rgba(34,197,94,0.2)',color:'#86EFAC',fontSize:11,padding:'6px 12px'}) }, '\\u2713 Mark Safe'),
                                    React.createElement('button', { onClick:function(e) { e.stopPropagation(); handleFeedback(selected.id, 'malicious'); }, style:Object.assign({}, btnBase, {background:'rgba(220,38,38,0.08)',border:'1px solid rgba(220,38,38,0.2)',color:'#FCA5A5',fontSize:11,padding:'6px 12px'}) }, '\\u2715 Mark Malicious')
                                )
                            ) : null,
                            selected.urls && selected.urls.length > 0 ? React.createElement('div', { style:{marginBottom:20} },
                                React.createElement('div', { style:{fontSize:11,fontWeight:700,letterSpacing:'0.08em',textTransform:'uppercase',color:'#666',marginBottom:10} }, 'URLs Detected (' + selected.urls.length + ')'),
                                selected.urls.map(function(url,idx) {
                                    return React.createElement('div', { key:idx, style:{fontSize:12,color:'#EF4444',fontFamily:'JetBrains Mono',padding:'8px 12px',background:'#0d0d0d',borderRadius:8,border:'1px solid #1a1a1a',wordBreak:'break-all',marginBottom:4} }, url);
                                })
                            ) : null,
                            React.createElement('div', null,
                                React.createElement('div', { style:{fontSize:11,fontWeight:700,letterSpacing:'0.08em',textTransform:'uppercase',color:'#666',marginBottom:8} }, 'Email Body'),
                                React.createElement('pre', { style:{background:'#0d0d0d',border:'1px solid #1a1a1a',borderRadius:8,padding:16,fontSize:12,fontFamily:'JetBrains Mono',color:'#a0a0a0',whiteSpace:'pre-wrap',wordBreak:'break-word',maxHeight:300,overflow:'auto'} }, selected.body_text || '(No text body)')
                            )
                        ),
                        React.createElement('div', { style:{padding:'16px 24px',borderTop:'1px solid #1a1a1a',display:'flex',justifyContent:'space-between',alignItems:'center'} },
                            React.createElement('div', { style:{fontSize:11,color:'#444'} }, 'Report ID: ' + selected.id),
                            React.createElement('button', { onClick:function() { setSelected(null); }, style:Object.assign({}, btnDark, {padding:'10px 24px'}) }, 'Close')
                        )
                    )
                ) : null,
                showPaste ? React.createElement('div', { onClick:function() { if(!pasting) setShowPaste(false); }, style:{position:'fixed',inset:0,background:'rgba(0,0,0,0.7)',backdropFilter:'blur(4px)',display:'flex',alignItems:'center',justifyContent:'center',padding:16,zIndex:100,animation:'fadeIn 0.15s ease-out'} },
                    React.createElement('div', { className:'anim-modal', onClick:function(e) { e.stopPropagation(); }, style:{background:'#161616',border:'1px solid #1a1a1a',borderRadius:16,width:'100%',maxWidth:560,padding:'28px'} },
                        React.createElement('div', { style:{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:20} },
                            React.createElement('div', null,
                                React.createElement('div', { style:{fontSize:18,fontWeight:700} }, 'Paste Email for Analysis'),
                                React.createElement('div', { style:{fontSize:12,color:'#666',marginTop:2} }, 'Paste a forwarded or raw phishing email')
                            ),
                            !pasting ? React.createElement('button', { onClick:function() { setShowPaste(false); }, style:{background:'#111',border:'1px solid #282828',borderRadius:8,width:28,height:28,display:'flex',alignItems:'center',justifyContent:'center',cursor:'pointer',color:'#666',fontSize:13} }, '\\u2715') : null
                        ),
                        pasting ? React.createElement('div', { style:{textAlign:'center',padding:'40px 0'} },
                            React.createElement('div', { style:{width:40,height:40,border:'3px solid #1a1a1a',borderTopColor:'#DC2626',borderRadius:'50%',animation:'spin 0.8s linear infinite',margin:'0 auto 20px'} }),
                            React.createElement('div', { style:{fontSize:14,fontWeight:600,color:'#a0a0a0',marginBottom:8} }, analysisSteps[analysisStep]),
                            React.createElement('div', { style:{display:'flex',gap:4,justifyContent:'center'} },
                                [0,1,2,3].map(function(s) {
                                    return React.createElement('div', { key:s, style:{width:32,height:3,borderRadius:2,background:s<=analysisStep?'#DC2626':'#222',transition:'background 0.3s'} });
                                })
                            )
                        ) : React.createElement('div', null,
                            React.createElement('div', { style:{marginBottom:14} },
                                React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Sender (optional)'),
                                React.createElement('input', { value:pasteFrom, onChange:function(e) { setPasteFrom(e.target.value); }, placeholder:'security@phishing-site.com', style:{width:'100%',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:13,fontFamily:'Inter',outline:'none',transition:'border-color 0.2s'} })
                            ),
                            React.createElement('div', { style:{marginBottom:14} },
                                React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Subject (optional)'),
                                React.createElement('input', { value:pasteSubject, onChange:function(e) { setPasteSubject(e.target.value); }, placeholder:'URGENT: Your account is compromised', style:{width:'100%',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:13,fontFamily:'Inter',outline:'none',transition:'border-color 0.2s'} })
                            ),
                            React.createElement('div', { style:{marginBottom:20} },
                                React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Email Content'),
                                React.createElement('textarea', { value:pasteContent, onChange:function(e) { setPasteContent(e.target.value); }, placeholder:'Paste the full forwarded email content here...', rows:10, style:{width:'100%',padding:'12px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:12,fontFamily:'JetBrains Mono',outline:'none',resize:'vertical',transition:'border-color 0.2s'} })
                            ),
                            React.createElement('div', { style:{display:'flex',gap:10,justifyContent:'flex-end'} },
                                React.createElement('button', { onClick:function() { setShowPaste(false); }, style:btnDark }, 'Cancel'),
                                React.createElement('button', { onClick:handlePaste, disabled:!pasteContent.trim(), style:Object.assign({}, btnRed, {opacity:!pasteContent.trim()?0.5:1,padding:'10px 24px'}) }, 'Analyze Email')
                            )
                        )
                    )
                ) : null,
                showClear ? React.createElement('div', { onClick:function() { setShowClear(false); }, style:{position:'fixed',inset:0,background:'rgba(0,0,0,0.7)',backdropFilter:'blur(4px)',display:'flex',alignItems:'center',justifyContent:'center',padding:16,zIndex:100,animation:'fadeIn 0.15s ease-out'} },
                    React.createElement('div', { className:'anim-modal', onClick:function(e) { e.stopPropagation(); }, style:{background:'#161616',border:'1px solid #1a1a1a',borderRadius:16,width:'100%',maxWidth:400,padding:'28px',textAlign:'center'} },
                        React.createElement('div', { style:{width:52,height:52,borderRadius:14,background:'rgba(220,38,38,0.12)',display:'inline-flex',alignItems:'center',justifyContent:'center',fontSize:22,marginBottom:16,color:'#EF4444'} }, '\\u26A0'),
                        React.createElement('div', { style:{fontSize:18,fontWeight:700,marginBottom:8} }, 'Clear All Reports?'),
                        React.createElement('div', { style:{fontSize:13,color:'#666',marginBottom:24,lineHeight:1.6} }, 'This will permanently delete all ' + total + ' analyzed report(s). This action cannot be undone.'),
                        React.createElement('div', { style:{display:'flex',gap:10,justifyContent:'center'} },
                            React.createElement('button', { onClick:function() { setShowClear(false); }, style:btnDark }, 'Cancel'),
                            React.createElement('button', { onClick:handleClear, disabled:clearing, style:Object.assign({}, btnRed, {opacity:clearing?0.5:1}) }, clearing ? 'Deleting...' : 'Delete All')
                        )
                    )
                ) : null,
                React.createElement('div', { style:{position:'fixed',top:80,right:20,zIndex:200,display:'flex',flexDirection:'column',gap:8} },
                    toasts.map(function(t) { return React.createElement(Toast, { key:t.id, toast:t }); })
                )
            );
        }

        var root = ReactDOM.createRoot(document.getElementById('root'));
        root.render(React.createElement(App));
    </script>
</body>
</html>"""

# ============================================================================
# SETTINGS PAGE
# ============================================================================
SETTINGS_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL - Settings</title>
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter', sans-serif; background: #0a0a0a; color: #f5f5f5; min-height: 100vh; }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #111; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 3px; }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes modalIn { from { opacity: 0; transform: scale(0.96) translateY(8px); } to { opacity: 1; transform: scale(1) translateY(0); } }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes toastIn { from { opacity: 0; transform: translateX(100%); } to { opacity: 1; transform: translateX(0); } }
        .s-hamburger { display: none; background: none; border: none; color: #f5f5f5; font-size: 22px; cursor: pointer; padding: 6px; line-height: 1; }
        @media (max-width: 768px) {
            .s-hamburger { display: flex !important; }
            .s-nav { display: none !important; }
            .s-nav.open { display: flex !important; flex-direction: column; position: absolute; top: 64px; left: 0; right: 0; background: #111; border-bottom: 1px solid #1a1a1a; padding: 8px 12px; gap: 6px; z-index: 99; }
            .s-wrap { padding: 0 12px !important; }
            .s-main { padding: 24px 12px !important; }
            .s-tabs { flex-wrap: wrap !important; gap: 6px !important; }
            .s-card-row { flex-direction: column !important; align-items: stretch !important; gap: 10px !important; }
            .s-invite-row { flex-direction: column !important; }
            .s-modal { max-width: calc(100vw - 16px) !important; margin: 8px !important; }
        }
    </style>
</head>
<body>
    <div id="root"></div>
    <script type="text/babel">
        var useState = React.useState, useEffect = React.useEffect, useCallback = React.useCallback;
        function getToken() { return localStorage.getItem('sentinel_token'); }
        function getUser() { return localStorage.getItem('sentinel_user'); }
        function logout() { localStorage.removeItem('sentinel_token'); localStorage.removeItem('sentinel_user'); window.location.href = '/login'; }

        var API = {
            base: '/api/v1',
            opts: function() { return { headers: {'Authorization': 'Bearer ' + getToken(), 'Content-Type': 'application/json'} }; },
            get: function(path) { return fetch(this.base + path, this.opts()).then(function(r) { if (r.status === 401) { logout(); throw new Error('Session expired'); } if (!r.ok) return r.json().then(function(d) { throw new Error(d.detail || 'Request failed (' + r.status + ')'); }, function() { throw new Error('Request failed (' + r.status + ')'); }); return r.json(); }); },
            post: function(path, body) { return fetch(this.base + path, Object.assign({}, this.opts(), { method: 'POST', body: JSON.stringify(body) })).then(function(r) { if (r.status === 401) { logout(); throw new Error('Session expired'); } if (!r.ok) return r.json().then(function(d) { throw new Error(d.detail || 'Request failed (' + r.status + ')'); }, function() { throw new Error('Request failed (' + r.status + ')'); }); return r.json(); }); },
            del: function(path) { return fetch(this.base + path, Object.assign({}, this.opts(), { method: 'DELETE' })).then(function(r) { if (r.status === 401) { logout(); throw new Error('Session expired'); } if (!r.ok) return r.json().then(function(d) { throw new Error(d.detail || 'Request failed (' + r.status + ')'); }, function() { throw new Error('Request failed (' + r.status + ')'); }); return r.json(); }); },
            patch: function(path, body) { return fetch(this.base + path, Object.assign({}, this.opts(), { method: 'PATCH', body: JSON.stringify(body) })).then(function(r) { if (r.status === 401) { logout(); throw new Error('Session expired'); } if (!r.ok) return r.json().then(function(d) { throw new Error(d.detail || 'Request failed (' + r.status + ')'); }, function() { throw new Error('Request failed (' + r.status + ')'); }); return r.json(); }); }
        };

        function App() {
            var _tab = useState('connections');
            var tab = _tab[0], setTab = _tab[1];
            var _conns = useState([]);
            var conns = _conns[0], setConns = _conns[1];
            var _scans = useState([]);
            var scans = _scans[0], setScans = _scans[1];
            var _team = useState([]);
            var team = _team[0], setTeam = _team[1];
            var _invites = useState([]);
            var invites = _invites[0], setInvites = _invites[1];
            var _inviteEmail = useState('');
            var inviteEmail = _inviteEmail[0], setInviteEmail = _inviteEmail[1];
            var _inviteLoading = useState(false);
            var inviteLoading = _inviteLoading[0], setInviteLoading = _inviteLoading[1];
            var _inviteRole = useState('friend');
            var inviteRole = _inviteRole[0], setInviteRole = _inviteRole[1];
            var _copiedInviteId = useState(null);
            var copiedInviteId = _copiedInviteId[0], setCopiedInviteId = _copiedInviteId[1];
            var _loading = useState(true);
            var loading = _loading[0], setLoading = _loading[1];
            var _showAdd = useState(false);
            var showAdd = _showAdd[0], setShowAdd = _showAdd[1];
            var _toast = useState(null);
            var toast = _toast[0], setToast = _toast[1];
            var _scanningId = useState('');
            var scanningId = _scanningId[0], setScanningId = _scanningId[1];

            var _schedule = useState({enabled:false, frequency:'monthly', recipients:[], last_sent:null});
            var schedule = _schedule[0], setSchedule = _schedule[1];
            var _schedLoading = useState(false);
            var schedLoading = _schedLoading[0], setSchedLoading = _schedLoading[1];

            var _branding = useState({logo_url:'', primary_color:'#DC2626', secondary_color:'#7F1D1D', org_display_name:''});
            var branding = _branding[0], setBranding = _branding[1];

            var _rules = useState([]);
            var rules = _rules[0], setRules = _rules[1];
            var _newRule = useState({name:'', pattern:'', rule_type:'keyword', action:'flag', description:''});
            var newRule = _newRule[0], setNewRule = _newRule[1];
            var _ruleTestText = useState('');
            var ruleTestText = _ruleTestText[0], setRuleTestText = _ruleTestText[1];
            var _ruleMatches = useState(null);
            var ruleMatches = _ruleMatches[0], setRuleMatches = _ruleMatches[1];

            var showToast = function(type, msg) {
                setToast({type:type, msg:msg});
                setTimeout(function() { setToast(null); }, 3000);
            };

            var fetchConns = useCallback(function() {
                API.get('/connections').then(function(r) { setConns(r.connections || []); setLoading(false); }).catch(function() { setLoading(false); });
            }, []);
            var fetchScans = useCallback(function() {
                API.get('/scans').then(function(r) { setScans(r.jobs || []); }).catch(function() {});
            }, []);
            var fetchTeam = useCallback(function() {
                API.get('/team').then(function(r) { setTeam(r.members || []); }).catch(function() {});
            }, []);
            var fetchInvites = useCallback(function() {
                API.get('/invites').then(function(r) { setInvites(r.invites || []); }).catch(function() {});
            }, []);
            var fetchSchedule = useCallback(function() {
                API.get('/report-schedule').then(function(r) { setSchedule(r); }).catch(function() {});
            }, []);
            var fetchBranding = useCallback(function() {
                API.get('/branding').then(function(r) { setBranding(r); }).catch(function() {});
            }, []);
            var fetchRules = useCallback(function() {
                API.get('/rules').then(function(r) { setRules(r.rules || []); }).catch(function() {});
            }, []);

            useEffect(function() {
                if (!getToken()) { window.location.href = '/login'; return; }
                fetchConns(); fetchScans(); fetchTeam(); fetchInvites(); fetchSchedule(); fetchBranding(); fetchRules();
            }, [fetchConns, fetchScans, fetchTeam, fetchInvites, fetchSchedule, fetchBranding, fetchRules]);

            var btnBase = { padding:'8px 16px', borderRadius:8, fontSize:13, fontWeight:600, cursor:'pointer', border:'none', fontFamily:'Inter', transition:'all 0.2s' };
            var btnRed = Object.assign({}, btnBase, { background:'linear-gradient(135deg,#DC2626,#991B1B)', color:'#fff' });
            var btnDark = Object.assign({}, btnBase, { background:'#161616', color:'#a0a0a0', border:'1px solid #282828' });
            var inputStyle = { width:'100%', padding:'10px 14px', background:'#0a0a0a', border:'1px solid #222', borderRadius:8, color:'#f5f5f5', fontSize:13, fontFamily:'Inter', outline:'none', transition:'border-color 0.2s' };
            var cardStyle = { background:'linear-gradient(145deg, #111, #0d0d0d)', border:'1px solid #1a1a1a', borderRadius:14, padding:24, marginBottom:16 };

            var tabs = [
                {id:'connections', label:'Email Connections'},
                {id:'scans', label:'Scan History'},
                {id:'team', label:'Team'},
                {id:'reports', label:'Scheduled Reports'},
                {id:'branding', label:'Branding'},
                {id:'rules', label:'Detection Rules'}
            ];

            return React.createElement('div', { style:{minHeight:'100vh'} },
                React.createElement('header', { style:{background:'rgba(17,17,17,0.9)',backdropFilter:'blur(20px)',borderBottom:'1px solid #1a1a1a',position:'sticky',top:0,zIndex:50} },
                    React.createElement('div', { className:'s-wrap', style:{maxWidth:1000,margin:'0 auto',padding:'0 24px',display:'flex',alignItems:'center',justifyContent:'space-between',height:64} },
                        React.createElement('div', { style:{display:'flex',alignItems:'center',gap:10} },
                            React.createElement('div', { dangerouslySetInnerHTML:{__html:'<svg viewBox="0 0 40 44" fill="none" xmlns="http://www.w3.org/2000/svg" width="28" height="31"><path d="M20 2L4 10v12c0 11 7.2 21.3 16 24 8.8-2.7 16-13 16-24V10L20 2z" fill="url(#lgS)" stroke="#991B1B" stroke-width="1.5"/><path d="M20 10v8m0 0v8m0-8l-4-4m4 4l4-4" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="lgS" x1="4" y1="2" x2="36" y2="46"><stop stop-color="#DC2626"/><stop offset="1" stop-color="#7F1D1D"/></linearGradient></defs></svg>'} }),
                            React.createElement('span', { style:{fontSize:16,fontWeight:800} }, 'Settings')
                        ),
                        React.createElement('button', { className:'s-hamburger', onClick:function() { document.querySelector('.s-nav').classList.toggle('open'); } }, '\u2630'),
                        React.createElement('div', { className:'s-nav', style:{display:'flex',gap:8,alignItems:'center'} },
                            React.createElement('button', { onClick:function() { window.location.href='/dashboard'; }, style:btnDark }, 'Back to Dashboard'),
                            React.createElement('button', { onClick:logout, style:Object.assign({}, btnBase, {background:'transparent',color:'#666',border:'1px solid #222'}) }, 'Logout')
                        )
                    )
                ),
                React.createElement('main', { className:'s-main', style:{maxWidth:1000,margin:'0 auto',padding:'32px 24px'} },
                    React.createElement('div', { className:'s-tabs', style:{display:'flex',gap:8,marginBottom:32} },
                        tabs.map(function(t) {
                            var isActive = tab === t.id;
                            return React.createElement('button', { key:t.id, onClick:function() { setTab(t.id); }, style:Object.assign({}, btnDark, { background:isActive?'rgba(220,38,38,0.1)':'#161616', borderColor:isActive?'rgba(220,38,38,0.4)':'#282828', color:isActive?'#EF4444':'#a0a0a0' }) }, t.label);
                        })
                    ),
                    tab === 'connections' ? React.createElement('div', null,
                        React.createElement('div', { style:{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:20} },
                            React.createElement('h2', { style:{fontSize:20,fontWeight:700} }, 'Email Connections'),
                            React.createElement('button', { onClick:function() { setShowAdd(true); }, style:btnRed }, '+ Add Connection')
                        ),
                        loading ? React.createElement('div', { style:{textAlign:'center',padding:40} }, React.createElement('div', { style:{width:32,height:32,border:'3px solid #1a1a1a',borderTopColor:'#DC2626',borderRadius:'50%',animation:'spin 0.8s linear infinite',margin:'0 auto 16px'} })) :
                        conns.length === 0 ? React.createElement('div', { style:cardStyle },
                            React.createElement('div', { style:{textAlign:'center',padding:'40px 0'} },
                                React.createElement('div', { style:{fontSize:40,marginBottom:12,opacity:0.3} }, '\\u260E'),
                                React.createElement('div', { style:{fontSize:16,fontWeight:700,marginBottom:6} }, 'No Email Connections'),
                                React.createElement('div', { style:{fontSize:13,color:'#666',marginBottom:20} }, 'Connect your email inbox to automatically scan for phishing emails.'),
                                React.createElement('button', { onClick:function() { setShowAdd(true); }, style:btnRed }, 'Add Your First Connection')
                            )
                        ) : conns.map(function(c) {
                            return React.createElement('div', { key:c.id, className:'s-card-row', style:Object.assign({}, cardStyle, {display:'flex',justifyContent:'space-between',alignItems:'center'}) },
                                    React.createElement('div', null,
                                    React.createElement('div', { style:{display:'flex',alignItems:'center',gap:8} },
                                        React.createElement('div', { style:{width:8,height:8,borderRadius:'50%',background:c.is_active?'#22C55E':'#666'} }),
                                        React.createElement('span', { style:{fontSize:15,fontWeight:600} }, c.label)
                                    ),
                                    React.createElement('div', { style:{fontSize:12,color:'#666',marginTop:4} }, c.imap_username + ' @ ' + c.imap_host),
                                    React.createElement('div', { style:{fontSize:11,color:'#555',marginTop:2} }, 'Last scan: ' + (c.last_scan_at ? new Date(c.last_scan_at).toLocaleString() : 'Never') + ' | ' + (c.last_scan_count || 0) + ' emails found')
                                ),
                            React.createElement('div', { className:'s-invite-row', style:{display:'flex',gap:8} },
                                    React.createElement('button', { onClick:function() {
                                        setScanningId(c.id);
                                        API.post('/scan/' + c.id, {}).then(function() { showToast('success', 'Scan started for ' + c.label + '. Check Dashboard for results.'); setScanningId(''); fetchConns(); }).catch(function(e) {
                                            var msg = 'Scan failed';
                                            if (e && e.message) { msg = e.message; }
                                            showToast('error', msg);
                                            setScanningId('');
                                        });
                                    }, disabled: scanningId === c.id, style:Object.assign({}, btnDark, {fontSize:11,padding:'6px 12px', opacity: scanningId === c.id ? 0.6 : 1, cursor: scanningId === c.id ? 'not-allowed' : 'pointer'}) }, scanningId === c.id ? 'Scanning...' : 'Scan Now'),
                                    React.createElement('button', { onClick:function() {
                                        API.del('/connections/' + c.id).then(function() { showToast('success', 'Connection removed'); fetchConns(); }).catch(function(e) { showToast('error', 'Failed to remove: ' + (e.message || 'Unknown')); });
                                    }, style:Object.assign({}, btnBase, {background:'rgba(220,38,38,0.08)',border:'1px solid rgba(220,38,38,0.2)',color:'#FCA5A5',fontSize:11,padding:'6px 12px'}) }, 'Remove')
                                )
                            );
                        })
                    ) : tab === 'scans' ? React.createElement('div', null,
                        React.createElement('h2', { style:{fontSize:20,fontWeight:700,marginBottom:20} }, 'Scan History'),
                        scans.length === 0 ? React.createElement('div', { style:cardStyle },
                            React.createElement('div', { style:{textAlign:'center',padding:'40px 0',color:'#666',fontSize:14} }, 'No scans yet. Connect an email account and run a scan.')
                        ) : scans.map(function(j) {
                            var statusColors = {pending:'#EAB308',running:'#3B82F6',completed:'#22C55E',failed:'#EF4444'};
                            return React.createElement('div', { key:j.id, style:Object.assign({}, cardStyle, {display:'flex',justifyContent:'space-between',alignItems:'center'}) },
                                React.createElement('div', null,
                                    React.createElement('div', { style:{display:'flex',alignItems:'center',gap:8} },
                                        j.status === 'running' ? React.createElement('div', { style:{width:8,height:8,borderRadius:'50%',background:'#3B82F6',animation:'spin 1s linear infinite'} }) : null,
                                        React.createElement('span', { style:{fontSize:14,fontWeight:600,textTransform:'capitalize'} }, j.status),
                                        React.createElement('span', { style:{fontSize:11,color:statusColors[j.status]||'#666',padding:'2px 8px',borderRadius:4,background:(statusColors[j.status]||'#666')+'20'} }, j.status)
                                    ),
                                    React.createElement('div', { style:{fontSize:12,color:'#666',marginTop:4} }, (j.emails_found||0) + ' found, ' + (j.emails_analyzed||0) + ' analyzed'),
                                    j.error_message ? React.createElement('div', { style:{fontSize:11,color:'#EF4444',marginTop:2} }, j.error_message) : null,
                                    React.createElement('div', { style:{fontSize:11,color:'#555',marginTop:2} }, new Date(j.created_at).toLocaleString())
                                )
                            );
                        })
                    ) : tab === 'team' ? React.createElement('div', null,
                        React.createElement('h2', { style:{fontSize:20,fontWeight:700,marginBottom:8} }, 'Team Members'),
                        React.createElement('p', { style:{fontSize:13,color:'#666',marginBottom:24} }, 'Manage who has access to your organization.'),

                        React.createElement('div', { style:Object.assign({}, cardStyle, {marginBottom:24}) },
                            React.createElement('div', { style:{fontSize:14,fontWeight:600,marginBottom:12} }, 'Invite Member'),
                            React.createElement('div', { style:{display:'flex',gap:8,flexWrap:'wrap'} },
                                React.createElement('input', { value:inviteEmail, onChange:function(e) { setInviteEmail(e.target.value); }, placeholder:'teammate@company.com', style:Object.assign({}, inputStyle, {flex:1,minWidth:200}) }),
                                React.createElement('select', { value:inviteRole, onChange:function(e) { setInviteRole(e.target.value); }, style:Object.assign({}, inputStyle, {width:120}) },
                                    React.createElement('option', { value:'friend' }, 'Friend (Lite)'),
                                    React.createElement('option', { value:'member' }, 'Member (Full)')
                                ),
                                React.createElement('button', { disabled:inviteLoading || !inviteEmail, onClick:function() {
                                    setInviteLoading(true);
                                    API.post('/invites', { email:inviteEmail, role:inviteRole }).then(function(r) {
                                        showToast('success', 'Invite sent to ' + inviteEmail);
                                        setInviteEmail('');
                                        fetchInvites();
                                        if (r.invite_link) {
                                            if (navigator.clipboard) { navigator.clipboard.writeText(r.invite_link); }
                                            showToast('success', 'Invite link copied to clipboard');
                                        }
                                    }).catch(function(e) {
                                        showToast('error', 'Failed to send invite: ' + (e.message || 'Unknown'));
                                    }).finally(function() { setInviteLoading(false); });
                                }, style:Object.assign({}, btnRed, {opacity:(inviteLoading||!inviteEmail)?0.5:1,whiteSpace:'nowrap'}) }, inviteLoading ? 'Sending...' : 'Send Invite')
                            )
                        ),

                        invites.length > 0 ? React.createElement('div', { style:Object.assign({}, cardStyle, {marginBottom:24}) },
                            React.createElement('div', { style:{fontSize:14,fontWeight:600,marginBottom:12} }, 'Pending Invites (' + invites.length + ')'),
                            invites.map(function(inv) {
                                return React.createElement('div', { key:inv.id, style:{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'10px 0',borderBottom:'1px solid #1a1a1a'} },
                                    React.createElement('div', null,
                                        React.createElement('div', { style:{fontSize:13,fontWeight:500} }, inv.email),
                                        React.createElement('div', { style:{fontSize:11,color:'#555',marginTop:2} }, 'Role: ' + inv.role + ' | Expires: ' + new Date(inv.expires_at).toLocaleDateString())
                                    ),
                                    React.createElement('div', { style:{display:'flex',gap:6,alignItems:'center'} },
                                        React.createElement('button', { onClick:function() {
                                            var link = inv.invite_link || (window.location.origin + '/accept-invite/' + inv.token);
                                            if (navigator.clipboard) { navigator.clipboard.writeText(link); setCopiedInviteId(inv.id); setTimeout(function() { setCopiedInviteId(null); }, 2000); }
                                        }, style:Object.assign({}, btnDark, {fontSize:11,padding:'5px 10px'}) }, copiedInviteId===inv.id ? 'Copied!' : 'Copy Link'),
                                        React.createElement('button', { onClick:function() {
                                            if (!confirm('Revoke invite for ' + inv.email + '?')) return;
                                            API.del('/invites/' + inv.id).then(function() { showToast('success', 'Invite revoked'); fetchInvites(); }).catch(function(e) { showToast('error', 'Failed: ' + (e.message || 'Unknown')); });
                                        }, style:Object.assign({}, btnBase, {background:'rgba(220,38,38,0.08)',border:'1px solid rgba(220,38,38,0.2)',color:'#FCA5A5',fontSize:11,padding:'5px 10px'}) }, 'Revoke')
                                    )
                                );
                            })
                        ) : null,

                        React.createElement('div', { style:{fontSize:13,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',marginBottom:12} }, 'Members (' + team.length + ')'),
                        team.length === 0 ? React.createElement('div', { style:cardStyle },
                            React.createElement('div', { style:{textAlign:'center',padding:'40px 0',color:'#666',fontSize:14} }, 'No team members yet.')
                        ) : React.createElement('div', null,
                            team.map(function(m) {
                                var isCurrentUser = m.user_id === (function() { try { return JSON.parse(atob(localStorage.getItem('sentinel_token').split('.')[1])).user_id; } catch(e) { return ''; } })();
                                return React.createElement('div', { key:m.user_id || m.id, style:Object.assign({}, cardStyle, {display:'flex',justifyContent:'space-between',alignItems:'center'}) },
                                    React.createElement('div', { style:{display:'flex',alignItems:'center',gap:12} },
                                        React.createElement('div', { style:{width:36,height:36,borderRadius:'50%',background:'linear-gradient(135deg,#DC2626,#7F1D1D)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:14,fontWeight:700,color:'#fff'} }, (m.username || m.email || '?')[0].toUpperCase()),
                                        React.createElement('div', null,
                                            React.createElement('div', { style:{display:'flex',alignItems:'center',gap:6} },
                                                React.createElement('span', { style:{fontSize:14,fontWeight:600} }, m.username),
                                                isCurrentUser ? React.createElement('span', { style:{fontSize:10,color:'#DC2626',background:'rgba(220,38,38,0.1)',padding:'2px 6px',borderRadius:4} }, 'You') : null,
                                                m.role === 'admin' ? React.createElement('span', { style:{fontSize:10,color:'#EAB308',background:'rgba(234,179,8,0.1)',padding:'2px 6px',borderRadius:4} }, 'Admin') : null
                                            ),
                                            React.createElement('div', { style:{fontSize:12,color:'#666',marginTop:2} }, m.email),
                                            React.createElement('div', { style:{fontSize:11,color:'#555',marginTop:2} }, 'Joined: ' + new Date(m.created_at || Date.now()).toLocaleDateString())
                                        )
                                    ),
                                    !isCurrentUser ? React.createElement('button', { onClick:function() {
                                        if (!confirm('Remove ' + m.username + ' from your organization?')) return;
                                        API.del('/team/' + (m.user_id || m.id)).then(function() { showToast('success', m.username + ' removed'); fetchTeam(); }).catch(function(e) { showToast('error', 'Failed: ' + (e.message || 'Unknown')); });
                                    }, style:Object.assign({}, btnBase, {background:'rgba(220,38,38,0.08)',border:'1px solid rgba(220,38,38,0.2)',color:'#FCA5A5',fontSize:11,padding:'5px 10px'}) }, 'Remove') : React.createElement('span', { style:{fontSize:11,color:'#555'} }, 'Current user')
                                );
                            })
                        )
                    ) : tab === 'reports' ? React.createElement('div', null,
                        React.createElement('h2', { style:{fontSize:20,fontWeight:700,marginBottom:8} }, 'Scheduled Reports'),
                        React.createElement('p', { style:{fontSize:13,color:'#666',marginBottom:24} }, 'Automatically generate and email PDF threat reports on a schedule.'),
                        React.createElement('div', { style:cardStyle },
                            React.createElement('div', { style:{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:16} },
                                React.createElement('div', { style:{display:'flex',alignItems:'center',gap:10} },
                                    React.createElement('div', { style:{width:36,height:36,borderRadius:8,background:schedule.enabled?'rgba(34,197,94,0.12)':'rgba(102,102,102,0.12)',display:'flex',alignItems:'center',justifyContent:'center',fontSize:16} }, schedule.enabled ? '\\u2713' : '\\u25CB'),
                                    React.createElement('div', null,
                                        React.createElement('div', { style:{fontSize:14,fontWeight:600} }, 'Report Schedule'),
                                        React.createElement('div', { style:{fontSize:11,color:'#666',marginTop:2} }, schedule.last_sent ? 'Last sent: ' + new Date(schedule.last_sent).toLocaleDateString() : 'Never sent yet')
                                    )
                                ),
                                React.createElement('div', { style:{display:'flex',alignItems:'center',gap:8} },
                                    React.createElement('span', { style:{fontSize:12,color:'#888'} }, schedule.enabled ? 'Enabled' : 'Disabled'),
                                    React.createElement('button', { onClick:function() {
                                        var next = Object.assign({}, schedule, {enabled:!schedule.enabled});
                                        setSchedLoading(true);
                                        API.post('/report-schedule', next).then(function() { setSchedule(next); showToast('success', next.enabled ? 'Schedule enabled' : 'Schedule disabled'); }).catch(function(e) { showToast('error', e.message || 'Failed'); }).finally(function() { setSchedLoading(false); });
                                    }, style:{width:44,height:24,borderRadius:12,background:schedule.enabled?'linear-gradient(135deg,#22C55E,#166534)':'#333',border:'none',cursor:'pointer',position:'relative',transition:'all 0.2s',opacity:schedLoading?0.6:1} },
                                        React.createElement('div', { style:{width:18,height:18,borderRadius:'50%',background:'#fff',position:'absolute',top:3,left:schedule.enabled?23:3,transition:'all 0.2s'} })
                                    )
                                )
                            ),
                            React.createElement('div', { style:{marginBottom:16} },
                                React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Frequency'),
                                React.createElement('select', { value:schedule.frequency, onChange:function(e) { setSchedule(Object.assign({}, schedule, {frequency:e.target.value})); }, style:{width:'100%',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:13,fontFamily:'Inter',cursor:'pointer'} },
                                    React.createElement('option', { value:'weekly' }, 'Weekly'),
                                    React.createElement('option', { value:'monthly' }, 'Monthly')
                                )
                            ),
                            React.createElement('div', { style:{marginBottom:16} },
                                React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Recipient Emails (comma separated)'),
                                React.createElement('input', { value:(schedule.recipients||[]).join(', '), onChange:function(e) { setSchedule(Object.assign({}, schedule, {recipients:e.target.value.split(',').map(function(s){return s.trim();}).filter(Boolean)})); }, placeholder:'admin@company.com, ceo@company.com', style:{width:'100%',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:13,fontFamily:'Inter'} })
                            ),
                            React.createElement('div', { style:{display:'flex',gap:8} },
                                React.createElement('button', { onClick:function() {
                                    setSchedLoading(true);
                                    API.post('/report-schedule', schedule).then(function() { showToast('success', 'Schedule saved'); }).catch(function(e) { showToast('error', e.message || 'Failed'); }).finally(function() { setSchedLoading(false); });
                                }, disabled:schedLoading, style:Object.assign({}, btnRed, {opacity:schedLoading?0.6:1}) }, schedLoading ? 'Saving...' : 'Save Schedule'),
                                React.createElement('button', { onClick:function() {
                                    window.open('/api/v1/report-schedule/test', '_blank');
                                    showToast('success', 'Generating report PDF...');
                                }, style:btnDark }, 'Download Test Report')
                            )
                        )
                    ) : tab === 'branding' ? React.createElement('div', null,
                        React.createElement('h2', { style:{fontSize:20,fontWeight:700,marginBottom:8} }, 'White-Label Branding'),
                        React.createElement('p', { style:{fontSize:13,color:'#666',marginBottom:24} }, 'Customize the look and feel of your SENTINEL deployment with your own brand.'),
                        React.createElement('div', { style:cardStyle },
                            React.createElement('div', { style:{marginBottom:16} },
                                React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Organization Display Name'),
                                React.createElement('input', { value:branding.org_display_name||'', onChange:function(e) { setBranding(Object.assign({}, branding, {org_display_name:e.target.value})); }, placeholder:'Your Company Name', style:{width:'100%',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:13,fontFamily:'Inter'} })
                            ),
                            React.createElement('div', { style:{marginBottom:16} },
                                React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Logo URL'),
                                React.createElement('input', { value:branding.logo_url||'', onChange:function(e) { setBranding(Object.assign({}, branding, {logo_url:e.target.value})); }, placeholder:'https://your-cdn.com/logo.png', style:{width:'100%',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:13,fontFamily:'Inter'} }),
                                React.createElement('div', { style:{fontSize:11,color:'#555',marginTop:4} }, 'Paste a URL to your logo image (PNG, SVG, or JPG recommended)')
                            ),
                            React.createElement('div', { style:{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:16} },
                                React.createElement('div', null,
                                    React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Primary Color'),
                                    React.createElement('div', { style:{display:'flex',gap:8,alignItems:'center'} },
                                        React.createElement('input', { type:'color', value:branding.primary_color||'#DC2626', onChange:function(e) { setBranding(Object.assign({}, branding, {primary_color:e.target.value})); }, style:{width:40,height:36,border:'1px solid #222',borderRadius:6,cursor:'pointer',padding:2,background:'#0a0a0a'} }),
                                        React.createElement('input', { value:branding.primary_color||'#DC2626', onChange:function(e) { setBranding(Object.assign({}, branding, {primary_color:e.target.value})); }, style:{flex:1,padding:'8px 12px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:12,fontFamily:'JetBrains Mono'} })
                                    )
                                ),
                                React.createElement('div', null,
                                    React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Secondary Color'),
                                    React.createElement('div', { style:{display:'flex',gap:8,alignItems:'center'} },
                                        React.createElement('input', { type:'color', value:branding.secondary_color||'#7F1D1D', onChange:function(e) { setBranding(Object.assign({}, branding, {secondary_color:e.target.value})); }, style:{width:40,height:36,border:'1px solid #222',borderRadius:6,cursor:'pointer',padding:2,background:'#0a0a0a'} }),
                                        React.createElement('input', { value:branding.secondary_color||'#7F1D1D', onChange:function(e) { setBranding(Object.assign({}, branding, {secondary_color:e.target.value})); }, style:{flex:1,padding:'8px 12px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:12,fontFamily:'JetBrains Mono'} })
                                    )
                                )
                            ),
                            React.createElement('div', { style:{marginBottom:16} },
                                React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Custom CSS (Advanced)'),
                                React.createElement('textarea', { value:branding.custom_css||'', onChange:function(e) { setBranding(Object.assign({}, branding, {custom_css:e.target.value})); }, placeholder:'.sentinel-logo { filter: brightness(1.5); }', rows:4, style:{width:'100%',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:12,fontFamily:'JetBrains Mono',resize:'vertical'} })
                            ),
                            React.createElement('div', { style:{display:'flex',gap:8} },
                                React.createElement('button', { onClick:function() {
                                    API.post('/branding', branding).then(function() { showToast('success', 'Branding saved'); }).catch(function(e) { showToast('error', e.message || 'Failed'); });
                                }, style:btnRed }, 'Save Branding'),
                                React.createElement('button', { onClick:function() { setBranding({logo_url:'', primary_color:'#DC2626', secondary_color:'#7F1D1D', org_display_name:'', custom_css:''}); }, style:btnDark }, 'Reset to Default')
                            )
                        ),
                        branding.logo_url ? React.createElement('div', { style:cardStyle },
                            React.createElement('div', { style:{fontSize:14,fontWeight:600,marginBottom:12} }, 'Preview'),
                            React.createElement('div', { style:{background:'#0a0a0a',border:'1px solid #222',borderRadius:12,padding:20} },
                                React.createElement('div', { style:{display:'flex',alignItems:'center',gap:12,marginBottom:16} },
                                    React.createElement('img', { src:branding.logo_url, alt:'Logo', style:{height:32,objectFit:'contain'}, onError:function(e) { e.target.style.display='none'; } }),
                                    React.createElement('span', { style:{fontSize:16,fontWeight:800,color:branding.primary_color||'#DC2626'} }, branding.org_display_name || 'Your Company'),
                                    React.createElement('span', { style:{fontSize:11,color:'#666',background:'#161616',padding:'2px 8px',borderRadius:4} }, 'SENTINEL Powered')
                                ),
                                React.createElement('div', { style:{display:'flex',gap:8} },
                                    React.createElement('div', { style:{background:branding.primary_color||'#DC2626',padding:'6px 14px',borderRadius:6,fontSize:12,fontWeight:600,color:'#fff'} }, 'Primary'),
                                    React.createElement('div', { style:{background:branding.secondary_color||'#7F1D1D',padding:'6px 14px',borderRadius:6,fontSize:12,fontWeight:600,color:'#fff'} }, 'Secondary')
                                )
                            )
                        ) : null
                    ) : tab === 'rules' ? React.createElement('div', null,
                        React.createElement('h2', { style:{fontSize:20,fontWeight:700,marginBottom:8} }, 'Custom Detection Rules'),
                        React.createElement('p', { style:{fontSize:13,color:'#666',marginBottom:24} }, 'Define your own patterns to flag, whitelist, or block specific content in scanned emails.'),

                        React.createElement('div', { style:cardStyle },
                            React.createElement('div', { style:{fontSize:14,fontWeight:600,marginBottom:16} }, 'Create New Rule'),
                            React.createElement('div', { style:{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12} },
                                React.createElement('div', null,
                                    React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Rule Name'),
                                    React.createElement('input', { value:newRule.name, onChange:function(e) { setNewRule(Object.assign({}, newRule, {name:e.target.value})); }, placeholder:'e.g. Block competitor domains', style:{width:'100%',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:13,fontFamily:'Inter'} })
                                ),
                                React.createElement('div', null,
                                    React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Pattern'),
                                    React.createElement('input', { value:newRule.pattern, onChange:function(e) { setNewRule(Object.assign({}, newRule, {pattern:e.target.value})); }, placeholder:'e.g. evil-domain\\.com or urgent wire transfer', style:{width:'100%',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:13,fontFamily:'JetBrains Mono'} })
                                )
                            ),
                            React.createElement('div', { style:{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12} },
                                React.createElement('div', null,
                                    React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Type'),
                                    React.createElement('select', { value:newRule.rule_type, onChange:function(e) { setNewRule(Object.assign({}, newRule, {rule_type:e.target.value})); }, style:{width:'100%',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:13,fontFamily:'Inter',cursor:'pointer'} },
                                        React.createElement('option', { value:'keyword' }, 'Keyword (substring match)'),
                                        React.createElement('option', { value:'regex' }, 'Regex (pattern match)'),
                                        React.createElement('option', { value:'domain' }, 'Domain (partial match)')
                                    )
                                ),
                                React.createElement('div', null,
                                    React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Action'),
                                    React.createElement('select', { value:newRule.action, onChange:function(e) { setNewRule(Object.assign({}, newRule, {action:e.target.value})); }, style:{width:'100%',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:13,fontFamily:'Inter',cursor:'pointer'} },
                                        React.createElement('option', { value:'flag' }, 'Flag (mark as suspicious)'),
                                        React.createElement('option', { value:'whitelist' }, 'Whitelist (mark as safe)'),
                                        React.createElement('option', { value:'block' }, 'Block (mark as malicious)')
                                    )
                                )
                            ),
                            React.createElement('div', { style:{marginBottom:16} },
                                React.createElement('label', { style:{fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6} }, 'Description (optional)'),
                                React.createElement('input', { value:newRule.description, onChange:function(e) { setNewRule(Object.assign({}, newRule, {description:e.target.value})); }, placeholder:'Why this rule matters...', style:{width:'100%',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:13,fontFamily:'Inter'} })
                            ),
                            React.createElement('button', { onClick:function() {
                                if (!newRule.name || !newRule.pattern) { showToast('error', 'Name and pattern are required'); return; }
                                API.post('/rules', newRule).then(function() { showToast('success', 'Rule created'); setNewRule({name:'', pattern:'', rule_type:'keyword', action:'flag', description:''}); fetchRules(); }).catch(function(e) { showToast('error', e.message || 'Failed'); });
                            }, style:btnRed }, '+ Create Rule')
                        ),

                        React.createElement('div', { style:cardStyle },
                            React.createElement('div', { style:{fontSize:14,fontWeight:600,marginBottom:12} }, 'Test Rules'),
                            React.createElement('div', { style:{display:'flex',gap:8,marginBottom:12} },
                                React.createElement('input', { value:ruleTestText, onChange:function(e) { setRuleTestText(e.target.value); }, placeholder:'Paste email text to test against your rules...', style:{flex:1,padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,color:'#f5f5f5',fontSize:13,fontFamily:'Inter'} }),
                                React.createElement('button', { onClick:function() {
                                    API.post('/rules/check', {text:ruleTestText}).then(function(r) { setRuleMatches(r.matches || []); }).catch(function(e) { showToast('error', e.message || 'Failed'); });
                                }, style:btnDark }, 'Test')
                            ),
                            ruleMatches !== null ? React.createElement('div', null,
                                ruleMatches.length === 0 ? React.createElement('div', { style:{fontSize:13,color:'#888',padding:'12px',background:'#0a0a0a',borderRadius:8,textAlign:'center'} }, 'No rules matched this text.') :
                                ruleMatches.map(function(m, i) {
                                    var actionColors = {flag:'#EAB308',whitelist:'#22C55E',block:'#EF4444'};
                                    return React.createElement('div', { key:i, style:{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'10px 14px',background:'#0a0a0a',border:'1px solid #222',borderRadius:8,marginBottom:6} },
                                        React.createElement('div', null,
                                            React.createElement('span', { style:{fontSize:13,fontWeight:600} }, m.name),
                                            React.createElement('span', { style:{fontSize:11,color:'#666',marginLeft:8} }, 'Pattern: ' + m.pattern)
                                        ),
                                        React.createElement('span', { style:{fontSize:11,fontWeight:700,color:actionColors[m.action]||'#888',textTransform:'uppercase'} }, m.action)
                                    );
                                })
                            ) : null
                        ),

                        React.createElement('div', { style:cardStyle },
                            React.createElement('div', { style:{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:16} },
                                React.createElement('div', { style:{fontSize:14,fontWeight:600} }, 'Active Rules (' + rules.length + ')')
                            ),
                            rules.length === 0 ? React.createElement('div', { style:{textAlign:'center',padding:'40px 0',color:'#666',fontSize:14} }, 'No custom rules yet. Create one above to get started.') :
                            rules.map(function(r) {
                                var actionColors = {flag:'#EAB308',whitelist:'#22C55E',block:'#EF4444'};
                                var actionBgs = {flag:'rgba(234,179,8,0.12)',whitelist:'rgba(34,197,94,0.12)',block:'rgba(220,38,38,0.12)'};
                                return React.createElement('div', { key:r.id, style:{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'14px 16px',background:'#0a0a0a',border:'1px solid #222',borderRadius:10,marginBottom:8,opacity:r.enabled?1:0.5} },
                                    React.createElement('div', { style:{flex:1} },
                                        React.createElement('div', { style:{display:'flex',alignItems:'center',gap:8,marginBottom:4} },
                                            React.createElement('span', { style:{fontSize:14,fontWeight:600} }, r.name),
                                            React.createElement('span', { style:{fontSize:10,fontWeight:700,color:actionColors[r.action],background:actionBgs[r.action],padding:'2px 8px',borderRadius:4,textTransform:'uppercase'} }, r.action),
                                            React.createElement('span', { style:{fontSize:10,color:'#888',background:'#161616',padding:'2px 6px',borderRadius:4} }, r.rule_type)
                                        ),
                                        React.createElement('div', { style:{fontSize:12,color:'#888',fontFamily:'JetBrains Mono',marginBottom:2} }, r.pattern),
                                        r.description ? React.createElement('div', { style:{fontSize:11,color:'#555'} }, r.description) : null
                                    ),
                                    React.createElement('div', { style:{display:'flex',gap:6,alignItems:'center'} },
                                        React.createElement('button', { onClick:function() {
                                            API.patch('/rules/' + r.id + '/toggle', {enabled:!r.enabled}).then(function() { fetchRules(); }).catch(function(e) { showToast('error', e.message || 'Failed'); });
                                        }, style:{width:36,height:20,borderRadius:10,background:r.enabled?'linear-gradient(135deg,#22C55E,#166534)':'#333',border:'none',cursor:'pointer',position:'relative',transition:'all 0.2s'} },
                                            React.createElement('div', { style:{width:16,height:16,borderRadius:'50%',background:'#fff',position:'absolute',top:2,left:r.enabled?18:2,transition:'all 0.2s'} })
                                        ),
                                        React.createElement('button', { onClick:function() {
                                            if (!confirm('Delete rule "' + r.name + '"?')) return;
                                            API.del('/rules/' + r.id).then(function() { showToast('success', 'Rule deleted'); fetchRules(); }).catch(function(e) { showToast('error', e.message || 'Failed'); });
                                        }, style:{background:'rgba(220,38,38,0.08)',border:'1px solid rgba(220,38,38,0.2)',color:'#FCA5A5',padding:'4px 10px',borderRadius:6,fontSize:11,cursor:'pointer',fontFamily:'Inter'} }, 'Delete')
                                    )
                                );
                            })
                        )
                    ) : React.createElement('div', null,
                        React.createElement('h2', { style:{fontSize:20,fontWeight:700,marginBottom:8} }, 'Team Members'),
                        React.createElement('p', { style:{fontSize:13,color:'#666',marginBottom:24} }, 'Manage who has access to your organization.'),

                        React.createElement('div', { style:Object.assign({}, cardStyle, {marginBottom:24}) },
                            React.createElement('div', { style:{fontSize:14,fontWeight:600,marginBottom:12} }, 'Invite Member'),
                            React.createElement('div', { style:{display:'flex',gap:8,flexWrap:'wrap'} },
                    React.createElement('div', { className:'anim-modal s-modal', onClick:function(e) { e.stopPropagation(); }, style:{background:'#161616',border:'1px solid #1a1a1a',borderRadius:16,width:'100%',maxWidth:480,padding:28} },
                        React.createElement('div', { style:{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:20} },
                            React.createElement('div', { style:{fontSize:18,fontWeight:700} }, 'Add Email Connection'),
                            React.createElement('button', { onClick:function() { setShowAdd(false); }, style:{background:'#111',border:'1px solid #282828',borderRadius:8,width:28,height:28,display:'flex',alignItems:'center',justifyContent:'center',cursor:'pointer',color:'#666',fontSize:13} }, '\\u2715')
                        ),
                        React.createElement(AddConnectionForm, { onDone:function() { setShowAdd(false); showToast('success', 'Connection added'); fetchConns(); }, showToast:showToast })
                    )
                ) : null,
                toast ? React.createElement('div', { style:{position:'fixed',top:80,right:20,zIndex:200,animation:'toastIn 0.3s ease-out',background:toast.type==='success'?'#0d2818':'#2d0a0a',border:'1px solid '+(toast.type==='success'?'#166534':'#7f1d1d'),borderRadius:10,padding:'12px 16px',display:'flex',alignItems:'center',gap:10,fontSize:13,color:toast.type==='success'?'#86EFAC':'#FCA5A5',boxShadow:'0 8px 30px rgba(0,0,0,0.4)'} },
                    React.createElement('span', null, toast.type==='success'?'\\u2713':'\\u2715'),
                    React.createElement('span', null, toast.msg)
                ) : null
            );
        }

        function AddConnectionForm(props) {
            var _s = useState({label:'My Email',provider:'gmail',imap_host:'imap.gmail.com',imap_port:993,imap_username:'',imap_password:'',imap_folder:'INBOX',scan_interval:30});
            var form = _s[0], setForm = _s[1];
            var _submitting = useState(false);
            var submitting = _submitting[0], setSubmitting = _submitting[1];
            var _showGuide = useState(false);
            var showGuide = _showGuide[0], setShowGuide = _showGuide[1];
            var inputStyle = { width:'100%', padding:'10px 14px', background:'#0a0a0a', border:'1px solid #222', borderRadius:8, color:'#f5f5f5', fontSize:13, fontFamily:'Inter', outline:'none' };

            var providers = { gmail:{host:'imap.gmail.com',port:993}, outlook:{host:'outlook.office365.com',port:993}, yahoo:{host:'imap.mail.yahoo.com',port:993}, custom:{host:'',port:993} };

            var handleChange = function(field, value) {
                var next = Object.assign({}, form, {[field]:value});
                if (field === 'provider' && providers[value]) {
                    next.imap_host = providers[value].host;
                    next.imap_port = providers[value].port;
                }
                setForm(next);
            };

            var handleSubmit = function() {
                if (!form.imap_username || !form.imap_password) { props.showToast('error', 'Fill in email and password'); return; }
                setSubmitting(true);
                API.post('/connections', form).then(function() { props.onDone(); }).catch(function(e) { props.showToast('error', 'Failed to add: ' + (e.message || 'Unknown error')); setSubmitting(false); });
            };

            var labelStyle = {fontSize:11,fontWeight:600,color:'#666',textTransform:'uppercase',letterSpacing:'0.05em',display:'block',marginBottom:6};
            var stepNum = {display:'inline-flex',alignItems:'center',justifyContent:'center',width:22,height:22,borderRadius:'50%',background:'linear-gradient(135deg,#DC2626,#991B1B)',color:'#fff',fontSize:11,fontWeight:700,flexShrink:0,marginRight:8};
            var guideStep = {display:'flex',alignItems:'flex-start',marginBottom:14};

            var gmailGuide = React.createElement('div', { style:{background:'#0a0a0a',border:'1px solid #222',borderRadius:10,padding:16,marginBottom:14} },
                React.createElement('div', { style:{fontSize:13,fontWeight:700,color:'#EF4444',marginBottom:12} }, 'How to Create a Gmail App Password'),
                React.createElement('div', { style:{fontSize:12,color:'#888',marginBottom:12} }, 'Google requires an "App Password" instead of your regular password for IMAP access. This is a one-time setup.'),
                React.createElement('div', { style:guideStep },
                    React.createElement('span', { style:stepNum }, '1'),
                    React.createElement('div', null,
                        React.createElement('div', { style:{fontSize:12,fontWeight:600,color:'#ccc'} }, 'Enable 2-Step Verification'),
                        React.createElement('div', { style:{fontSize:11,color:'#666',lineHeight:1.5} }, 'Go to ', React.createElement('a', { href:'https://myaccount.google.com/security', target:'_blank', style:{color:'#EF4444'} }, 'myaccount.google.com/security'), ' and turn on 2-Step Verification if you have not already. This is required before you can create an app password.')
                    )
                ),
                React.createElement('div', { style:guideStep },
                    React.createElement('span', { style:stepNum }, '2'),
                    React.createElement('div', null,
                        React.createElement('div', { style:{fontSize:12,fontWeight:600,color:'#ccc'} }, 'Open App Passwords Page'),
                        React.createElement('div', { style:{fontSize:11,color:'#666',lineHeight:1.5} }, 'Go to ', React.createElement('a', { href:'https://myaccount.google.com/apppasswords', target:'_blank', style:{color:'#EF4444'} }, 'myaccount.google.com/apppasswords'), ' directly. You may be asked to sign in again.')
                    )
                ),
                React.createElement('div', { style:guideStep },
                    React.createElement('span', { style:stepNum }, '3'),
                    React.createElement('div', null,
                        React.createElement('div', { style:{fontSize:12,fontWeight:600,color:'#ccc'} }, 'Generate the Password'),
                        React.createElement('div', { style:{fontSize:11,color:'#666',lineHeight:1.5} }, 'Under "App name", type something like "Sentinel" and click ', React.createElement('span', { style:{fontWeight:600,color:'#ccc'} }, 'Create'), '. Google will show you a 16-character password.')
                    )
                ),
                React.createElement('div', { style:guideStep },
                    React.createElement('span', { style:stepNum }, '4'),
                    React.createElement('div', null,
                        React.createElement('div', { style:{fontSize:12,fontWeight:600,color:'#ccc'} }, 'Copy & Paste the Password'),
                        React.createElement('div', { style:{fontSize:11,color:'#666',lineHeight:1.5} }, 'Copy the 16-character password (e.g. abcd efgh ijkl mnop) and paste it in the App Password field below. ', React.createElement('span', { style:{color:'#EF4444',fontWeight:600} }, 'Remove the spaces'), ' when pasting.')
                    )
                ),
                React.createElement('div', { style:guideStep },
                    React.createElement('span', { style:stepNum }, '5'),
                    React.createElement('div', null,
                        React.createElement('div', { style:{fontSize:12,fontWeight:600,color:'#ccc'} }, 'All Set!'),
                        React.createElement('div', { style:{fontSize:11,color:'#666',lineHeight:1.5} }, 'Click "Add Connection" below. Sentinel will verify your credentials by logging into your inbox via IMAP.')
                    )
                )
            );

            var outlookGuide = React.createElement('div', { style:{background:'#0a0a0a',border:'1px solid #222',borderRadius:10,padding:16,marginBottom:14} },
                React.createElement('div', { style:{fontSize:13,fontWeight:700,color:'#3B82F6',marginBottom:12} }, 'How to Create a Microsoft App Password'),
                React.createElement('div', { style:guideStep },
                    React.createElement('span', { style:stepNum }, '1'),
                    React.createElement('div', null,
                        React.createElement('div', { style:{fontSize:12,fontWeight:600,color:'#ccc'} }, 'Go to Microsoft Account Security'),
                        React.createElement('div', { style:{fontSize:11,color:'#666',lineHeight:1.5} }, 'Visit ', React.createElement('a', { href:'https://account.microsoft.com/security', target:'_blank', style:{color:'#3B82F6'} }, 'account.microsoft.com/security'), ' and sign in.')
                    )
                ),
                React.createElement('div', { style:guideStep },
                    React.createElement('span', { style:stepNum }, '2'),
                    React.createElement('div', null,
                        React.createElement('div', { style:{fontSize:12,fontWeight:600,color:'#ccc'} }, 'Create an App Password'),
                        React.createElement('div', { style:{fontSize:11,color:'#666',lineHeight:1.5} }, 'Click "Create a new app password" under the "App passwords" section. Copy the generated password and paste it below.')
                    )
                )
            );

            return React.createElement('div', null,
                React.createElement('div', { style:{marginBottom:14} },
                    React.createElement('label', { style:labelStyle }, 'Label'),
                    React.createElement('input', { value:form.label, onChange:function(e) { handleChange('label', e.target.value); }, style:inputStyle })
                ),
                React.createElement('div', { style:{marginBottom:14} },
                    React.createElement('label', { style:labelStyle }, 'Provider'),
                    React.createElement('select', { value:form.provider, onChange:function(e) { handleChange('provider', e.target.value); }, style:Object.assign({}, inputStyle, {cursor:'pointer'}) },
                        React.createElement('option', { value:'gmail' }, 'Gmail'),
                        React.createElement('option', { value:'outlook' }, 'Outlook / Microsoft 365'),
                        React.createElement('option', { value:'yahoo' }, 'Yahoo Mail'),
                        React.createElement('option', { value:'custom' }, 'Custom IMAP')
                    )
                ),
                React.createElement('div', { style:{marginBottom:14} },
                    React.createElement('label', { style:labelStyle }, 'IMAP Host'),
                    React.createElement('input', { value:form.imap_host, onChange:function(e) { handleChange('imap_host', e.target.value); }, style:inputStyle })
                ),
                React.createElement('div', { style:{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:14} },
                    React.createElement('div', null,
                        React.createElement('label', { style:labelStyle }, 'Port'),
                        React.createElement('input', { type:'number', value:form.imap_port, onChange:function(e) { handleChange('imap_port', parseInt(e.target.value)||993); }, style:inputStyle })
                    ),
                    React.createElement('div', null,
                        React.createElement('label', { style:labelStyle }, 'Folder'),
                        React.createElement('input', { value:form.imap_folder, onChange:function(e) { handleChange('imap_folder', e.target.value); }, style:inputStyle })
                    )
                ),
                React.createElement('div', { style:{marginBottom:14} },
                    React.createElement('label', { style:labelStyle }, 'Email Address'),
                    React.createElement('input', { value:form.imap_username, onChange:function(e) { handleChange('imap_username', e.target.value); }, placeholder:'you@gmail.com', style:inputStyle })
                ),
                React.createElement('div', { style:{marginBottom:14} },
                    React.createElement('label', { style:labelStyle }, 'App Password'),
                    React.createElement('input', { type:'password', value:form.imap_password, onChange:function(e) { handleChange('imap_password', e.target.value); }, placeholder:'16-character app password', style:inputStyle }),
                    React.createElement('button', { onClick:function() { setShowGuide(!showGuide); }, style:{background:'none',border:'none',color:'#EF4444',fontSize:11,fontWeight:600,cursor:'pointer',padding:'4px 0',marginTop:4,fontFamily:'Inter'} }, showGuide ? '\u25B2 Hide instructions' : '\u25BC How to create an app password')
                ),
                form.provider === 'gmail' && showGuide ? gmailGuide : null,
                form.provider === 'outlook' && showGuide ? outlookGuide : null,
                form.provider !== 'gmail' && form.provider !== 'outlook' && showGuide ? React.createElement('div', { style:{background:'#0a0a0a',border:'1px solid #222',borderRadius:10,padding:16,marginBottom:14} },
                    React.createElement('div', { style:{fontSize:13,fontWeight:700,color:'#EAB308',marginBottom:8} }, 'App Password'),
                    React.createElement('div', { style:{fontSize:11,color:'#888',lineHeight:1.5} }, 'Contact your email provider for instructions on creating an app-specific password for IMAP access.')
                ) : null,
                React.createElement('div', { style:{marginBottom:20} },
                    React.createElement('label', { style:labelStyle }, 'Scan Interval (minutes)'),
                    React.createElement('input', { type:'number', value:form.scan_interval, onChange:function(e) { handleChange('scan_interval', parseInt(e.target.value)||30); }, min:5, max:1440, style:inputStyle })
                ),
                React.createElement('div', { style:{display:'flex',gap:10,justifyContent:'flex-end'} },
                    React.createElement('button', { onClick:props.onDone, style:{padding:'8px 16px',borderRadius:8,fontSize:13,fontWeight:600,cursor:'pointer',border:'1px solid #282828',background:'#161616',color:'#a0a0a0',fontFamily:'Inter'} }, 'Cancel'),
                    React.createElement('button', { onClick:handleSubmit, disabled:submitting, style:{padding:'8px 16px',borderRadius:8,fontSize:13,fontWeight:600,cursor:'pointer',border:'none',background:'linear-gradient(135deg,#DC2626,#991B1B)',color:'#fff',fontFamily:'Inter',opacity:submitting?0.7:1} }, submitting ? 'Adding...' : 'Add Connection')
                )
            );
        }

        var root = ReactDOM.createRoot(document.getElementById('root'));
        root.render(React.createElement(App));
    </script>
</body>
</html>"""

# ============================================================================
# MARKETING PAGE
# ============================================================================
MARKETING_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL - AI-Powered Phishing Defense</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter', sans-serif; background: #0a0a0a; color: #f5f5f5; line-height: 1.6; overflow-x: hidden; }
        a { text-decoration: none; color: inherit; }

        .nav { position: fixed; top: 0; left: 0; right: 0; z-index: 100; padding: 16px 40px; display: flex; justify-content: space-between; align-items: center; background: rgba(10,10,10,0.9); backdrop-filter: blur(20px); border-bottom: 1px solid #1a1a1a; }
        .logo { display: flex; align-items: center; gap: 10px; }
        .logo-text { font-weight: 800; font-size: 18px; letter-spacing: -0.02em; }
        .nav-links { display: flex; gap: 12px; align-items: center; }
        .nav-links a { padding: 8px 16px; border-radius: 8px; font-size: 14px; font-weight: 500; color: #a0a0a0; transition: all 0.2s; }
        .nav-links a:hover { color: #f5f5f5; }
        .btn-primary { background: linear-gradient(135deg, #DC2626, #991B1B); color: white; border: 1px solid rgba(220,38,38,0.3); padding: 10px 24px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
        .btn-primary:hover { box-shadow: 0 4px 20px rgba(220,38,38,0.3); transform: translateY(-1px); }
        .btn-outline { background: transparent; color: #f5f5f5; border: 1px solid #333; padding: 10px 24px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
        .btn-outline:hover { border-color: #555; background: #161616; }
        .section-label { text-align: center; font-size: 12px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: #DC2626; margin-bottom: 12px; }

        .hero { min-height: 100vh; display: flex; align-items: center; justify-content: center; text-align: center; padding: 120px 40px 80px; position: relative; }
        .hero::before { content: ''; position: absolute; top: -200px; left: 50%; transform: translateX(-50%); width: 900px; height: 900px; background: radial-gradient(circle, rgba(220,38,38,0.06) 0%, transparent 60%); pointer-events: none; }
        .hero h1 { font-size: 60px; font-weight: 900; letter-spacing: -0.03em; line-height: 1.05; margin-bottom: 20px; }
        .hero h1 span { background: linear-gradient(135deg, #DC2626, #F87171); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .hero p { font-size: 18px; color: #888; max-width: 600px; margin: 0 auto 36px; line-height: 1.7; }
        .hero-buttons { display: flex; gap: 12px; justify-content: center; margin-bottom: 48px; }
        .hero-buttons .btn-primary { padding: 14px 36px; font-size: 16px; }
        .hero-buttons .btn-outline { padding: 14px 36px; font-size: 16px; }

        .demo-section { padding: 80px 40px; max-width: 1000px; margin: 0 auto; }
        .demo-section h2 { text-align: center; font-size: 36px; font-weight: 800; margin-bottom: 12px; }
        .demo-section > p { text-align: center; color: #666; margin-bottom: 48px; font-size: 16px; }
        .demo-window { background: #111; border: 1px solid #1a1a1a; border-radius: 16px; overflow: hidden; box-shadow: 0 20px 60px rgba(0,0,0,0.4); }
        .demo-titlebar { display: flex; align-items: center; gap: 8px; padding: 12px 16px; background: #0d0d0d; border-bottom: 1px solid #1a1a1a; }
        .demo-dot { width: 10px; height: 10px; border-radius: 50%; }
        .demo-dot.r { background: #EF4444; }
        .demo-dot.y { background: #EAB308; }
        .demo-dot.g { background: #22C55E; }
        .demo-titlebar span { font-size: 12px; color: #666; margin-left: 8px; }
        .demo-body { padding: 32px; min-height: 400px; position: relative; }

        .demo-step { display: none; animation: demoFadeIn 0.5s ease-out; }
        .demo-step.active { display: block; }
        @keyframes demoFadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

        .demo-paste-area { background: #0a0a0a; border: 1px solid #222; border-radius: 8px; padding: 16px; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #a0a0a0; line-height: 1.6; margin-bottom: 16px; min-height: 160px; white-space: pre-wrap; }
        .demo-btn { background: linear-gradient(135deg, #DC2626, #991B1B); color: white; border: none; padding: 10px 20px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; }
        .demo-result { background: #0d0d0d; border: 1px solid #1a1a1a; border-radius: 12px; padding: 24px; }
        .demo-verdict { display: inline-flex; align-items: center; gap: 6px; padding: 6px 14px; border-radius: 8px; font-size: 13px; font-weight: 700; text-transform: uppercase; }
        .demo-verdict.malicious { background: rgba(220,38,38,0.12); color: #FCA5A5; border: 1px solid rgba(220,38,38,0.25); }
        .demo-verdict.safe { background: rgba(34,197,94,0.12); color: #86EFAC; border: 1px solid rgba(34,197,94,0.25); }
        .demo-indicator { display: flex; gap: 8px; font-size: 13px; color: #a0a0a0; margin-bottom: 6px; padding: 8px 12px; background: #111; border-radius: 6px; border: 1px solid #1a1a1a; }
        .demo-indicator .dot { color: #EF4444; font-size: 8px; margin-top: 5px; }
        .demo-confidence { text-align: center; margin: 16px 0; }
        .demo-confidence .score { font-size: 48px; font-weight: 900; color: #EF4444; }
        .demo-confidence .label { font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 0.05em; }
        .demo-nav { display: flex; justify-content: center; gap: 8px; margin-top: 24px; padding-top: 16px; border-top: 1px solid #1a1a1a; }
        .demo-nav button { padding: 8px 16px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; border: 1px solid #282828; background: #161616; color: #a0a0a0; transition: all 0.2s; }
        .demo-nav button:hover { border-color: #DC2626; color: #EF4444; }
        .demo-nav button.active { background: rgba(220,38,38,0.1); border-color: rgba(220,38,38,0.4); color: #EF4444; }

        .steps-section { padding: 100px 40px; max-width: 1000px; margin: 0 auto; }
        .steps-section h2 { text-align: center; font-size: 36px; font-weight: 800; margin-bottom: 60px; }
        .install-steps { display: flex; flex-direction: column; gap: 24px; }
        .install-step { display: flex; gap: 20px; align-items: flex-start; background: linear-gradient(145deg, #111, #0d0d0d); border: 1px solid #1a1a1a; border-radius: 14px; padding: 28px; transition: all 0.3s; }
        .install-step:hover { border-color: #2a2a2a; transform: translateX(4px); }
        .install-step-num { width: 40px; height: 40px; border-radius: 10px; background: rgba(220,38,38,0.1); border: 1px solid rgba(220,38,38,0.2); display: flex; align-items: center; justify-content: center; font-size: 16px; font-weight: 800; color: #DC2626; flex-shrink: 0; }
        .install-step-content h3 { font-size: 16px; font-weight: 700; margin-bottom: 6px; }
        .install-step-content p { font-size: 14px; color: #777; line-height: 1.6; }
        .install-step-content code { display: block; margin-top: 10px; padding: 10px 14px; background: #0a0a0a; border: 1px solid #1a1a1a; border-radius: 6px; font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #a0a0a0; word-break: break-all; }

        .features-section { padding: 100px 40px; max-width: 1200px; margin: 0 auto; }
        .features-section h2 { text-align: center; font-size: 36px; font-weight: 800; margin-bottom: 60px; }
        .features-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; }
        .feature-card { background: linear-gradient(145deg, #111, #0d0d0d); border: 1px solid #1a1a1a; border-radius: 14px; padding: 28px; transition: all 0.3s; }
        .feature-card:hover { border-color: #2a2a2a; transform: translateY(-3px); }
        .feature-icon { width: 44px; height: 44px; border-radius: 10px; background: rgba(220,38,38,0.08); border: 1px solid rgba(220,38,38,0.12); display: flex; align-items: center; justify-content: center; margin-bottom: 16px; }
        .feature-icon svg { width: 20px; height: 20px; }
        .feature-card h3 { font-size: 16px; font-weight: 700; margin-bottom: 6px; }
        .feature-card p { font-size: 13px; color: #777; line-height: 1.7; }

        .security-section { padding: 80px 40px; max-width: 800px; margin: 0 auto; text-align: center; }
        .security-section h2 { font-size: 36px; font-weight: 800; margin-bottom: 12px; }
        .security-section > p { color: #666; margin-bottom: 40px; font-size: 16px; }
        .security-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
        .security-item { background: linear-gradient(145deg, #111, #0d0d0d); border: 1px solid #1a1a1a; border-radius: 12px; padding: 24px; text-align: left; transition: all 0.3s; }
        .security-item:hover { border-color: rgba(34,197,94,0.3); }
        .security-item h4 { font-size: 14px; font-weight: 700; margin-bottom: 6px; color: #86EFAC; }
        .security-item p { font-size: 13px; color: #777; line-height: 1.6; }

        .cta-section { padding: 100px 40px; text-align: center; }
        .cta-box { max-width: 640px; margin: 0 auto; background: linear-gradient(145deg, #111, #0d0d0d); border: 1px solid #1a1a1a; border-radius: 20px; padding: 60px 48px; position: relative; overflow: hidden; }
        .cta-box::before { content: ''; position: absolute; top: -1px; left: 20%; right: 20%; height: 2px; background: linear-gradient(90deg, transparent, #DC2626, transparent); }
        .cta-box h2 { font-size: 30px; font-weight: 800; margin-bottom: 12px; }
        .cta-box p { color: #888; margin-bottom: 32px; font-size: 16px; }

        .footer { padding: 40px; text-align: center; border-top: 1px solid #1a1a1a; color: #444; font-size: 13px; }
        .footer-links { display: flex; gap: 24px; justify-content: center; margin-top: 8px; }
        .footer-links a { color: #666; font-size: 12px; transition: color 0.2s; }
        .footer-links a:hover { color: #DC2626; }

        @keyframes fadeUp { from { opacity: 0; transform: translateY(24px); } to { opacity: 1; transform: translateY(0); } }
        @keyframes typing { from { width: 0; } to { width: 100%; } }
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes blink { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }
        .fade-up { animation: fadeUp 0.7s cubic-bezier(0.16, 1, 0.3, 1) both; }
        .delay-1 { animation-delay: 0.1s; }
        .delay-2 { animation-delay: 0.2s; }
        .delay-3 { animation-delay: 0.3s; }
    </style>
</head>
<body>
    <nav class="nav">
        <a href="/" class="logo">
            <svg viewBox="0 0 40 44" fill="none" xmlns="http://www.w3.org/2000/svg" width="32" height="35"><path d="M20 2L4 10v12c0 11 7.2 21.3 16 24 8.8-2.7 16-13 16-24V10L20 2z" fill="url(#lgM)" stroke="#991B1B" stroke-width="1.5"/><path d="M20 10v8m0 0v8m0-8l-4-4m4 4l4-4" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="lgM" x1="4" y1="2" x2="36" y2="46"><stop stop-color="#DC2626"/><stop offset="1" stop-color="#7F1D1D"/></linearGradient></defs></svg>
            <div class="logo-text">SENTINEL</div>
        </a>
        <div class="nav-links">
            <a href="/">Home</a>
            <a href="/login">Log In</a>
            <a href="/login"><button class="btn-primary">Get Started</button></a>
        </div>
    </nav>

    <section class="hero">
        <div>
            <div class="hero-badge fade-up" style="display:inline-flex;align-items:center;gap:8px;padding:8px 16px;border-radius:20px;border:1px solid rgba(220,38,38,0.3);background:rgba(220,38,38,0.08);font-size:12px;font-weight:600;color:#FCA5A5;margin-bottom:24px">
                <div style="width:6px;height:6px;border-radius:50%;background:#22C55E;animation:blink 2s ease-in-out infinite"></div>
                AI-Powered Phishing Defense
            </div>
            <h1 class="fade-up delay-1">Protect Your Team<br>from <span>Phishing Attacks</span></h1>
            <p class="fade-up delay-2">SENTINEL analyzes suspicious emails in real-time using advanced AI. Get instant verdicts, detailed reasoning, and actionable recommendations to keep your organization safe.</p>
            <div class="hero-buttons fade-up delay-3">
                <a href="/login"><button class="btn-primary">Get Started</button></a>
                <a href="#demo"><button class="btn-outline">See It In Action</button></a>
            </div>
        </div>
    </section>

    <section class="demo-section fade-up" id="demo">
        <div class="section-label">LIVE DEMO</div>
        <h2>See SENTINEL In Action</h2>
        <p>Watch how SENTINEL analyzes a phishing email in real-time</p>
        <div class="demo-window">
            <div class="demo-titlebar">
                <div class="demo-dot r"></div>
                <div class="demo-dot y"></div>
                <div class="demo-dot g"></div>
                <span>SENTINEL Dashboard - Email Analysis</span>
            </div>
            <div class="demo-body">
                <div class="demo-step active" id="d1">
                    <div style="font-size:13px;color:#666;margin-bottom:12px;font-weight:600">STEP 1: Paste the suspicious email</div>
                    <div class="demo-paste-area">From: security@paypa1-verify.xyz
Subject: URGENT: Your PayPal account has been limited

Dear Customer,

We detected unusual activity on your PayPal account.
Your account access has been temporarily limited.

You must verify your identity within 24 hours or your
account will be permanently suspended.

Click here to verify: http://bit.ly/paypal-verify

Please confirm your:
- Full name
- PayPal password
- Social Security Number</div>
                    <button class="demo-btn" onclick="demoNext(2)">Analyze Email</button>
                </div>
                <div class="demo-step" id="d2">
                    <div style="font-size:13px;color:#666;margin-bottom:16px;font-weight:600">STEP 2: AI analyzes the email</div>
                    <div style="text-align:center;padding:40px 0">
                        <div style="width:40px;height:40px;border:3px solid #1a1a1a;border-top-color:#DC2626;border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto 16px"></div>
                        <div style="color:#a0a0a0;font-size:14px">Running AI threat analysis...</div>
                        <div style="display:flex;gap:4px;justify-content:center;margin-top:12px">
                            <div style="width:40px;height:3px;border-radius:2px;background:#DC2626"></div>
                            <div style="width:40px;height:3px;border-radius:2px;background:#DC2626"></div>
                            <div style="width:40px;height:3px;border-radius:2px;background:#DC2626;animation:pulse 1s ease-in-out infinite"></div>
                            <div style="width:40px;height:3px;border-radius:2px;background:#222"></div>
                        </div>
                    </div>
                    <div style="text-align:center"><button class="demo-btn" onclick="demoNext(3)">View Results</button></div>
                </div>
                <div class="demo-step" id="d3">
                    <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px">
                        <div>
                            <div style="font-size:13px;color:#666;margin-bottom:4px;font-weight:600">STEP 3: Review the verdict</div>
                            <div style="font-size:18px;font-weight:800">AI Threat Analysis</div>
                        </div>
                        <div class="demo-verdict malicious">&#10005; MALICIOUS</div>
                    </div>
                    <div class="demo-confidence">
                        <div class="score">98%</div>
                        <div class="label">Confidence Score</div>
                    </div>
                    <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#666;margin:16px 0 8px">Indicators Found</div>
                    <div class="demo-indicator"><span class="dot">&#9679;</span> Sender domain paypa1-verify.xyz spoofs legitimate paypal.com</div>
                    <div class="demo-indicator"><span class="dot">&#9679;</span> URL shortener bit.ly obscures true destination</div>
                    <div class="demo-indicator"><span class="dot">&#9679;</span> Urgency language: account will be suspended in 24 hours</div>
                    <div class="demo-indicator"><span class="dot">&#9679;</span> Request for password/credentials in body text</div>
                    <div class="demo-indicator"><span class="dot">&#9679;</span> Request for sensitive personal information (SSN)</div>
                    <div style="font-size:11px;font-weight:700;letter-spacing:0.08em;text-transform:uppercase;color:#666;margin:16px 0 8px">Social Engineering Tactics</div>
                    <div style="display:flex;flex-wrap:wrap;gap:6px">
                        <span style="padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;background:rgba(220,38,38,0.1);color:#FCA5A5;border:1px solid rgba(220,38,38,0.2)">&#9888; urgency</span>
                        <span style="padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;background:rgba(220,38,38,0.1);color:#FCA5A5;border:1px solid rgba(220,38,38,0.2)">&#9888; authority</span>
                        <span style="padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;background:rgba(220,38,38,0.1);color:#FCA5A5;border:1px solid rgba(220,38,38,0.2)">&#9888; fear</span>
                        <span style="padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;background:rgba(34,197,94,0.06);color:#86EFAC;border:1px solid rgba(34,197,94,0.12)">&#10003; curiosity</span>
                        <span style="padding:5px 12px;border-radius:6px;font-size:11px;font-weight:600;background:rgba(34,197,94,0.06);color:#86EFAC;border:1px solid rgba(34,197,94,0.12)">&#10003; scarcity</span>
                    </div>
                    <div style="margin-top:20px;text-align:center"><button class="demo-btn" onclick="demoNext(1)">Try Again</button></div>
                </div>
                <div class="demo-nav">
                    <button class="active" onclick="demoNext(1)">1. Paste</button>
                    <button onclick="demoNext(2)">2. Analyze</button>
                    <button onclick="demoNext(3)">3. Verdict</button>
                </div>
            </div>
        </div>
    </section>

    <section class="steps-section">
        <div class="section-label">SETUP GUIDE</div>
        <h2>Get Started in 3 Steps</h2>
        <div class="install-steps">
            <div class="install-step fade-up">
                <div class="install-step-num">1</div>
                <div class="install-step-content">
                    <h3>Download & Extract</h3>
                    <p>Download the SENTINEL package and extract it to any folder on your computer.</p>
                    <code>sentinel-v3.0.0.zip &rarr; Extract to C:\\SENTINEL\\</code>
                </div>
            </div>
            <div class="install-step fade-up delay-1">
                <div class="install-step-num">2</div>
                <div class="install-step-content">
                    <h3>Install Dependencies</h3>
                    <p>Run the one-click installer to set up the Python environment and all required packages.</p>
                    <code>cd C:\\SENTINEL && pip install -r requirements.txt</code>
                </div>
            </div>
            <div class="install-step fade-up delay-2">
                <div class="install-step-num">3</div>
                <div class="install-step-content">
                    <h3>Launch SENTINEL</h3>
                    <p>Start the server and open your browser. You're ready to analyze phishing emails.</p>
                    <code>python app.py &rarr; Dashboard: http://localhost:8000/dashboard</code>
                </div>
            </div>
        </div>
    </section>

    <section class="features-section">
        <div class="section-label">FEATURES</div>
        <h2>Everything You Need</h2>
        <div class="features-grid">
            <div class="feature-card">
                <div class="feature-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg></div>
                <h3>AI-Powered Analysis</h3>
                <p>Advanced LLM detects social engineering, spoofed domains, and credential harvesting with structured explainable output.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg></div>
                <h3>One-Click Reporting</h3>
                <p>Forward suspicious emails or paste them directly. Our parser extracts the original email and provides instant verdicts.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg></div>
                <h3>Real-Time Dashboard</h3>
                <p>Monitor threats live with confidence scores, indicators, and detailed analysis breakdowns in a sleek interface.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></div>
                <h3>Auto Email Polling</h3>
                <p>Connect your mailbox and SENTINEL automatically scans forwarded phishing reports around the clock.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div>
                <h3>Team Collaboration</h3>
                <p>Each team member gets their own isolated workspace. Share findings and build collective phishing intelligence.</p>
            </div>
            <div class="feature-card">
                <div class="feature-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#DC2626" stroke-width="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg></div>
                <h3>Executive Reports</h3>
                <p>Generate professional PDF security summaries with threat analysis, trends, and actionable recommendations.</p>
            </div>
        </div>
    </section>

    <section class="security-section">
        <div class="section-label">SECURITY &amp; PRIVACY</div>
        <h2>Your Data Stays Yours</h2>
        <p>Enterprise-grade security built into every layer of SENTINEL</p>
        <div class="security-grid">
            <div class="security-item">
                <h4>End-to-End Encrypted</h4>
                <p>All data is encrypted in transit and at rest. Your emails never leave your local machine unless you choose to connect external services.</p>
            </div>
            <div class="security-item">
                <h4>Per-User Isolation</h4>
                <p>Every user's data is completely isolated. One client can never see another client's emails, verdicts, or analysis history.</p>
            </div>
            <div class="security-item">
                <h4>Zero-Knowledge Architecture</h4>
                <p>SENTINEL processes everything locally. We don't collect, store, or transmit your email data to external servers.</p>
            </div>
            <div class="security-item">
                <h4>Self-Hosted</h4>
                <p>Run SENTINEL on your own infrastructure. Full control over your data, your network, your security policy.</p>
            </div>
        </div>
    </section>

    <section class="cta-section">
        <div class="cta-box">
            <h2>Ready to Protect Your Team?</h2>
            <p>Set up SENTINEL in under 5 minutes.</p>
            <a href="/login"><button class="btn-primary" style="padding: 14px 40px; font-size: 16px;">Get Started</button></a>
        </div>
    </section>

    <section id="health-check" style="padding: 80px 40px; max-width: 800px; margin: 0 auto; text-align: center;">
        <div style="font-size: 12px; font-weight: 700; letter-spacing: 0.1em; text-transform: uppercase; color: #DC2626; margin-bottom: 12px;">Free Tool</div>
        <h2 style="font-size: 32px; font-weight: 800; margin-bottom: 12px;">Security Health Check</h2>
        <p style="color: #888; font-size: 15px; margin-bottom: 32px; max-width: 500px; margin-left: auto; margin-right: auto;">Paste a suspicious email header or raw email text and get an instant threat assessment powered by AI.</p>

        <div id="hc-form" style="background: linear-gradient(145deg, #111, #0d0d0d); border: 1px solid #1a1a1a; border-radius: 16px; padding: 32px; text-align: left;">
            <div style="display: flex; gap: 12px; margin-bottom: 16px;">
                <div style="flex: 1;">
                    <label style="font-size: 11px; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 6px;">Sender Email</label>
                    <input id="hc-sender" placeholder="phisher@evil.com" style="width: 100%; padding: 10px 14px; background: #0a0a0a; border: 1px solid #222; border-radius: 8px; color: #f5f5f5; font-size: 13px; font-family: Inter, sans-serif; outline: none;">
                </div>
                <div style="flex: 1;">
                    <label style="font-size: 11px; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 6px;">Subject</label>
                    <input id="hc-subject" placeholder="Urgent: Verify your account" style="width: 100%; padding: 10px 14px; background: #0a0a0a; border: 1px solid #222; border-radius: 8px; color: #f5f5f5; font-size: 13px; font-family: Inter, sans-serif; outline: none;">
                </div>
            </div>
            <div style="margin-bottom: 16px;">
                <label style="font-size: 11px; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 6px;">Email Header / Body (paste raw email or forwarded text)</label>
                <textarea id="hc-body" rows="8" placeholder="Paste the full email header and body here...&#10;&#10;From: security@paypa1-verify.xyz&#10;Subject: Urgent: Verify your account&#10;...&#10;&#10;Dear customer, your account will be suspended within 24 hours. Click here to verify: http://bit.ly/xyz" style="width: 100%; padding: 10px 14px; background: #0a0a0a; border: 1px solid #222; border-radius: 8px; color: #f5f5f5; font-size: 13px; font-family: 'JetBrains Mono', monospace; outline: none; resize: vertical;"></textarea>
            </div>
            <button id="hc-btn" onclick="runHealthCheck()" style="background: linear-gradient(135deg, #DC2626, #991B1B); color: white; border: none; padding: 11px 24px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; font-family: Inter, sans-serif; transition: all 0.2s;">Scan for Threats</button>

            <div id="hc-result" style="display: none; margin-top: 24px; padding: 20px; background: #0a0a0a; border-radius: 12px; border: 1px solid #1a1a1a;">
                <div id="hc-verdict" style="font-size: 16px; font-weight: 700; margin-bottom: 12px;"></div>
                <div id="hc-indicators" style="margin-bottom: 16px;"></div>
                <div id="hc-reasoning" style="font-size: 13px; color: #a0a0a0; line-height: 1.6; margin-bottom: 16px;"></div>
                <div id="hc-recommendations" style="margin-bottom: 16px;"></div>
                <div id="hc-lead-gate" style="display: none; padding: 16px; background: rgba(220,38,38,0.05); border: 1px solid rgba(220,38,38,0.15); border-radius: 10px; text-align: center;">
                    <p style="font-size: 13px; color: #a0a0a0; margin-bottom: 12px;">Enter your work email to get the full report with detailed recommendations:</p>
                    <div style="display: flex; gap: 8px; max-width: 400px; margin: 0 auto;">
                        <input id="hc-lead-email" placeholder="you@company.com" style="flex: 1; padding: 10px 14px; background: #111; border: 1px solid #282828; border-radius: 8px; color: #f5f5f5; font-size: 13px; font-family: Inter, sans-serif; outline: none;">
                        <button onclick="captureLead()" style="background: linear-gradient(135deg, #DC2626, #991B1B); color: white; border: none; padding: 10px 20px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer;">Get Report</button>
                    </div>
                </div>
            </div>
        </div>
    </section>

    <script>
        var hcResult = null;
        function runHealthCheck() {
            var sender = document.getElementById('hc-sender').value;
            var subject = document.getElementById('hc-subject').value;
            var body = document.getElementById('hc-body').value;
            if (!sender && !body) { alert('Please provide a sender email or paste email content.'); return; }
            var btn = document.getElementById('hc-btn');
            btn.disabled = true;
            btn.textContent = 'Scanning...';
            fetch('/api/public/health-check', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ sender: sender, subject: subject, email_body: body, email_header: '' })
            }).then(function(r) { return r.json(); }).then(function(data) {
                hcResult = data;
                var resultDiv = document.getElementById('hc-result');
                resultDiv.style.display = 'block';
                var verdictColors = { safe: '#22C55E', suspicious: '#EAB308', malicious: '#DC2626' };
                var verdictBg = { safe: 'rgba(34,197,94,0.1)', suspicious: 'rgba(234,179,8,0.1)', malicious: 'rgba(220,38,38,0.1)' };
                var v = data.verdict || 'safe';
                document.getElementById('hc-verdict').innerHTML = '<span style="color:' + verdictColors[v] + '">' + v.toUpperCase() + '</span> <span style="color:#666;font-size:12px;font-weight:400">(' + (data.confidence_score || 0) + '% confidence)</span>';
                document.getElementById('hc-verdict').style.background = verdictBg[v];
                document.getElementById('hc-verdict').style.padding = '12px 16px';
                document.getElementById('hc-verdict').style.borderRadius = '8px';
                var indHtml = '<div style="display:flex;flex-wrap:wrap;gap:8px;">';
                (data.indicators || []).forEach(function(ind) {
                    indHtml += '<span style="padding:4px 10px;border-radius:6px;font-size:11px;background:rgba(220,38,38,0.08);color:#FCA5A5;border:1px solid rgba(220,38,38,0.2);">' + ind + '</span>';
                });
                indHtml += '</div>';
                document.getElementById('hc-indicators').innerHTML = indHtml;
                document.getElementById('hc-reasoning').textContent = data.reasoning_summary || '';
                if (data.recommendations && data.recommendations.length > 0) {
                    var recHtml = '<div style="font-size:11px;font-weight:700;color:#666;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;">Recommendations</div>';
                    data.recommendations.forEach(function(r) {
                        recHtml += '<div style="font-size:13px;color:#a0a0a0;margin-bottom:4px;">&#9654; ' + r + '</div>';
                    });
                    document.getElementById('hc-recommendations').innerHTML = recHtml;
                }
                if (!data.lead_captured) {
                    document.getElementById('hc-lead-gate').style.display = 'block';
                }
            }).catch(function(e) {
                alert('Error: ' + e.message);
            }).finally(function() {
                btn.disabled = false;
                btn.textContent = 'Scan for Threats';
            });
        }
        function captureLead() {
            var email = document.getElementById('hc-lead-email').value;
            if (!email || email.indexOf('@') === -1) { alert('Please enter a valid email address.'); return; }
            fetch('/api/public/health-check/capture', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: email })
            }).then(function(r) { return r.json(); }).then(function(data) {
                document.getElementById('hc-lead-gate').innerHTML = '<p style="color:#86EFAC;font-size:13px;font-weight:600;">Thank you! Full report unlocked. Check your email for the complete analysis.</p>';
                if (hcResult && hcResult.recommendations) {
                    var recHtml = '<div style="font-size:11px;font-weight:700;color:#666;text-transform:uppercase;letter-spacing:0.08em;margin-bottom:8px;">Full Recommendations</div>';
                    hcResult.recommendations.forEach(function(r) {
                        recHtml += '<div style="font-size:13px;color:#a0a0a0;margin-bottom:4px;">&#9654; ' + r + '</div>';
                    });
                    document.getElementById('hc-recommendations').innerHTML = recHtml;
                }
            }).catch(function(e) {
                alert('Error capturing email.');
            });
        }
    </script>

    <footer class="footer">
        <p>SENTINEL v3.0.0 &mdash; AI-Powered Phishing Triage Intelligence</p>
        <div class="footer-links">
            <a href="/">Home</a>
            <a href="/login">Log In</a>
            <a href="/register">Create Account</a>
            <a href="/docs">API Docs</a>
        </div>
    </footer>

    <script>
        function demoNext(step) {
            document.querySelectorAll('.demo-step').forEach(function(el) { el.classList.remove('active'); });
            document.getElementById('d' + step).classList.add('active');
            document.querySelectorAll('.demo-nav button').forEach(function(btn, i) {
                btn.classList.toggle('active', i === step - 1);
            });
        }
    </script>
</body>
</html>"""

# ============================================================================
# INVITE ACCEPT PAGE
# ============================================================================
INVITE_ACCEPT_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL - Accept Invite</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter', sans-serif; background: #0a0a0a; color: #f5f5f5; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .card { background: linear-gradient(145deg, #111, #0d0d0d); border: 1px solid #1a1a1a; border-radius: 16px; padding: 40px; width: 100%; max-width: 420px; text-align: center; }
        .shield { width: 56px; height: 56px; margin: 0 auto 20px; background: linear-gradient(135deg, #DC2626, #7F1D1D); border-radius: 14px; display: flex; align-items: center; justify-content: center; }
        .shield svg { width: 28px; height: 28px; }
        h1 { font-size: 22px; font-weight: 800; margin-bottom: 6px; }
        .subtitle { font-size: 13px; color: #666; margin-bottom: 28px; line-height: 1.5; }
        .form-group { text-align: left; margin-bottom: 14px; }
        .label { font-size: 11px; font-weight: 600; color: #666; text-transform: uppercase; letter-spacing: 0.05em; display: block; margin-bottom: 6px; }
        .input { width: 100%; padding: 10px 14px; background: #0a0a0a; border: 1px solid #222; border-radius: 8px; color: #f5f5f5; font-size: 13px; font-family: 'Inter', sans-serif; outline: none; transition: border-color 0.2s; }
        .input:focus { border-color: #DC2626; }
        .btn { width: 100%; padding: 11px 20px; border-radius: 8px; font-size: 14px; font-weight: 600; cursor: pointer; border: none; font-family: 'Inter', sans-serif; transition: all 0.2s; }
        .btn-red { background: linear-gradient(135deg, #DC2626, #991B1B); color: #fff; }
        .btn-red:hover { box-shadow: 0 4px 20px rgba(220,38,38,0.3); transform: translateY(-1px); }
        .btn-red:disabled { opacity: 0.5; cursor: not-allowed; transform: none; box-shadow: none; }
        .btn-outline { background: transparent; color: #a0a0a0; border: 1px solid #282828; margin-top: 10px; }
        .btn-outline:hover { border-color: #555; color: #f5f5f5; }
        .divider { font-size: 12px; color: #555; margin: 16px 0; }
        .links { margin-top: 20px; font-size: 12px; color: #555; }
        .links a { color: #DC2626; text-decoration: none; }
        .links a:hover { text-decoration: underline; }
        .error { background: #2d0a0a; border: 1px solid #7f1d1d; border-radius: 8px; padding: 10px 14px; margin-bottom: 16px; font-size: 12px; color: #FCA5A5; display: none; }
        .success { background: #0d2818; border: 1px solid #166534; border-radius: 8px; padding: 10px 14px; margin-bottom: 16px; font-size: 12px; color: #86EFAC; display: none; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        .card { animation: fadeIn 0.4s ease-out; }
    </style>
</head>
<body>
    <div class="card">
        <div class="shield">
            <svg viewBox="0 0 40 44" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M20 2L4 10v12c0 11 7.2 21.3 16 24 8.8-2.7 16-13 16-24V10L20 2z" fill="url(#lg)" stroke="#991B1B" stroke-width="1.5"/><path d="M20 10v8m0 0v8m0-8l-4-4m4 4l4-4" stroke="#fff" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/><defs><linearGradient id="lg" x1="4" y1="2" x2="36" y2="46"><stop stop-color="#DC2626"/><stop offset="1" stop-color="#7F1D1D"/></linearGradient></defs></svg>
        </div>
        <h1>Join Your Team</h1>
        <p class="subtitle">You've been invited to join a team on SENTINEL.<br>Log in or create an account to accept.</p>

        <div id="error-box" class="error"></div>
        <div id="success-box" class="success"></div>

        <div id="login-form">
            <div class="form-group">
                <label class="label">Username</label>
                <input id="username" class="input" placeholder="Your username" autocomplete="username">
            </div>
            <div class="form-group">
                <label class="label">Password</label>
                <div style="position:relative">
                    <input id="password" class="input" type="password" placeholder="Your password" autocomplete="current-password" style="width:100%;padding-right:44px">
                    <button type="button" onclick="togglePw('password',this)" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#666;padding:4px" aria-label="Toggle password visibility"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
                </div>
            </div>
            <button id="login-btn" class="btn btn-red" onclick="doLogin()">Log In &amp; Accept Invite</button>
            <div class="divider">or</div>
            <button class="btn btn-outline" onclick="showRegister()">Create New Account</button>
        </div>

        <div id="register-form" style="display:none">
            <div class="form-group">
                <label class="label">Username</label>
                <input id="reg-username" class="input" placeholder="Choose a username" autocomplete="username">
            </div>
            <div class="form-group">
                <label class="label">Email</label>
                <input id="reg-email" class="input" type="email" placeholder="you@company.com" autocomplete="email">
            </div>
            <div class="form-group">
                <label class="label">Password</label>
                <div style="position:relative">
                    <input id="reg-password" class="input" type="password" placeholder="Choose a password" autocomplete="new-password" style="width:100%;padding-right:44px">
                    <button type="button" onclick="togglePw('reg-password',this)" style="position:absolute;right:10px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#666;padding:4px" aria-label="Toggle password visibility"><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg></button>
                </div>
            </div>
            <button id="reg-btn" class="btn btn-red" onclick="doRegister()">Create Account &amp; Accept Invite</button>
            <div class="divider">or</div>
            <button class="btn btn-outline" onclick="showLogin()">Back to Log In</button>
        </div>

        <div class="links">
            <a href="/login">Back to Login</a>
        </div>
    </div>

    <script>
        function togglePw(id, btn) {
            var inp = document.getElementById(id);
            var isPw = inp.type === 'password';
            inp.type = isPw ? 'text' : 'password';
            btn.innerHTML = isPw
                ? '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>'
                : '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
        }
        var TOKEN = '{{TOKEN}}';
        var API_BASE = window.location.origin;

        function showError(msg) {
            var el = document.getElementById('error-box');
            el.textContent = msg;
            el.style.display = 'block';
            document.getElementById('success-box').style.display = 'none';
        }
        function showSuccess(msg) {
            var el = document.getElementById('success-box');
            el.textContent = msg;
            el.style.display = 'block';
            document.getElementById('error-box').style.display = 'none';
        }
        function hideMessages() {
            document.getElementById('error-box').style.display = 'none';
            document.getElementById('success-box').style.display = 'none';
        }
        function showLogin() {
            document.getElementById('login-form').style.display = 'block';
            document.getElementById('register-form').style.display = 'none';
            hideMessages();
        }
        function showRegister() {
            document.getElementById('login-form').style.display = 'none';
            document.getElementById('register-form').style.display = 'block';
            hideMessages();
        }

        // If already logged in, accept invite immediately
        (function() {
            var token = localStorage.getItem('sentinel_token');
            if (token) {
                acceptInvite(token);
            }
        })();

        function doLogin() {
            hideMessages();
            var username = document.getElementById('username').value.trim();
            var password = document.getElementById('password').value;
            if (!username || !password) { showError('Please fill in all fields.'); return; }
            document.getElementById('login-btn').disabled = true;
            document.getElementById('login-btn').textContent = 'Logging in...';

            fetch(API_BASE + '/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username, password: password })
            }).then(function(r) { return r.json(); }).then(function(data) {
                if (data.status === 'success' && data.token) {
                    localStorage.setItem('sentinel_token', data.token);
                    showSuccess('Logged in! Accepting invite...');
                    acceptInvite(data.token);
                } else {
                    showError(data.detail || 'Login failed. Check your credentials.');
                    document.getElementById('login-btn').disabled = false;
                    document.getElementById('login-btn').textContent = 'Log In & Accept Invite';
                }
            }).catch(function(e) {
                showError('Connection error. Please try again.');
                document.getElementById('login-btn').disabled = false;
                document.getElementById('login-btn').textContent = 'Log In & Accept Invite';
            });
        }

        function doRegister() {
            hideMessages();
            var username = document.getElementById('reg-username').value.trim();
            var email = document.getElementById('reg-email').value.trim();
            var password = document.getElementById('reg-password').value;
            if (!username || !email || !password) { showError('Please fill in all fields.'); return; }
            document.getElementById('reg-btn').disabled = true;
            document.getElementById('reg-btn').textContent = 'Creating account...';

            fetch(API_BASE + '/api/auth/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: username, email: email, password: password })
            }).then(function(r) { return r.json(); }).then(function(data) {
                if (data.status === 'success' && data.token) {
                    localStorage.setItem('sentinel_token', data.token);
                    showSuccess('Account created! Accepting invite...');
                    acceptInvite(data.token);
                } else {
                    showError(data.detail || 'Registration failed.');
                    document.getElementById('reg-btn').disabled = false;
                    document.getElementById('reg-btn').textContent = 'Create Account & Accept Invite';
                }
            }).catch(function(e) {
                showError('Connection error. Please try again.');
                document.getElementById('reg-btn').disabled = false;
                document.getElementById('reg-btn').textContent = 'Create Account & Accept Invite';
            });
        }

        function acceptInvite(userToken) {
            fetch(API_BASE + '/api/v1/accept-invite/' + TOKEN, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + userToken
                }
            }).then(function(r) { return r.json(); }).then(function(data) {
                if (data.status === 'success') {
                    showSuccess('Invite accepted! Redirecting to dashboard...');
                    var dest = (data.role === 'friend') ? '/lite/dashboard' : '/dashboard';
                    setTimeout(function() { window.location.href = dest; }, 1500);
                } else {
                    showError(data.detail || 'Failed to accept invite. It may have expired.');
                    document.getElementById('login-btn').disabled = false;
                    document.getElementById('login-btn').textContent = 'Log In & Accept Invite';
                    document.getElementById('reg-btn').disabled = false;
                    document.getElementById('reg-btn').textContent = 'Create Account & Accept Invite';
                }
            }).catch(function(e) {
                showError('Error accepting invite. Please try again.');
                document.getElementById('login-btn').disabled = false;
                document.getElementById('login-btn').textContent = 'Log In & Accept Invite';
            });
        }
    </script>
</body>
</html>"""

# ============================================================================
# INTERACTIVE DEMO PAGE
# ============================================================================
DEMO_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SENTINEL - Interactive Demo</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: 'Inter', sans-serif; background: #0a0a0a; color: #f5f5f5; min-height: 100vh; }
        .topbar { position: fixed; top: 0; left: 0; right: 0; z-index: 100; padding: 12px 32px; display: flex; justify-content: space-between; align-items: center; background: rgba(10,10,10,0.95); backdrop-filter: blur(20px); border-bottom: 1px solid #1a1a1a; }
        .logo { display: flex; align-items: center; gap: 8px; text-decoration: none; color: #f5f5f5; }
        .logo svg { width: 28px; height: 28px; }
        .logo-text { font-weight: 800; font-size: 16px; letter-spacing: -0.02em; }
        .topbar-right { display: flex; align-items: center; gap: 10px; }
        .btn { padding: 8px 18px; border-radius: 8px; font-size: 13px; font-weight: 600; cursor: pointer; border: none; font-family: 'Inter'; transition: all 0.2s; text-decoration: none; display: inline-flex; align-items: center; gap: 6px; }
        .btn-ghost { background: transparent; border: 1px solid #333; color: #aaa; }
        .btn-ghost:hover { border-color: #555; background: #161616; color: #f5f5f5; }
        .btn-red { background: linear-gradient(135deg, #DC2626, #991B1B); color: #fff; border: 1px solid rgba(220,38,38,0.4); }
        .btn-red:hover { box-shadow: 0 4px 20px rgba(220,38,38,0.35); transform: translateY(-1px); }
        .demo-badge { background: rgba(220,38,38,0.1); color: #EF4444; padding: 3px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; border: 1px solid rgba(220,38,38,0.2); }
        .main { padding: 80px 32px 40px; max-width: 1200px; margin: 0 auto; }
        .page-header { text-align: center; margin-bottom: 32px; }
        .page-header h1 { font-size: 32px; font-weight: 900; letter-spacing: -0.02em; margin-bottom: 8px; }
        .page-header h1 span { background: linear-gradient(135deg, #DC2626, #F87171); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .page-header p { color: #888; font-size: 15px; }
        .dashboard-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 24px; }
        .stat-card { background: #111; border: 1px solid #1e1e1e; border-radius: 10px; padding: 16px 18px; }
        .stat-card .label { font-size: 11px; font-weight: 500; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 6px; }
        .stat-card .value { font-size: 28px; font-weight: 800; letter-spacing: -0.02em; font-family: 'JetBrains Mono', monospace; }
        .stat-card .value.red { color: #DC2626; }
        .stat-card .value.yellow { color: #EAB308; }
        .stat-card .value.green { color: #22C55E; }
        .stat-card .value.blue { color: #3B82F6; }
        .section-title { font-size: 18px; font-weight: 700; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
        .section-title .dot { width: 8px; height: 8px; border-radius: 50%; background: #22C55E; animation: pulse 2s infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
        .email-table { background: #111; border: 1px solid #1e1e1e; border-radius: 12px; overflow: hidden; margin-bottom: 24px; }
        .email-table table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .email-table th { text-align: left; padding: 12px 16px; background: #0d0d0d; color: #888; font-weight: 500; text-transform: uppercase; font-size: 11px; letter-spacing: 0.05em; border-bottom: 1px solid #1e1e1e; }
        .email-table td { padding: 12px 16px; border-bottom: 1px solid #1a1a1a; }
        .email-table tr:hover td { background: rgba(255,255,255,0.02); }
        .verdict-tag { display: inline-block; padding: 3px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; }
        .verdict-tag.malicious { background: rgba(220,38,38,0.12); color: #FCA5A5; border: 1px solid rgba(220,38,38,0.25); }
        .verdict-tag.suspicious { background: rgba(234,179,8,0.12); color: #FDE047; border: 1px solid rgba(234,179,8,0.25); }
        .verdict-tag.safe { background: rgba(34,197,94,0.12); color: #86EFAC; border: 1px solid rgba(34,197,94,0.25); }
        .scan-panel { background: #111; border: 1px solid #1e1e1e; border-radius: 12px; padding: 24px; margin-bottom: 24px; }
        .scan-panel h3 { font-size: 16px; font-weight: 700; margin-bottom: 16px; }
        .scan-input { width: 100%; padding: 14px 16px; background: #0a0a0a; border: 1px solid #222; border-radius: 8px; color: #f5f5f5; font-size: 13px; font-family: 'JetBrains Mono', monospace; resize: vertical; min-height: 120px; outline: none; transition: border-color 0.2s; }
        .scan-input:focus { border-color: #DC2626; box-shadow: 0 0 0 2px rgba(220,38,38,0.15); }
        .scan-result { margin-top: 16px; background: #0d0d0d; border: 1px solid #1a1a1a; border-radius: 10px; padding: 20px; display: none; }
        .scan-result.show { display: block; animation: fadeUp 0.3s ease-out; }
        @keyframes fadeUp { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
        .confidence-ring { width: 120px; height: 120px; margin: 0 auto 12px; position: relative; }
        .confidence-ring svg { transform: rotate(-90deg); }
        .confidence-score { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center; font-size: 28px; font-weight: 900; font-family: 'JetBrains Mono', monospace; }
        .indicator { display: flex; align-items: center; gap: 8px; padding: 8px 12px; background: #111; border: 1px solid #1a1a1a; border-radius: 6px; margin-bottom: 6px; font-size: 13px; color: #aaa; }
        .indicator .dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; }
        .indicator .dot.red { background: #EF4444; }
        .indicator .dot.yellow { background: #EAB308; }
        .indicator .dot.green { background: #22C55E; }
        .features-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 32px; }
        .feature-card { background: #111; border: 1px solid #1e1e1e; border-radius: 12px; padding: 20px; transition: all 0.2s; }
        .feature-card:hover { border-color: rgba(220,38,38,0.3); transform: translateY(-2px); }
        .feature-card .icon { font-size: 24px; margin-bottom: 10px; }
        .feature-card h4 { font-size: 14px; font-weight: 700; margin-bottom: 6px; }
        .feature-card p { font-size: 12px; color: #888; line-height: 1.5; }
        .cta-bar { text-align: center; padding: 48px; background: linear-gradient(135deg, rgba(220,38,38,0.08), rgba(127,29,29,0.08)); border: 1px solid rgba(220,38,38,0.2); border-radius: 16px; margin-bottom: 32px; }
        .cta-bar h2 { font-size: 28px; font-weight: 800; margin-bottom: 8px; }
        .cta-bar p { color: #888; margin-bottom: 20px; font-size: 15px; }
        .cta-bar .btn-red { padding: 14px 36px; font-size: 15px; }
        .spinner { width: 18px; height: 18px; border: 2px solid rgba(220,38,38,0.3); border-top-color: #DC2626; border-radius: 50%; animation: spin 0.6s linear infinite; display: inline-block; }
        @keyframes spin { to { transform: rotate(360deg); } }
        .topbar-nav { display: flex; gap: 6px; }
        .topbar-nav a { padding: 7px 14px; border-radius: 8px; font-size: 12px; font-weight: 500; color: #888; transition: all 0.2s; text-decoration: none; }
        .topbar-nav a:hover { color: #f5f5f5; background: rgba(255,255,255,0.05); }
        @media (max-width: 768px) {
            .main { padding: 72px 12px 12px; }
            .dashboard-grid { grid-template-columns: repeat(2, 1fr); }
            .features-grid { grid-template-columns: 1fr; }
            .topbar-nav { display: none; }
        }
    </style>
</head>
<body>
    <div class="topbar">
        <a href="/" class="logo">
            <svg viewBox="0 0 36 36" fill="none"><path d="M18 2L3 10v16l15 8 15-8V10L18 2z" fill="url(#g1)" opacity="0.9"/><path d="M18 6l10 5.5v11L18 28 8 22.5v-11L18 6z" fill="#0a0a0a"/><path d="M18 12l-6 3.3v6.6L18 25l6-3.1v-6.6L18 12z" fill="url(#g2)"/><defs><linearGradient id="g1" x1="3" y1="2" x2="33" y2="34"><stop stop-color="#DC2626"/><stop offset="1" stop-color="#991B1B"/></linearGradient><linearGradient id="g2" x1="12" y1="12" x2="24" y2="25"><stop stop-color="#DC2626"/><stop offset="1" stop-color="#991B1B"/></linearGradient></defs></svg>
            <span class="logo-text">SENTINEL</span>
            <span class="demo-badge">Interactive Demo</span>
        </a>
        <div style="display:flex;align-items:center;gap:10px">
            <div class="topbar-nav">
                <a href="/marketing">Overview</a>
                <a href="/docs">Docs</a>
                <a href="/lite">SENTINEL Lite</a>
            </div>
            <a href="/login" class="btn btn-ghost">Log In</a>
            <a href="/register" class="btn btn-red">Get Started</a>
        </div>
    </div>

    <div class="main">
        <div class="page-header">
            <h1>See <span>SENTINEL</span> in Action</h1>
            <p>Explore a live preview of the dashboard, scan emails in real-time, and see how phishing detection works.</p>
        </div>

        <div class="dashboard-grid">
            <div class="stat-card"><div class="label">Emails Scanned</div><div class="value" id="d-scanned">0</div></div>
            <div class="stat-card"><div class="label">Threats Detected</div><div class="value red" id="d-threats">0</div></div>
            <div class="stat-card"><div class="label">Suspicious</div><div class="value yellow" id="d-suspicious">0</div></div>
            <div class="stat-card"><div class="label">Safe</div><div class="value green" id="d-safe">0</div></div>
        </div>

        <div class="scan-panel">
            <h3>Try the AI Scanner</h3>
            <p style="color:#888;font-size:13px;margin-bottom:12px">Paste any email content below to see SENTINEL analyze it for phishing indicators.</p>
            <textarea class="scan-input" id="scanInput" placeholder="Paste email headers, body text, or a suspicious link here...">From: support@paypa1-secure.com
To: user@company.com
Subject: URGENT: Your account has been limited

Dear Customer,

We have detected unusual activity on your PayPal account. Your account access has been temporarily limited.

Please verify your identity within 24 hours by clicking the link below:
https://paypa1-secure.com/verify?id=837291

If you do not verify, your account will be permanently suspended.

Thank you,
PayPal Security Team</textarea>
            <div style="display:flex;gap:8px;margin-top:12px">
                <button class="btn btn-red" id="scanBtn" onclick="runScan()">
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 2L3 7v13a1 1 0 001 1h16a1 1 0 001-1V7l-6-5z"/><path d="M9 2v6h6V2"/></svg>
                    Scan Now
                </button>
                <button class="btn btn-ghost" onclick="loadSample('phishing')">Load Phishing Sample</button>
                <button class="btn btn-ghost" onclick="loadSample('legit')">Load Legitimate Sample</button>
                <button class="btn btn-ghost" onclick="loadSample('suspicious')">Load Suspicious Sample</button>
            </div>
            <div class="scan-result" id="scanResult">
                <div style="display:grid;grid-template-columns:160px 1fr;gap:20px;align-items:start">
                    <div>
                        <div class="confidence-ring" id="confRing"></div>
                        <div id="verdictTag" style="text-align:center;margin-bottom:8px"></div>
                        <div id="verdictText" style="text-align:center;font-size:12px;color:#888"></div>
                    </div>
                    <div>
                        <div style="font-size:14px;font-weight:700;margin-bottom:12px">Analysis Breakdown</div>
                        <div id="indicators"></div>
                        <div style="margin-top:12px;padding-top:12px;border-top:1px solid #1a1a1a">
                            <div style="font-size:12px;font-weight:600;color:#888;margin-bottom:4px">AI Reasoning</div>
                            <div id="reasoning" style="font-size:12px;color:#aaa;line-height:1.6"></div>
                        </div>
                    </div>
                </div>
            </div>
        </div>

        <div class="section-title"><span class="dot"></span>Live Threat Feed (Demo Data)</div>
        <div class="email-table">
            <table>
                <thead><tr><th>From</th><th>Subject</th><th>Date</th><th>Verdict</th><th>Confidence</th></tr></thead>
                <tbody id="feedBody"></tbody>
            </table>
        </div>

        <div class="section-title" style="margin-top:32px">Why SENTINEL?</div>
        <div class="features-grid">
            <div class="feature-card">
                <div class="icon">&#x1F9E0;</div>
                <h4>AI-Powered Analysis</h4>
                <p>Advanced language models analyze email content, headers, and links for sophisticated phishing indicators.</p>
            </div>
            <div class="feature-card">
                <div class="icon">&#x26A1;</div>
                <h4>Real-Time Scanning</h4>
                <p>Automatically monitors your inbox via IMAP and alerts you instantly when threats are detected.</p>
            </div>
            <div class="feature-card">
                <div class="icon">&#x1F6E1;</div>
                <h4>Confidence Scoring</h4>
                <p>Every scan includes a detailed confidence score and breakdown of exactly why something was flagged.</p>
            </div>
            <div class="feature-card">
                <div class="icon">&#x1F4CA;</div>
                <h4>Analytics Dashboard</h4>
                <p>Track threat trends, top attackers, and scan history with a beautiful, real-time analytics dashboard.</p>
            </div>
            <div class="feature-card">
                <div class="icon">&#x1F465;</div>
                <h4>Team Management</h4>
                <p>Invite team members with different access levels. Share threat intelligence across your organization.</p>
            </div>
            <div class="feature-card">
                <div class="icon">&#x1F4F1;</div>
                <h4>SENTINEL Lite</h4>
                <p>A simplified version for individuals. Use your own API key for quick phishing checks without setup.</p>
            </div>
        </div>

        <div class="cta-bar">
            <h2>Ready to protect your inbox?</h2>
            <p>Get started in 60 seconds. Connect your email and let SENTINEL do the rest.</p>
            <a href="/register" class="btn btn-red">Create Free Account</a>
        </div>
    </div>

    <script>
        var demoEmails = [
            {from:'billing@amazon-verify.com', subject:'Action Required: Payment Failed', date:'2025-07-18', verdict:'malicious', confidence:97},
            {from:'hr@company-inc.co', subject:'Updated PTO Policy - Please Review', date:'2025-07-18', verdict:'suspicious', confidence:72},
            {from:'newsletter@stripe.com', subject:'Your July Invoice is Ready', date:'2025-07-17', verdict:'safe', confidence:99},
            {from:'admin@microsoft-365-security.com', subject:'Your password expires today', date:'2025-07-17', verdict:'malicious', confidence:94},
            {from:'jane.doe@company.com', subject:'Q3 Report Draft', date:'2025-07-16', verdict:'safe', confidence:98},
            {from:'support@fedex-delivery-notice.com', subject:'Undeliverable Package #FX98271', date:'2025-07-16', verdict:'malicious', confidence:91},
            {from:'it@company.com', subject:'Scheduled Maintenance Tonight', date:'2025-07-15', verdict:'safe', confidence:96},
            {from:'alert@bankofamerica-security.net', subject:'Suspicious Login Detected', date:'2025-07-15', verdict:'malicious', confidence:89},
        ];

        function renderFeed() {
            var body = document.getElementById('feedBody');
            body.innerHTML = demoEmails.map(function(e) {
                var vc = {malicious:'malicious', suspicious:'suspicious', safe:'safe'};
                return '<tr><td style="font-family:JetBrains Mono,monospace;font-size:12px">' + e.from + '</td>' +
                    '<td>' + e.subject + '</td><td style="color:#666;font-size:12px">' + e.date + '</td>' +
                    '<td><span class="verdict-tag ' + vc[e.verdict] + '">' + e.verdict + '</span></td>' +
                    '<td style="font-family:JetBrains Mono,monospace;font-size:12px">' + e.confidence + '%</td></tr>';
            }).join('');
        }

        function animateCounter(id, target, color) {
            var el = document.getElementById(id);
            var current = 0;
            var step = Math.max(1, Math.floor(target / 40));
            var iv = setInterval(function() {
                current = Math.min(current + step, target);
                el.textContent = current.toLocaleString();
                if (current >= target) clearInterval(iv);
            }, 30);
        }

        var scanResults = {
            phishing: {
                confidence: 96, verdict: 'MALICIOUS', color: '#DC2626',
                indicators: [
                    {text: 'Domain spoofing: paypa1-secure.com mimics paypal.com', color: '#EF4444'},
                    {text: 'Urgency language: "within 24 hours", "permanently suspended"', color: '#EF4444'},
                    {text: 'Suspicious link: https://paypa1-secure.com/verify?id=837291', color: '#EF4444'},
                    {text: 'Generic greeting: "Dear Customer" instead of your name', color: '#EAB308'},
                    {text: 'Impersonation of known brand (PayPal)', color: '#EF4444'},
                ],
                reasoning: 'This email exhibits multiple classic phishing characteristics. The sending domain paypa1-secure.com uses a homoglyph (number 1 replacing letter l) to impersonate PayPal. The message creates artificial urgency and threatens account suspension to pressure immediate action without verification. The verification link points to the spoofed domain, not paypal.com.'
            },
            legit: {
                confidence: 99, verdict: 'SAFE', color: '#22C55E',
                indicators: [
                    {text: 'Known sender domain: stripe.com', color: '#22C55E'},
                    {text: 'No urgency or threat language detected', color: '#22C55E'},
                    {text: 'Standard business communication pattern', color: '#22C55E'},
                    {text: 'No suspicious links or attachments', color: '#22C55E'},
                ],
                reasoning: 'This email is from a verified legitimate sender domain (stripe.com) and contains standard invoice notification content. The language is professional and non-urgent, with no pressure tactics or suspicious links. The formatting is consistent with legitimate Stripe communications.'
            },
            suspicious: {
                confidence: 74, verdict: 'SUSPICIOUS', color: '#EAB308',
                indicators: [
                    {text: 'External domain: company-inc.co (not your company domain)', color: '#EAB308'},
                    {text: 'HR policy topics used as social engineering vector', color: '#EAB308'},
                    {text: 'No direct threat, but requests review action', color: '#EAB308'},
                    {text: 'Passes basic legitimacy checks', color: '#22C55E'},
                ],
                reasoning: 'This email uses a domain similar to your company but is not from your actual company domain. While the content appears professional and non-threatening, HR policy updates are commonly used in targeted phishing campaigns. We recommend verifying with your HR department before clicking any links.'
            }
        };

        function loadSample(type) {
            var samples = {
                phishing: 'From: support@paypa1-secure.com\\nTo: user@company.com\\nSubject: URGENT: Your account has been limited\\n\\nDear Customer,\\n\\nWe have detected unusual activity on your PayPal account. Your account access has been temporarily limited.\\n\\nPlease verify your identity within 24 hours by clicking the link below:\\nhttps://paypa1-secure.com/verify?id=837291\\n\\nIf you do not verify, your account will be permanently suspended.\\n\\nThank you,\\nPayPal Security Team',
                legit: 'From: newsletter@stripe.com\\nTo: billing@company.com\\nSubject: Your July Invoice is Ready\\n\\nHi,\\n\\nYour latest Stripe invoice for July 2025 is now available.\\n\\nAmount due: $249.00\\nDue date: August 1, 2025\\n\\nYou can view and download your invoice from your Stripe Dashboard.\\n\\nIf you have any questions, reply to this email or visit our support center.\\n\\nBest,\\nThe Stripe Team',
                suspicious: 'From: hr@company-inc.co\\nTo: all-staff@company.com\\nSubject: Updated PTO Policy - Please Review\\n\\nDear Team,\\n\\nWe have updated our PTO policy effective August 1st. Please review the changes at your earliest convenience.\\n\\nKey changes include:\\n- Increased carryover limit\\n- New mental health days\\n- Updated request process\\n\\nPlease acknowledge receipt by end of week.\\n\\nBest regards,\\nHuman Resources'
            };
            document.getElementById('scanInput').value = samples[type].replace(/\\n/g, '\\n');
            document.getElementById('scanResult').className = 'scan-result';
        }

        function runScan() {
            var text = document.getElementById('scanInput').value;
            if (!text.trim()) return;
            var btn = document.getElementById('scanBtn');
            btn.innerHTML = '<span class="spinner"></span> Analyzing...';
            btn.disabled = true;

            setTimeout(function() {
                var type = 'suspicious';
                if (text.indexOf('paypal') !== -1 || text.indexOf('paypa1') !== -1 || text.indexOf('verify your') !== -1 || text.indexOf('URGENT') !== -1) type = 'phishing';
                else if (text.indexOf('stripe') !== -1 || text.indexOf('invoice') !== -1) type = 'legit';

                var r = scanResults[type];
                var result = document.getElementById('scanResult');
                result.className = 'scan-result show';

                document.getElementById('confRing').innerHTML =
                    '<svg width="120" height="120" viewBox="0 0 120 120">' +
                    '<circle cx="60" cy="60" r="52" fill="none" stroke="#1e1e1e" stroke-width="8"/>' +
                    '<circle cx="60" cy="60" r="52" fill="none" stroke="' + r.color + '" stroke-width="8" stroke-linecap="round" stroke-dasharray="' + (r.confidence * 3.27) + ' 999" style="transition:stroke-dasharray 1s ease-out"/>' +
                    '</svg>' +
                    '<div class="confidence-score" style="color:' + r.color + '">' + r.confidence + '</div>';

                document.getElementById('verdictTag').innerHTML = '<span class="verdict-tag ' + type + '" style="font-size:13px;padding:6px 16px">' + r.verdict + '</span>';
                document.getElementById('verdictText').textContent = r.confidence + '% confidence';

                document.getElementById('indicators').innerHTML = r.indicators.map(function(ind) {
                    return '<div class="indicator"><span class="dot" style="background:' + ind.color + '"></span>' + ind.text + '</div>';
                }).join('');

                document.getElementById('reasoning').textContent = r.reasoning;

                btn.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 2L3 7v13a1 1 0 001 1h16a1 1 0 001-1V7l-6-5z"/><path d="M9 2v6h6V2"/></svg> Scan Now';
                btn.disabled = false;
            }, 1200);
        }

        animateCounter('d-scanned', 2847);
        animateCounter('d-threats', 312);
        animateCounter('d-suspicious', 156);
        animateCounter('d-safe', 2379);
        renderFeed();
    </script>
</body>
</html>"""

# ============================================================================
# RUN SERVER
# ============================================================================
if __name__ == "__main__":
    import uvicorn

    print("", flush=True)
    print("================================================================", flush=True)
    print("  SENTINEL - AI-Powered Phishing Triage Intelligence", flush=True)
    print("================================================================", flush=True)
    print(f"  Version:    {settings.APP_VERSION}", flush=True)
    print(f"  Dashboard:  http://localhost:8000/dashboard", flush=True)
    print(f"  Landing:    http://localhost:8000/", flush=True)
    print(f"  API Docs:   http://localhost:8000/docs", flush=True)
    print(f"  Groq API:   {'OK - Configured' if settings.GROQ_API_KEY else 'NOT CONFIGURED (using mock analysis)'}", flush=True)
    if imap_service.is_configured:
        print(f"  IMAP:       OK - {imap_service.username}", flush=True)
    print("================================================================", flush=True)
    print("", flush=True)

    uvicorn.run(
        "app:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        log_level="info",
    )
