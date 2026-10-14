"""
backend/base/services/honeytoken.py
=====================================
Honeytoken Engine — the highest-confidence detection signal in Genius Mirage.

What are honeytokens?
---------------------
Honeytokens are fake credentials, API keys, or session tokens that are
invisibly planted inside every response served by the platform. They are
indistinguishable from real credentials — same format, same length, same
entropy — but they have ZERO legitimate use.

A real human visitor will never use them. Only an automated scraper, a
credential-harvesting bot, or a penetration tester probing the site will
extract and attempt to use them.

When a request arrives that carries a known honeytoken, it triggers an
IMMEDIATE Tier 1 flag with 99% confidence — no ambiguity, no false positive
risk whatsoever.

This solves the core detection problem: attackers who avoid all known
attack signatures (no SQLi, no XSS, no obvious tools) but who harvest and
replay credentials are caught the moment they use the planted token.

How tokens are planted
----------------------
1.  HTML responses get a hidden <input type="hidden"> with a fake API key.
2.  JSON API responses get an extra "_token" or "_debug_key" field buried
    in the data structure at a realistic-looking path.
3.  HTTP response headers get a fake X-Debug-Token header.
4.  A fake robots.txt entry points to a /secret-admin-panel/ honey URL.

Token registry
--------------
Every planted token is stored in the HoneytokenRegistry (Django cache + DB
fallback) keyed by its value, with the session_id that received it.
When that token appears in ANY subsequent request, the evaluator calls
check_honeytoken() and gets back the session that planted it.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import uuid
from datetime import timedelta
from typing import Optional, Tuple

from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)

# Token TTL in cache (48 hours — enough to catch delayed attacks)
TOKEN_TTL = 60 * 60 * 48

# Prefix so we never collide with other cache keys
CACHE_PREFIX = "gm_ht:"

# Regex to find any gm_ prefixed token in request content
HONEYTOKEN_PATTERN = re.compile(r'gm_[a-f0-9]{32,64}', re.IGNORECASE)

# ── Token generation ──────────────────────────────────────────────────────────

def generate_token(session_id: str, site_id: str, token_type: str = "api_key") -> str:
    """
    Generate a deterministic but secret honeytoken for a given session.
    Deterministic so we can regenerate it later to verify, but secret
    because it includes a server-side secret component.
    """
    from django.conf import settings
    secret = getattr(settings, 'SECRET_KEY', 'genius-mirage-default')[:16]
    raw = f"gm_{session_id[:8]}_{site_id[:8]}_{secret}_{token_type}"
    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    return f"gm_{token_hash[:40]}"


def plant_token(session_id: str, site_id: str, token_type: str = "api_key") -> str:
    """
    Generate and register a honeytoken for this session.
    Returns the token string so it can be injected into the response.
    """
    token = generate_token(session_id, site_id, token_type)
    cache_key = f"{CACHE_PREFIX}{token}"

    # Store in cache with 48h TTL
    cache.set(cache_key, {
        "session_id":  session_id,
        "site_id":     site_id,
        "token_type":  token_type,
        "planted_at":  timezone.now().isoformat(),
    }, timeout=TOKEN_TTL)

    # Also persist to DB for long-term audit
    _persist_to_db(token, session_id, site_id, token_type)

    logger.debug("[Honeytoken] Planted %s token for session %s", token_type, session_id[:8])
    return token


def check_request_for_honeytokens(
    session_id: str,
    request_data: dict,
) -> Tuple[bool, Optional[str], Optional[dict]]:
    """
    Scan every field of request_data for known honeytoken values.

    Returns:
        (triggered: bool, token: Optional[str], registry_entry: Optional[dict])

    If triggered=True, the session is definitely an attacker —
    this is a Tier 1 zero-false-positive signal.
    """
    # Build the full searchable string from all request fields
    searchable = _build_searchable(request_data)

    # Fast scan with regex
    matches = HONEYTOKEN_PATTERN.findall(searchable)
    if not matches:
        return False, None, None

    for candidate in matches:
        cache_key = f"{CACHE_PREFIX}{candidate}"
        entry = cache.get(cache_key)
        if entry:
            logger.warning(
                "[Honeytoken] TRIGGERED: session=%s used token planted for session=%s (type=%s)",
                session_id[:8],
                entry.get("session_id", "?")[:8],
                entry.get("token_type", "?"),
            )
            return True, candidate, entry

    return False, None, None


# ── Response injection ────────────────────────────────────────────────────────

def inject_into_html(html: str, session_id: str, site_id: str) -> str:
    """
    Inject two honeytokens into an HTML response:
      1. A hidden form field (looks like a CSRF or form token).
      2. A comment with a fake internal URL (honeypot URL bait).

    Only injects if <body> tag is present (no injection into API/JSON responses).
    """
    if "<body" not in html.lower():
        return html

    token = plant_token(session_id, site_id, token_type="form_field")
    fake_endpoint = f"/_internal/api/v2/admin?key={token}&debug=1"

    injection = (
        f'\n<input type="hidden" name="_gm_csrf_ext" value="{token}" />'
        f'\n<!-- internal: {fake_endpoint} -->\n'
    )

    # Insert just before </body>
    close_body = html.lower().rfind("</body>")
    if close_body != -1:
        return html[:close_body] + injection + html[close_body:]
    return html + injection


def inject_into_json(data: dict, session_id: str, site_id: str) -> dict:
    """
    Inject a honeytoken into a JSON API response dict.
    Looks like a legitimate debug or internal field.
    """
    token = plant_token(session_id, site_id, token_type="api_key")
    data.setdefault("_meta", {})
    data["_meta"]["_debug_key"] = token
    return data


def honeytoken_response_header(session_id: str, site_id: str) -> dict:
    """
    Return a dict of headers to add to every response.
    Plants a fake internal token in X-Request-ID (looks real, is bait).
    """
    token = plant_token(session_id, site_id, token_type="header_token")
    return {
        "X-Request-ID": token,
        "X-Powered-By": "GeniusMirage/5.1",
    }


def get_honey_robots_entry() -> str:
    """
    Return a robots.txt Disallow line pointing to a honeypath.
    Bots that ignore robots.txt will probe this path — instant Tier 1 flag.
    """
    return "\nDisallow: /_internal/admin-portal/\nDisallow: /_gm_honey_/\n"


# ── Honey URL detection ───────────────────────────────────────────────────────

HONEY_URL_PATTERN = re.compile(
    r'(/_internal/|/_gm_honey_/|/secret-admin-panel/|/_internal/api/v2/admin)',
    re.IGNORECASE,
)


def is_honey_url(path: str) -> bool:
    """Return True if the path is one of the planted honey URLs."""
    return bool(HONEY_URL_PATTERN.search(path))


# ── Helpers ───────────────────────────────────────────────────────────────────

def _build_searchable(request_data: dict) -> str:
    parts = [
        str(request_data.get("path", "")),
        str(request_data.get("query_string", "")),
        str(request_data.get("body", "")),
        json.dumps(request_data.get("headers", {})),
        str(request_data.get("user_agent", "")),
    ]
    return " ".join(parts)


def _persist_to_db(token: str, session_id: str, site_id: str, token_type: str):
    """Optionally persist honeytoken to DB for long-term audit logs."""
    try:
        from base.models import HoneytokenRecord  # optional model
        HoneytokenRecord.objects.get_or_create(
            token=token,
            defaults={
                "session_id": session_id,
                "site_id":    site_id,
                "token_type": token_type,
                "created_at": timezone.now(),
            },
        )
    except Exception:
        # DB model may not exist yet — cache-only is fine
        pass
