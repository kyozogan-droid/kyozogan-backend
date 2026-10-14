"""
services/global_ai_analyzer.py  (v5.1)
=======================================
AI-powered threat analyser for Genius Mirage.

Changes from v5.0
-----------------
* analyze_session() now accepts extra_context parameter so the caller
  (threat_evaluator Tier 3) can pass behavioral entropy signals into
  the Groq prompt, giving the AI much richer context to reason from.
* Prompt includes site profile "suspicious_signals" field explicitly
  so Groq knows what's site-specifically suspicious vs. universally bad.
* Session prompt now includes error rate, path diversity, and timing
  signals extracted from activity logs.
"""

import json
import logging
import os
import re
import traceback
from typing import Dict, List, Optional

from django.conf import settings
from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)


# ── Provider-aware AI client resolution ─────────────────────────────────────
# Admin panel (System Settings → AI Integration) can switch between Groq and
# OpenAI, and set a model name per provider, without a redeploy. Everything
# below resolves whichever provider is currently configured; _groq_client()
# and MODEL are kept as names for backward compatibility with existing call
# sites in this file and in views.py, but both are now provider-aware rather
# than Groq-only.

_DEFAULT_MODEL = {'groq': 'llama-3.3-70b-versatile', 'openai': 'gpt-4o-mini'}


def _resolve_ai_settings() -> dict:
    """
    Returns {'provider': 'groq'|'openai', 'model': str, 'api_key': str}.
    Admin-configured values (System Settings) take priority over environment
    variables, so changing them in the admin panel doesn't require a redeploy.
    """
    provider = 'groq'
    model = ''
    groq_key = ''
    openai_key = ''
    try:
        from base.models import SystemSettings
        obj = SystemSettings.objects.filter(pk=1).first()
        if obj:
            provider = obj.ai_provider or 'groq'
            model = (obj.ai_model or '').strip()
            groq_key = obj.groq_api_key or ''
            openai_key = obj.openai_api_key or ''
    except Exception:
        # DB not ready yet (e.g. during initial migrate) — fall through to env vars
        pass

    if not model:
        model = _DEFAULT_MODEL.get(provider, _DEFAULT_MODEL['groq'])

    if provider == 'openai':
        api_key = openai_key or os.environ.get('OPENAI_API_KEY') or getattr(settings, 'OPENAI_API_KEY', '')
    else:
        api_key = groq_key or os.environ.get('GROQ_API_KEY') or getattr(settings, 'GROQ_API_KEY', '')

    return {'provider': provider, 'model': model, 'api_key': api_key}


def _resolve_groq_api_key() -> str:
    """Kept for backward compatibility — returns the active provider's key
    (despite the name), since views.py's test endpoint imports this directly.
    Prefer _resolve_ai_settings() in new code."""
    return _resolve_ai_settings()['api_key']


def _groq_client():
    """Returns an OpenAI-SDK-compatible client (.chat.completions.create(...))
    for whichever provider is currently configured. Groq's own Python SDK
    mirrors OpenAI's client interface, so callers don't need to branch."""
    cfg = _resolve_ai_settings()
    if not cfg['api_key']:
        raise RuntimeError(
            f"No {cfg['provider'].upper()} API key configured. Set one in the admin panel "
            f"(System Settings → AI Integration), or via the "
            f"{'OPENAI_API_KEY' if cfg['provider'] == 'openai' else 'GROQ_API_KEY'} environment variable."
        )
    if cfg['provider'] == 'openai':
        from openai import OpenAI
        return OpenAI(api_key=cfg['api_key'])
    from groq import Groq
    return Groq(api_key=cfg['api_key'])


def _current_model() -> str:
    """Call this at the point of use, every time — not module-import time —
    so a model/provider change in the admin panel takes effect on the very
    next AI call, with no redeploy. (A module-level MODEL = "..." constant
    would freeze whatever System Settings said at import time, which for a
    JSON-serialized API payload can't be worked around with a str subclass:
    json.dumps() reads a str's underlying buffer directly rather than
    calling __str__(), so such a proxy would silently stay stale forever.)"""
    return _resolve_ai_settings()['model']


# Kept only for any external code/tests that import MODEL directly for
# display purposes. Reflects the *default* model, not necessarily the one
# actually in use — call _current_model() for the live value.
MODEL = _DEFAULT_MODEL['groq']


# ═══════════════════════════════════════════════════════════════════════════════
# SITE PROFILER  (unchanged from v5.0)
# ═══════════════════════════════════════════════════════════════════════════════

def profile_site(site) -> Dict:
    from base.models import SiteProfile
    profile, _ = SiteProfile.objects.get_or_create(site=site)
    profile.status = 'profiling'
    profile.save(update_fields=['status'])

    pages_text, pages_crawled, crawl_error = _crawl_site(site.domain)

    if not pages_text:
        profile.status      = 'failed'
        profile.crawl_error = crawl_error or 'Could not fetch any pages'
        profile.save()
        return {'status': 'failed', 'error': profile.crawl_error}

    prompt = _build_profile_prompt(site.domain, pages_text)

    try:
        client   = _groq_client()
        response = client.chat.completions.create(
            model=_current_model(),
            messages=[
                {
                    'role': 'system',
                    'content': (
                        'You are a cybersecurity AI that analyses websites to understand '
                        'their purpose and build a behavioural baseline. '
                        'You respond ONLY with valid JSON — no markdown, no explanation outside the JSON.'
                    ),
                },
                {'role': 'user', 'content': prompt},
            ],
            temperature=0.2,
            max_tokens=1200,
        )
        raw  = response.choices[0].message.content.strip()
        data = _safe_json(raw)
    except Exception as exc:
        profile.status      = 'failed'
        profile.crawl_error = f'Groq error: {exc}'
        profile.save()
        return {'status': 'failed', 'error': profile.crawl_error}

    profile.status             = 'ready'
    profile.site_purpose       = data.get('site_purpose', '')
    profile.site_type          = data.get('site_type', '')
    profile.expected_paths     = data.get('expected_paths', [])
    profile.normal_actions     = data.get('normal_actions', [])
    profile.suspicious_signals = data.get('suspicious_signals', [])
    profile.sensitive_areas    = data.get('sensitive_areas', [])
    profile.raw_ai_response    = raw
    profile.pages_crawled      = pages_crawled
    profile.crawl_error        = ''
    profile.save()

    return {'status': 'ready', **data}


def _crawl_site(domain: str) -> tuple:
    import requests
    from html.parser import HTMLParser

    class _TextExtractor(HTMLParser):
        def __init__(self):
            super().__init__()
            self._chunks = []
            self._skip   = False

        def handle_starttag(self, tag, attrs):
            if tag in ('script', 'style', 'noscript'):
                self._skip = True

        def handle_endtag(self, tag):
            if tag in ('script', 'style', 'noscript'):
                self._skip = False

        def handle_data(self, data):
            if not self._skip:
                text = data.strip()
                if text:
                    self._chunks.append(text)

        def get_text(self):
            return ' '.join(self._chunks)

    is_local = any(x in domain for x in ('localhost', '127.0.0.1'))
    base_url  = f"{'http' if is_local else 'https'}://{domain}"
    session   = requests.Session()
    session.headers['User-Agent'] = 'GeniusMirage-Profiler/1.0'

    pages_text    = []
    pages_crawled = 0
    error         = ''
    urls_to_visit = [base_url + '/']
    visited       = set()

    while urls_to_visit and pages_crawled < 5:
        url = urls_to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)
        try:
            try:
                resp = session.get(url, timeout=8, verify=True, allow_redirects=True)
            except requests.exceptions.SSLError:
                import warnings, urllib3
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)
                    resp = session.get(url, timeout=8, verify=False, allow_redirects=True)
            if resp.status_code != 200:
                continue
            parser = _TextExtractor()
            parser.feed(resp.text)
            text = parser.get_text()[:3000]
            if text:
                pages_text.append(f"[Page: {url}]\n{text}")
                pages_crawled += 1
            if pages_crawled == 1:
                links = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
                for link in links:
                    if link.startswith('/') and not link.startswith('//'):
                        full = base_url + link
                        if full not in visited:
                            urls_to_visit.append(full)
                    elif link.startswith(base_url):
                        if link not in visited:
                            urls_to_visit.append(link)
        except Exception as exc:
            error = str(exc)

    return '\n\n'.join(pages_text), pages_crawled, error


def _build_profile_prompt(domain: str, pages_text: str) -> str:
    return f"""I have crawled "{domain}". Page content:

---
{pages_text[:6000]}
---

Return ONLY this JSON (no markdown):

{{
  "site_purpose": "One or two sentence plain-English description.",
  "site_type": "One of: e-commerce, banking, healthcare, government, saas, blog, portfolio, forum, social, news, other",
  "expected_paths": ["url paths a normal user visits"],
  "normal_actions": ["what legitimate users do, e.g. browse products, submit contact form"],
  "suspicious_signals": [
    "behaviours suspicious FOR THIS SPECIFIC SITE, e.g. accessing /admin as regular visitor, submitting login form 20 times in 30 seconds"
  ],
  "sensitive_areas": ["/paths regular users should never access, e.g. /admin, /api/users"]
}}"""


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION ANALYSER  (updated with extra_context parameter)
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_session(
    session,
    activity_logs: List[Dict],
    site_profile=None,
    extra_context: str = "",      # ← NEW: receives behavioral entropy signals
) -> Dict:
    """
    Analyse a session using Groq.

    Parameters
    ----------
    session        : ActiveSession model instance
    activity_logs  : list of recent ActivityLog dicts
    site_profile   : SiteProfile instance (or None)
    extra_context  : optional string of additional signals (behavioral entropy,
                     timing analysis, etc.) to include in the prompt

    Returns dict with: risk_score, threat_level, flagged, techniques,
                       explanation, deception_strategy, confidence, ai_powered
    """
    cache_key = f'session_analysis:{session.session_id}'
    cached    = cache.get(cache_key)
    if cached:
        return cached

    profile_context = _format_profile(site_profile) if site_profile else (
        'No site profile available — evaluate purely from request patterns.'
    )

    # Build richer session statistics for the prompt
    session_stats = _compute_session_stats(activity_logs)

    prompt = _build_session_prompt(
        session, activity_logs, profile_context,
        session_stats, extra_context
    )

    try:
        client   = _groq_client()
        response = client.chat.completions.create(
            model=_current_model(),
            messages=[
                {
                    'role': 'system',
                    'content': (
                        'You are a cybersecurity threat-detection AI embedded in a deception platform. '
                        'You analyse HTTP session logs and decide whether a visitor is malicious. '
                        'You understand that sophisticated attackers can look exactly like normal users — '
                        'your job is to detect INTENT and BEHAVIOURAL PATTERNS, not just obvious signatures. '
                        'Pay close attention to: timing regularity (bots are consistent), '
                        'navigation patterns (bots scan uniformly), '
                        'site-specific suspicious signals, and the overall story told by the request sequence. '
                        'You respond ONLY with valid JSON. No markdown. No text outside the JSON.'
                    ),
                },
                {'role': 'user', 'content': prompt},
            ],
            temperature=0.2,
            max_tokens=800,
        )
        raw  = response.choices[0].message.content.strip()
        data = _safe_json(raw)

        result = {
            'risk_score':         int(data.get('risk_score', 0)),
            'threat_level':       data.get('threat_level', 'low'),
            'flagged':            data.get('flagged', False),
            'techniques':         data.get('techniques', []),
            'explanation':        data.get('explanation', ''),
            'deception_strategy': data.get('deception_strategy', 'monitor'),
            'confidence':         int(data.get('confidence', 50)),
            'ai_powered':         True,
        }

        cache.set(cache_key, result, timeout=180)
        return result

    except Exception as exc:
        # BUG FIX: this used to swallow every failure here and return
        # `_fallback_analysis(session)`, which defaults risk_score to 0
        # for any session with <=20 total interactions. That silently
        # suppressed Tier 3 scores to near-zero on the very common case of
        # "Groq unavailable" (no key configured, rate-limited, outage) —
        # actively making detection *worse* on AI failure instead of
        # falling back safely.
        #
        # Both actual callers already have their own correct handling for
        # this: threat_evaluator._check_tier3() catches it and runs
        # `_tier3_heuristic_fallback`, which properly factors in request
        # velocity and stacked technique count instead of just returning 0;
        # views.py's ai_session_analysis endpoint already catches
        # RuntimeError specifically (missing API key) and returns a 503.
        # Re-raising here lets those existing, better-designed fallbacks
        # actually run instead of this function pre-empting them.
        logger.warning('[AI analyser] Error: %s', exc)
        raise



def _compute_session_stats(logs: List[Dict]) -> Dict:
    """Extract summary statistics from activity logs for the AI prompt."""
    if not logs:
        return {}

    endpoints    = [l.get('endpoint', '') for l in logs if l.get('endpoint')]
    methods      = [l.get('method', 'GET') for l in logs]
    status_codes = [l.get('status_code', 200) for l in logs]
    scores       = [l.get('suspicion_score', 0) for l in logs if l.get('suspicion_score')]

    unique_paths  = set(endpoints)
    error_count   = sum(1 for s in status_codes if isinstance(s, int) and s >= 400)
    post_count    = methods.count('POST') + methods.count('PUT') + methods.count('DELETE')
    avg_score     = round(sum(scores) / len(scores), 1) if scores else 0
    max_score     = max(scores, default=0)

    return {
        'total_requests':  len(logs),
        'unique_paths':    len(unique_paths),
        'unique_ratio':    round(len(unique_paths) / max(len(endpoints), 1), 2),
        'error_count':     error_count,
        'error_rate':      round(error_count / max(len(logs), 1), 2),
        'mutation_count':  post_count,
        'avg_susp_score':  avg_score,
        'max_susp_score':  max_score,
        'top_paths':       list(unique_paths)[:8],
    }


def _format_profile(profile) -> str:
    if profile is None or profile.status != 'ready':
        return 'Site profile not yet available.'
    return (
        f"SITE PROFILE FOR {profile.site.domain}:\n"
        f"Purpose: {profile.site_purpose}\n"
        f"Type: {profile.site_type}\n"
        f"Normal paths: {json.dumps(profile.expected_paths)}\n"
        f"Normal user actions: {json.dumps(profile.normal_actions)}\n"
        f"Site-specific suspicious signals: {json.dumps(profile.suspicious_signals)}\n"
        f"Sensitive areas (should NEVER be accessed by regular users): {json.dumps(profile.sensitive_areas)}"
    )


def _build_session_prompt(session, logs, profile_context,
                           session_stats: Dict, extra_context: str) -> str:
    log_lines = []
    for log in logs[-30:]:
        log_lines.append(
            f"  {log.get('timestamp','?')} | {log.get('method','?')} {log.get('endpoint','?')} "
            f"| UA: {str(log.get('user_agent',''))[:60]} | status={log.get('status_code','?')} "
            f"| score={log.get('suspicion_score', 0)}"
        )
    logs_text = '\n'.join(log_lines) if log_lines else '  (no logs yet)'

    # Format session statistics
    stats_text = ""
    if session_stats:
        stats_text = (
            f"\nSESSION STATISTICS:\n"
            f"  Total requests: {session_stats.get('total_requests', 0)}\n"
            f"  Unique paths visited: {session_stats.get('unique_paths', 0)} "
            f"({session_stats.get('unique_ratio', 0)*100:.0f}% unique)\n"
            f"  HTTP error rate: {session_stats.get('error_rate', 0)*100:.0f}%\n"
            f"  Write operations (POST/PUT/DELETE): {session_stats.get('mutation_count', 0)}\n"
            f"  Avg / Max suspicion score: {session_stats.get('avg_susp_score', 0)} / {session_stats.get('max_susp_score', 0)}\n"
            f"  Paths accessed: {json.dumps(session_stats.get('top_paths', []))}"
        )

    # Behavioral context from entropy analysis
    behav_section = ""
    if extra_context:
        behav_section = f"\nBEHAVIORAL ENTROPY ANALYSIS:\n  {extra_context}"

    return f"""You are a security analyst reviewing an HTTP session log. Classify the session accurately.

{profile_context}

SESSION:
  ID: {session.session_id} | IP: {session.ip_address} | Domain: {session.domain}
  Started: {session.start_time} | Interactions: {session.interaction_count}
  State: backend={session.backend_type}, threat_level={session.threat_level}
{stats_text}
{behav_section}

RECENT REQUESTS (last 30, newest first):
{logs_text}

CLASSIFICATION RULES — use these exact technique names, never invent others:
  SQL Injection          — UNION SELECT, ' OR 1=1, DROP TABLE, sleep(), xp_cmdshell in URL/body
  Command Injection      — ;whoami, |id, ;cat /etc/passwd, $(cmd), `backtick` execution in URL/body
  XSS                    — <script>, javascript:, onerror=, document.cookie in URL/body
  Path Traversal         — ../../../etc/passwd, %2e%2e%2f, /etc/shadow in URL/body
  SSTI                   — {{{{7*7}}}}, {{{{config}}}}, ${{7*7}} in URL/body
  SSRF                   — http://localhost, http://169.254.169.254 in URL/body
  IDOR Enumeration       — sequential numeric IDs accessed across multiple requests
  Credential Stuffing    — repeated POST to login/auth with different credentials
  Web Scraping           — systematic GET of many pages, high unique-path ratio, no JS
  Recon/Scanning         — probing admin paths, backup files, CMS endpoints
  Brute Force            — high-frequency repeated requests to same endpoint
  Scanner Tool           — sqlmap, nikto, nmap, masscan, dirbuster in User-Agent
  Honeypot Triggered     — accessed a path that is disallowed/hidden and should not exist

IMPORTANT:
- A payload with ";whoami" or ";id" is COMMAND INJECTION, not SQL injection — do not conflate
- A payload with "%3Cscript%3E" (URL-encoded <script>) is XSS, not SQL injection
- "%60id%60" (URL-encoded backticks) around a command is COMMAND INJECTION
- "%3B+whoami" (URL-encoded ;whoami) is COMMAND INJECTION
- Only label SQL Injection when you see actual SQL syntax (SELECT, UNION, DROP, etc.)
- A session can have MULTIPLE techniques — list each one separately

Based on the above:
1. What is this session doing and what is the most likely intent?
2. Which specific techniques (from the list above) are present? Be precise.
3. Is this flagged (malicious/automated = true, normal = false)?
4. Confidence level?

Return ONLY valid JSON, no markdown:
{{
  "risk_score": <0-100>,
  "threat_level": "<low|medium|high|critical>",
  "flagged": <true|false>,
  "techniques": ["exact names from the taxonomy above only"],
  "explanation": "Precise description of what the session is doing and why each technique was identified. Reference the actual payloads seen.",
  "deception_strategy": "<monitor|lure|isolate|contain>",
  "confidence": <0-100>
}}"""


def _safe_json(text: str) -> Dict:
    text = re.sub(r'^```[a-z]*\n?', '', text.strip())
    text = re.sub(r'\n?```$', '', text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r'\{.*\}', text, re.DOTALL)
        if m:
            try:
                return json.loads(m.group())
            except Exception:
                pass
    return {}
