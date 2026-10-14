"""
services/threat_evaluator.py  (v5.1 — rebuilt detection pipeline)
===================================================================
Three-Tier Session Evaluation Engine for Genius Mirage.

Changes from v5.0
-----------------
*  Honeytoken check added to Tier 1 (T1-13) — highest-confidence signal.
*  Behavioral entropy analysis integrated into Tier 2 (adds up to 40 pts).
*  `_build_session_data` improved to surface more signals from fewer logs.
*  Tier 3 AI prompt receives behavioral entropy context so Groq can reason
   about automation signals, not just raw request strings.
*  `T3_LOW_THRESHOLD` lowered to 25 so borderline sessions get AI review.
"""

from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List, Optional, Tuple
from urllib.parse import unquote_plus

from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# RESULT DATACLASS
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class EvaluationResult:
    flagged: bool
    tier: int
    score: int
    threat_level: str
    techniques: List[str]
    reasons: List[str]
    deception_strategy: str
    confidence: int
    ai_powered: bool
    explanation: str
    soft_isolation: bool
    tier1_triggers: List[str] = field(default_factory=list)
    tier2_breakdown: Dict[str, int] = field(default_factory=dict)
    tier3_analysis: Dict = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════════════════════
# TIER 1 — DETERMINISTIC WIRETRIPS
# Zero false-positive binary flags. ANY match = immediate flag.
# ═══════════════════════════════════════════════════════════════════════════════

HONEY_PATH_PATTERNS = re.compile(
    r'(/__probe__|/\.env|/\.git/|/config\.php|/wp-config\.php|/server-status'
    r'|/actuator/|/\.aws/|/\.ssh/|/backup|/dump\.sql|/db\.sqlite3|/phpinfo'
    r'|/_gmhoney_|/_internal/|/_gm_honey_/|/secret-admin-panel/)',
    re.IGNORECASE,
)

ABSOLUTE_SQLI = re.compile(
    r'(union\s+select|select\s+.*\s+from\s+information_schema'
    r"|'\s*or\s+'1'\s*=\s*'1|1\s*=\s*1\s*--|;\s*drop\s+table|;\s*delete\s+from"
    r"|insert\s+into\s+.*\s+values|exec\s*\(|xp_cmdshell|sleep\s*\(\d+\)"
    r'|benchmark\s*\(\d+|waitfor\s+delay)',
    re.IGNORECASE,
)

ABSOLUTE_XSS = re.compile(
    r'(<script[^>]*>.*?</script>|javascript\s*:|on(?:error|load|click|mouseover|focus)\s*='
    r'|<iframe[^>]*src|document\.cookie|document\.write\s*\(|eval\s*\('
    r'|String\.fromCharCode\s*\(|<svg[^>]*onload)',
    re.IGNORECASE | re.DOTALL,
)

ABSOLUTE_PATH_TRAVERSAL = re.compile(
    r'((\.\./){3,}|%2e%2e%2f|%252e%252e%252f|/etc/passwd|/etc/shadow'
    r'|/proc/self/environ|/windows/win\.ini|/boot\.ini)',
    re.IGNORECASE,
)

ABSOLUTE_CMDI = re.compile(
    r'(;\s*(?:cat|ls|id|whoami|wget|curl|bash|sh|python|perl|ruby|nc|ncat)\b'
    r'|\|\s*(?:cat|ls|id|whoami|bash|sh)\b|`[^`]{1,100}`|\$\(.*\))',
    re.IGNORECASE,
)

ABSOLUTE_ATTACK_UA = re.compile(
    r'(sqlmap|nikto|masscan|zgrab|dirbuster|gobuster|wfuzz|ffuf'
    r'|acunetix|nessus|openvas|metasploit|havij|pangolin'
    r'|skipfish|w3af|burpsuite|zap-proxy|nuclei|httpx-scanner)',
    re.IGNORECASE,
)

HONEY_FIELD_TAMPERING = re.compile(
    r'_gm_role\s*=\s*(?!visitor)[^\s&]+', re.IGNORECASE,
)

ABSOLUTE_SSTI = re.compile(
    r'(\{\{.*\}\}|\{%.*%\}|\$\{.*\}|#\{.*\})', re.IGNORECASE,
)

ABSOLUTE_SSRF = re.compile(
    r'(http://(?:127\.0\.0\.1|localhost|169\.254\.169\.254|0\.0\.0\.0)'
    r'|file:///|dict://|gopher://|ftp://localhost)',
    re.IGNORECASE,
)


def _check_tier1(request_data: Dict, session_data: Dict,
                 session_id: str = "") -> Tuple[bool, List[str]]:
    triggers = []
    path  = request_data.get('path', '')
    ua    = request_data.get('user_agent', '')
    body  = _decode_for_matching(_stringify(request_data.get('body', '')))
    qs    = _decode_for_matching(request_data.get('query_string', ''))
    full  = f"{path} {qs} {body}"

    if HONEY_PATH_PATTERNS.search(path):
        triggers.append(f"T1-01: Honey path accessed — {path}")

    if ABSOLUTE_SQLI.search(full):
        triggers.append("T1-02: Definitive SQL injection payload detected")

    if ABSOLUTE_XSS.search(full):
        triggers.append("T1-03: Definitive XSS payload detected")

    if ABSOLUTE_PATH_TRAVERSAL.search(full):
        triggers.append("T1-04: Path traversal to sensitive OS files detected")

    if ABSOLUTE_CMDI.search(full):
        triggers.append("T1-05: OS command injection payload detected")

    if ABSOLUTE_ATTACK_UA.search(ua):
        triggers.append(f"T1-06: Known attack tool User-Agent — {ua[:60]}")

    if HONEY_FIELD_TAMPERING.search(full):
        triggers.append("T1-07: Hidden honeypot form field tampered")

    if request_data.get('noscript_triggered', False):
        triggers.append("T1-08: JavaScript disabled — noscript trap fired")

    if ABSOLUTE_SSTI.search(full):
        triggers.append("T1-09: Server-Side Template Injection payload detected")

    if ABSOLUTE_SSRF.search(full):
        triggers.append("T1-10: SSRF payload detected")

    if request_data.get('method', '') in ('TRACE', 'CONNECT'):
        triggers.append(f"T1-11: Prohibited HTTP method {request_data['method']}")

    if session_data.get('requests_last_60s', 0) > 100:
        triggers.append(f"T1-12: Machine-speed velocity ({session_data['requests_last_60s']} req/60s)")

    # ── T1-13: Honeytoken triggered (NEW — highest confidence signal) ──────
    if session_id:
        try:
            from base.services.honeytoken import check_request_for_honeytokens
            ht_triggered, ht_token, ht_entry = check_request_for_honeytokens(
                session_id, request_data
            )
            if ht_triggered:
                token_type = (ht_entry or {}).get("token_type", "unknown")
                triggers.append(
                    f"T1-13: Honeytoken triggered — planted {token_type} used in request"
                )
        except Exception as exc:
            logger.debug("[T1-13] Honeytoken check error: %s", exc)

    # ── T1-14: Payment webhook forgery (NEW) ────────────────────────────────
    # Catches forged/self-issued payment-gateway callbacks (e.g. a user
    # POSTing straight to their site's own M-Pesa/PayPal callback URL with a
    # CheckoutRequestID they legitimately obtained from calling the site's
    # own "initiate payment" endpoint moments earlier). This is invisible to
    # every other Tier 1/2 rule because, taken alone, the request has no
    # attack payload and no anomalous velocity — only its traffic *shape*
    # (browser fingerprint on a server-to-server-only path, or the same IP
    # hitting initiate-then-webhook) gives it away. See webhook_guard.py.
    if request_data.get('is_webhook_path'):
        try:
            from base.services.webhook_guard import check_webhook_forgery
            wh_triggered, wh_reasons = check_webhook_forgery(
                request_data, request_data.get('ip_address', ''), request_data.get('site_id', ''),
            )
            if wh_triggered:
                triggers.extend(wh_reasons)
        except Exception as exc:
            logger.debug("[T1-14] Webhook forgery check error: %s", exc)

    return bool(triggers), triggers


# ═══════════════════════════════════════════════════════════════════════════════
# TIER 2 — BEHAVIOURAL ANOMALY SCORING
# ═══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_PATH_RULES: List[Tuple] = [
    (re.compile(r'(\.\./|\.\.\\)',                              re.I), 25, 'Path Traversal Attempt',     'File System'),
    (re.compile(r"('|--|;|%27)",                               re.I), 20, 'SQL Syntax Probe',           'Injection'),
    (re.compile(r'(<script|%3cscript)',                         re.I), 20, 'XSS Probe',                  'Injection'),
    (re.compile(r'(/etc/|/proc/|/sys/)',                        re.I), 30, 'Linux Path Probe',           'File System'),
    (re.compile(r'(phpinfo|eval\(|base64_decode)',              re.I), 25, 'Code Injection Probe',       'Injection'),
    (re.compile(r'(/wp-admin|/wp-login|/phpmyadmin)',           re.I), 20, 'CMS Admin Probe',            'Reconnaissance'),
    (re.compile(r'(/admin|/administrator|/dashboard)',          re.I), 15, 'Admin Panel Probe',          'Reconnaissance'),
    (re.compile(r'(/api/v\d+/admin|/api/config)',               re.I), 25, 'Sensitive API Probe',        'Reconnaissance'),
    (re.compile(r'(\|cat|&&cat|;cat|`cat)',                    re.I), 30, 'Command Injection Probe',    'Injection'),
    (re.compile(r'(nikto|sqlmap|nmap|masscan)',                 re.I), 40, 'Scanner Tool Signature',     'Tool'),
    (re.compile(r'\.(bak|old|sql|zip|tar|gz|dump)($|\?)',      re.I), 25, 'Backup File Probe',          'File System'),
    (re.compile(r'(robots\.txt|sitemap\.xml)',                  re.I),  5, 'Recon File Access',          'Reconnaissance'),
]
# NOTE: the old "IDOR Enumeration" single-request rule (any URL ending in a
# 4-8 digit number) was removed — that matches ordinary resource URLs
# (`/invoice/384921`, `/posts/48213`) constantly and was a major source of
# false positives. Real IDOR probing is a *sequence* signal: it only looks
# like an attack once you see several near-consecutive IDs in one session.
# That's handled correctly (and only) by `session_data['sequential_id_access']`
# below, which requires 4+ sequential IDs before it contributes any score.
#
# The old "Sensitive API Probe" rule matched any `/api/v1/users` style path
# too — "users" is one of the most common REST resource names on the planet.
# Narrowed to only match genuinely privileged endpoints (`/api/*/admin`,
# `/api/config`).

SUSPICIOUS_UA_RULES: List[Tuple] = [
    (re.compile(r'(python-requests|go-http-client|java/\d|okhttp|aiohttp|httpx)', re.I),  8, 'Scripted Client',    'Automation'),
    (re.compile(r'(curl|wget|httpie|libwww)',                                      re.I),  8, 'CLI HTTP Tool',      'Automation'),
    (re.compile(r'^-$|^\s*$'),                                                           20, 'Missing User-Agent', 'Evasion'),
    (re.compile(r'(hydra|medusa|ncrack)',                                          re.I), 45, 'Brute-Force Tool',   'Tool'),
    (re.compile(r'(headlesschrome|phantomjs|selenium|puppeteer|playwright)',       re.I), 12, 'Headless Browser',   'Automation'),
    (re.compile(r'^Mozilla/[45]\.0\s*$'),                                                10, 'Stripped UA',        'Evasion'),
    (re.compile(r'(nikto|sqlmap|nmap|masscan|zgrab|dirbuster|gobuster|wfuzz|ffuf|nuclei)', re.I), 40, 'Scanner Tool UA', 'Tool'),
]
# "Scanner Tool UA" closes a real gap: the path-level "Scanner Tool
# Signature" rule only inspects the URL/query/body, never the User-Agent
# header, so a scanner sending e.g. "Nmap Scripting Engine" as its UA while
# hitting an otherwise ordinary-looking path went undetected by Tier 2
# entirely (several of these tools, like nmap, aren't in Tier 1's shorter
# ABSOLUTE_ATTACK_UA list either, so nothing would have caught them).
# "Scripted Client" / "CLI HTTP Tool" / "Headless Browser" points lowered
# (15→8, 20→12). These UAs are extremely common in *legitimate* traffic —
# server-to-server integrations, webhooks, cron jobs, uptime monitors
# (Pingdom/UptimeRobot), CI smoke tests, and QA automation (Selenium/
# Playwright) all present these strings honestly. They're still worth a
# small number of points (genuine attack tooling often layers on top of
# them), but they should never be able to single-handedly push a session
# into AI review — only *combined* with other independent evidence.
#
# Automation UAs used to be double-penalized: once for the UA string itself,
# and again for "missing" Accept/Accept-Encoding headers that non-browser
# clients never send in the first place (see `_check_tier2` below, which now
# skips that second charge for UAs already flagged as automation — it's the
# same underlying fact counted twice, not two pieces of independent evidence).

# Keywords that indicate a genuinely privileged/sensitive path, used by the
# "Unlinked Sensitive Path" site-profile check below. Deliberately excludes
# generic terms like "api" and "user" — those appear in the majority of
# ordinary REST endpoints and made the old rule fire on almost any dynamic,
# uncrawled URL.
SENSITIVE_PATH_KEYWORDS = (
    'admin', 'config', 'secret', 'password', 'passwd', '.env',
    'credential', 'private-key', 'backup', 'dump', '.git', '.ssh',
)

# Segments that look like an ID/UUID/hash rather than a fixed route name.
_ID_SEGMENT = re.compile(
    r'^(\d+|[0-9a-f]{8,}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$',
    re.I,
)


def _normalize_path(path: str) -> str:
    """
    Collapse numeric/UUID/hash path segments to a placeholder so that
    `/orders/48213` and `/orders/91002` normalize to the same route
    `/orders/{id}`. Used to compare live traffic against a site's crawled
    `expected_paths`, which otherwise only ever contains the concrete
    values seen at crawl time and would flag every dynamic URL as
    "unexpected" on an exact-string match.
    """
    if not path:
        return path
    segments = path.split('/')
    normalized = ['{id}' if _ID_SEGMENT.match(seg) else seg for seg in segments]
    return '/'.join(normalized)


def _check_tier2(request_data: Dict, session_data: Dict,
                 activity_logs: List[Dict],
                 site_profile=None) -> Tuple[int, Dict[str, int], List[str]]:
    breakdown: Dict[str, int] = {}
    techniques: List[str] = []
    score = 0

    path    = request_data.get('path', '')
    qs      = _decode_for_matching(request_data.get('query_string', ''))
    ua      = request_data.get('user_agent', '')
    body    = _decode_for_matching(_stringify(request_data.get('body', '')))
    headers = request_data.get('headers', {})
    method  = request_data.get('method', 'GET')
    full    = f"{path} {qs} {body}"

    # ── Path rules ────────────────────────────────────────────────────────────
    for pattern, pts, name, _ in SUSPICIOUS_PATH_RULES:
        if pattern.search(full):
            score += pts; breakdown[name] = pts; techniques.append(name)

    # ── UA rules ──────────────────────────────────────────────────────────────
    is_known_automation_ua = False
    for pattern, pts, name, _ in SUSPICIOUS_UA_RULES:
        if pattern.search(ua):
            score += pts; breakdown[name] = pts; techniques.append(name)
            if name in ('Scripted Client', 'CLI HTTP Tool', 'Headless Browser'):
                is_known_automation_ua = True

    # ── Header anomaly ────────────────────────────────────────────────────────
    has_accept     = bool(headers.get('Accept')    or headers.get('accept'))
    has_accept_enc = bool(headers.get('Accept-Encoding') or headers.get('accept-encoding'))
    xff            = headers.get('X-Forwarded-For', headers.get('x-forwarded-for', ''))

    # Only charge for missing Accept/Accept-Encoding when the client ISN'T
    # already a known automation UA — for curl/python-requests/etc. these
    # headers are legitimately absent by default, so penalizing both the UA
    # string and the headers it naturally omits double-counts one fact as
    # two signals and was pushing ordinary API/webhook traffic toward review.
    if not is_known_automation_ua:
        if not has_accept:
            score += 6; breakdown['Missing Accept Header'] = 6; techniques.append('Missing Accept Header')
        if not has_accept_enc:
            score += 4; breakdown['Missing Accept-Encoding'] = 4; techniques.append('Missing Accept-Encoding')

    # X-Forwarded-For: legitimate multi-hop CDN/WAF/load-balancer chains
    # routinely reach 3-5 entries (client → CDN edge → WAF → LB → app), so
    # the old ">3 commas" threshold flagged normal enterprise infrastructure.
    # Raised to a chain length that's actually anomalous, and only counts
    # duplicate entries (a real spoofing tell) as a stronger, separate signal.
    if xff:
        hops = [h.strip() for h in xff.split(',') if h.strip()]
        if len(hops) > 6:
            score += 15; breakdown['Unusually Long Forwarding Chain'] = 15; techniques.append('Unusually Long Forwarding Chain')
        if len(hops) != len(set(hops)) and len(hops) > 1:
            score += 15; breakdown['Duplicate IPs in Forwarding Chain'] = 15; techniques.append('Duplicate IPs in Forwarding Chain')

    if method in ('POST', 'PUT', 'PATCH') and body:
        ct = headers.get('Content-Type', headers.get('content-type', ''))
        if not ct:
            score += 15; breakdown['Content-Type/Body Mismatch'] = 15; techniques.append('Content-Type/Body Mismatch')

    # ── Velocity ──────────────────────────────────────────────────────────────
    rps = session_data.get('requests_last_60s', 0)
    if 20 <= rps < 50:
        score += 20; breakdown['Medium Request Velocity'] = 20; techniques.append('Medium Request Velocity')
    elif 50 <= rps <= 100:
        score += 35; breakdown['High Request Velocity'] = 35; techniques.append('High Request Velocity')

    if session_data.get('repeated_4xx', 0) >= 5:
        pts = min(session_data['repeated_4xx'] * 3, 30)
        score += pts; breakdown['Repeated 4xx Errors'] = pts; techniques.append('Repeated 4xx Errors')

    if session_data.get('avg_dwell_ms', 9999) < 300 and session_data.get('interaction_count', 0) > 5:
        score += 15; breakdown['Machine-Speed Dwell Time'] = 15; techniques.append('Machine-Speed Dwell Time')

    if session_data.get('no_cookie_persistence', False):
        score += 10; breakdown['No Cookie Persistence'] = 10; techniques.append('No Cookie Persistence')

    if session_data.get('sequential_id_access', False):
        score += 20; breakdown['Sequential ID Enumeration'] = 20; techniques.append('Sequential ID Enumeration')

    # ── Site profile checks ───────────────────────────────────────────────────
    if site_profile and site_profile.status == 'ready':
        expected_raw = site_profile.expected_paths or []
        # Compare normalized routes, not raw crawled URLs — otherwise every
        # dynamic URL with a different ID than whatever the crawler happened
        # to see (e.g. /orders/48213 vs the crawled /orders/91002) reads as
        # "unexpected" and this fires on completely ordinary navigation.
        expected_normalized = {_normalize_path(p) for p in expected_raw}
        norm_path = _normalize_path(path)
        if expected_normalized and norm_path not in expected_normalized and len(path) > 1:
            if any(kw in path.lower() for kw in SENSITIVE_PATH_KEYWORDS):
                score += 15; breakdown['Unlinked Sensitive Path'] = 15; techniques.append('Unlinked Sensitive Path')

    if method in ('POST', 'PUT', 'DELETE') and site_profile:
        for sensitive_path in (getattr(site_profile, 'sensitive_areas', None) or []):
            if sensitive_path and sensitive_path in path:
                score += 25; breakdown['Method Escalation'] = 25; techniques.append('Method Escalation')
                break

    # ── Behavioral entropy analysis (NEW — up to 40 pts) ─────────────────────
    try:
        from base.services.behavioral_detector import analyze_session_behavior
        behav = analyze_session_behavior(activity_logs, request_data, site_profile)
        if behav.total_score > 0:
            # Scale to max 40 pts contribution
            behav_pts = min(int(behav.total_score * 0.4), 40)
            score += behav_pts
            breakdown['Behavioral Entropy'] = behav_pts
            techniques.extend(behav.signals[:4])
            if behav.explanation:
                breakdown[f'BehaviorDetail:{behav.explanation[:60]}'] = 0
    except Exception as exc:
        logger.debug("[T2] Behavioral analysis error: %s", exc)

    return min(score, 100), breakdown, list(set(techniques))


# ═══════════════════════════════════════════════════════════════════════════════
# TIER 3 — AI INTENT ENGINE
# ═══════════════════════════════════════════════════════════════════════════════

T3_LOW_THRESHOLD  = 25   # Lower threshold — more sessions get AI review
T3_HIGH_THRESHOLD = 75


def _check_tier3(session, activity_logs, site_profile,
                 tier2_score, tier2_techniques, behavioral_context: str = "") -> Dict:
    try:
        from base.services.global_ai_analyzer import analyze_session as _ai
        result = _ai(session, activity_logs, site_profile,
                     extra_context=behavioral_context)
        blended = int(result['risk_score'] * 0.6 + tier2_score * 0.4)
        result['risk_score'] = min(blended, 100)
        result['techniques'] = list(set(result.get('techniques', []) + tier2_techniques))
        return result
    except Exception as exc:
        logger.warning("[T3] AI failed, using heuristic fallback: %s", exc)
        return _tier3_heuristic_fallback(session, tier2_score, tier2_techniques)


def _tier3_heuristic_fallback(session, tier2_score, tier2_techniques) -> Dict:
    score = tier2_score
    explanation = "Heuristic analysis (AI unavailable)."

    age_minutes = max(
        (timezone.now() - session.start_time).total_seconds() / 60, 0.01
    )
    req_per_min = session.interaction_count / age_minutes
    if req_per_min > 10:
        score = min(score + 20, 100)
        explanation += f" High request rate ({req_per_min:.1f}/min)."

    if len(tier2_techniques) >= 4:
        score = min(score + 15, 100)
        explanation += f" Multiple attack vectors ({len(tier2_techniques)})."

    flagged = score >= 60
    return {
        'risk_score':         score,
        'threat_level':       _score_to_level(score),
        'flagged':            flagged,
        'techniques':         tier2_techniques,
        'explanation':        explanation,
        'deception_strategy': 'isolate' if flagged else 'monitor',
        'confidence':         35,
        'ai_powered':         False,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def evaluate_session(
    session,
    activity_logs: List[Dict],
    site_profile=None,
    request_data: Optional[Dict] = None,
    session_data: Optional[Dict] = None,
) -> EvaluationResult:
    if request_data is None:
        request_data = _extract_request_data_from_logs(activity_logs)
    if session_data is None:
        session_data = _build_session_data(session, activity_logs)

    session_id = getattr(session, 'session_id', '')

    # ── TIER 1 ───────────────────────────────────────────────────────────────
    t1_triggered, t1_reasons = _check_tier1(request_data, session_data, session_id)

    if t1_triggered:
        return EvaluationResult(
            flagged=True, tier=1, score=100, threat_level='critical',
            techniques=_extract_technique_names(t1_reasons),
            reasons=t1_reasons,
            deception_strategy='contain', confidence=99,
            ai_powered=False,
            explanation=(
                "Tier 1 deterministic wiretrap triggered. "
                "A definitive attack payload, honey path, or honeytoken use was detected."
            ),
            soft_isolation=False,
            tier1_triggers=t1_reasons,
        )

    # ── TIER 2 ───────────────────────────────────────────────────────────────
    t2_score, t2_breakdown, t2_techniques = _check_tier2(
        request_data, session_data, activity_logs, site_profile
    )

    threshold = _get_site_threshold(site_profile, session)

    # Require signal *diversity*, not just accumulated points, before Tier 2
    # can hard-flag a session on its own. A handful of correlated/weak
    # signals from the same source (e.g. a non-browser client tripping
    # several header/UA rules that are really one underlying fact) can add
    # up past T3_HIGH_THRESHOLD without ever representing independent
    # evidence of malicious intent. Contributions are the non-zero breakdown
    # entries, excluding the zero-point BehaviorDetail annotation.
    contributing_signals = [k for k, v in t2_breakdown.items() if v > 0]
    has_signal_diversity = len(contributing_signals) >= 2

    if t2_score >= T3_HIGH_THRESHOLD and has_signal_diversity:
        return EvaluationResult(
            flagged=True, tier=2, score=t2_score,
            threat_level=_score_to_level(t2_score),
            techniques=t2_techniques,
            reasons=[f"{k}: +{v} pts" for k, v in t2_breakdown.items() if v > 0],
            deception_strategy=_strategy_for_score(t2_score),
            confidence=85, ai_powered=False,
            explanation=(
                f"Tier 2 threshold exceeded (score {t2_score}/100). "
                "Multiple behavioural and signature signals detected."
            ),
            soft_isolation=True,
            tier2_breakdown=t2_breakdown,
        )

    if t2_score < T3_LOW_THRESHOLD:
        return EvaluationResult(
            flagged=False, tier=2, score=t2_score, threat_level='low',
            techniques=t2_techniques,
            reasons=[f"{k}: +{v} pts" for k, v in t2_breakdown.items() if v > 0]
                    or ["No suspicious signals detected"],
            deception_strategy='monitor', confidence=80,
            ai_powered=False,
            explanation="No significant threat indicators. Session appears legitimate.",
            soft_isolation=False,
            tier2_breakdown=t2_breakdown,
        )

    # ── TIER 3 (grey zone) ───────────────────────────────────────────────────
    # Build behavioral context string for the AI prompt
    behavioral_ctx = ""
    try:
        from base.services.behavioral_detector import analyze_session_behavior
        behav = analyze_session_behavior(activity_logs, request_data, site_profile)
        behavioral_ctx = (
            f"Behavioral entropy analysis: {behav.explanation} "
            f"(timing={behav.timing_score}/25, graph={behav.graph_score}/25, "
            f"browser_consistency={behav.consistency_score}/25, trajectory={behav.trajectory_score}/25)"
        )
    except Exception:
        pass

    t3_result = _check_tier3(
        session, activity_logs, site_profile,
        t2_score, t2_techniques, behavioral_ctx
    )

    final_score = t3_result['risk_score']
    ai_flagged  = t3_result.get('flagged', False) or final_score >= threshold

    return EvaluationResult(
        flagged=ai_flagged, tier=3, score=final_score,
        threat_level=t3_result.get('threat_level', _score_to_level(final_score)),
        techniques=t3_result.get('techniques', t2_techniques),
        reasons=(
            [f"AI Analysis: {t3_result.get('explanation', '')}"]
            + [f"{k}: +{v} pts" for k, v in t2_breakdown.items() if v > 0]
        ),
        deception_strategy=t3_result.get('deception_strategy', _strategy_for_score(final_score)),
        confidence=t3_result.get('confidence', 50),
        ai_powered=t3_result.get('ai_powered', False),
        explanation=t3_result.get('explanation', ''),
        soft_isolation=True,
        tier2_breakdown=t2_breakdown,
        tier3_analysis=t3_result,
    )


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _stringify(value) -> str:
    if value is None: return ''
    if isinstance(value, (dict, list)):
        try: return json.dumps(value)
        except: return str(value)
    return str(value)


def _decode_for_matching(value: str) -> str:
    """
    Decode a query string or POST body before running literal-character
    pattern checks against it (XSS, SQLi, command injection, etc).

    Browsers percent-encode special characters — `<`, `>`, spaces, quotes —
    when building a query string or an application/x-www-form-urlencoded
    body. A path segment gets auto-decoded by WSGI/Express before this code
    ever sees it, which is why `/product/1 UNION SELECT ...` typed into a
    URL bar was detected correctly, while the exact same payload typed into
    a search box or form field (arriving as `q=%3Cscript%3E...` in the query
    string) silently matched nothing — every literal-character rule
    (`ABSOLUTE_XSS`, `ABSOLUTE_SQLI`, etc.) was written assuming decoded
    text, and query_string/body were never being decoded before reaching
    them.

    `unquote_plus` also turns `+` into a space, matching
    application/x-www-form-urlencoded convention for form bodies and
    query strings (unlike path segments, where `+` is a literal character).

    Failure mode is intentionally safe: if the input isn't actually
    percent-encoded, unquoting is a no-op for the vast majority of real
    text. The rare false-decode (literal text that happens to contain a
    `%XX`-looking sequence, e.g. "50%20off" meant as literal characters)
    only affects pattern-matching, not what's stored/displayed/forwarded
    elsewhere — an acceptable trade-off against a 100% miss rate on
    encoded attacks, which is what existed before this fix.
    """
    if not value:
        return value
    try:
        return unquote_plus(value)
    except Exception:
        return value


def _score_to_level(score: int) -> str:
    if score >= 80: return 'critical'
    if score >= 60: return 'high'
    if score >= 30: return 'medium'
    return 'low'


def _strategy_for_score(score: int) -> str:
    if score >= 85: return 'contain'
    if score >= 70: return 'isolate'
    if score >= 50: return 'lure'
    return 'monitor'


def _extract_technique_names(reasons: List[str]) -> List[str]:
    names = []
    for r in reasons:
        parts = r.split(': ', 1)
        if len(parts) == 2:
            names.append(parts[1].replace(' detected', '').replace(' payload', ''))
    return names


def _extract_request_data_from_logs(logs: List[Dict]) -> Dict:
    if not logs: return {}
    latest = logs[-1] if isinstance(logs[-1], dict) else {}
    return {
        'path':               latest.get('endpoint', '/'),
        'user_agent':         latest.get('user_agent', ''),
        'method':             latest.get('method', 'GET'),
        'body':               latest.get('request_body', ''),
        'query_string':       '',
        'headers':            latest.get('headers', {}),
        'noscript_triggered': latest.get('noscript_triggered', False),
    }


def _build_session_data(session, logs: List[Dict]) -> Dict:
    """
    Build session-level aggregate signals from activity logs.
    Improved to extract meaningful signals even from small log samples.
    """
    now     = timezone.now()
    cutoff  = now - timedelta(seconds=60)

    requests_last_60s = 0
    repeated_4xx      = 0
    dwell_times       = []
    prev_time         = None
    endpoints         = []
    status_codes      = []

    for log in logs:
        ts_raw = log.get('timestamp')
        if ts_raw:
            try:
                if hasattr(ts_raw, 'tzinfo'):
                    ts = ts_raw
                else:
                    from django.utils.dateparse import parse_datetime
                    ts = parse_datetime(str(ts_raw))
                if ts and ts >= cutoff:
                    requests_last_60s += 1
                if prev_time and ts:
                    delta_ms = abs((ts - prev_time).total_seconds() * 1000)
                    if 0 < delta_ms < 300_000:   # ignore gaps > 5 min
                        dwell_times.append(delta_ms)
                prev_time = ts
            except Exception:
                pass

        sc = log.get('status_code', 200)
        status_codes.append(sc)
        if isinstance(sc, int) and 400 <= sc < 500:
            repeated_4xx += 1

        ep = log.get('endpoint', '')
        if ep:
            endpoints.append(ep)

    avg_dwell = (sum(dwell_times) / len(dwell_times)) if dwell_times else 9999

    # Sequential numeric IDOR detection. Previously required 3-8 digit IDs,
    # which meant small ID spaces — extremely common in early-stage/small
    # apps (invoice #1, #2, #3...) — were structurally invisible to this
    # check no matter how many were accessed in sequence. Lowered to 1+
    # digits; the existing requirements (4+ IDs seen, max gap <=5) already
    # keep this from tripping on unrelated single numbers like a "2" in
    # a product name or a page-size query param.
    sequential_id_access = False
    id_pat = re.compile(r'/(\d{1,8})(?:/|$|\?)')
    ids_seen = sorted(
        int(m.group(1))
        for ep in endpoints
        for m in [id_pat.search(ep)]
        if m
    )
    if len(ids_seen) >= 4:
        diffs = [ids_seen[i+1] - ids_seen[i] for i in range(len(ids_seen)-1)]
        if diffs and max(diffs) <= 5:
            sequential_id_access = True

    # High error rate even on small samples
    if status_codes:
        error_rate = sum(1 for s in status_codes if isinstance(s, int) and s >= 400) / len(status_codes)
    else:
        error_rate = 0.0

    # Detect if ALL requests are on the same path (scanner testing one endpoint)
    unique_paths = set(endpoints)
    single_path_hammering = len(endpoints) >= 5 and len(unique_paths) == 1

    return {
        'requests_last_60s':      requests_last_60s,
        'repeated_4xx':           repeated_4xx,
        'avg_dwell_ms':           avg_dwell,
        'interaction_count':      getattr(session, 'interaction_count', len(logs)),
        'no_cookie_persistence':  False,
        'sequential_id_access':   sequential_id_access,
        'error_rate':             error_rate,
        'single_path_hammering':  single_path_hammering,
    }


def _get_site_threshold(site_profile, session) -> int:
    try:
        if session and session.site:
            return session.site.sensitivity_level
    except Exception:
        pass
    try:
        from base.models import SystemSettings
        s = SystemSettings.objects.first()
        if s:
            return s.suspicion_threshold
    except Exception:
        pass
    return 65
