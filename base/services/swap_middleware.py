"""
services/swap_middleware.py
============================
Genius Mirage — Seamless Backend Swap Layer (v5)

This is the actual hot-swap mechanism. Once the three-tier evaluator flags
a session, this layer intercepts every subsequent request from that session
and routes it to the decoy engine instead of the real client backend.

How the swap works
------------------
For clean sessions:
    Request → DeceptionProxyMiddleware → forward to real backend → real response

For flagged sessions:
    Request → DeceptionProxyMiddleware → decoy_engine.generate_decoy_response()
                                       → decoy response (never touches real backend)

The swap is:
  - Per-session: User A (clean) and User B (flagged) hit the same URL.
                 A gets the real response. B gets the decoy.
  - Seamless:    B never receives an error, a redirect, or a broken page.
                 From B's perspective, the site is responding normally.
  - Stateful:    The decoy engine maintains internal consistency across
                 B's entire session. State is cached per session.
  - Logged:      Every single request B makes inside the decoy is recorded
                 to DeceptionInteraction for the dashboard.

Integration modes
-----------------
MODE 1 — Django Middleware (for clients who run Django)
    Add 'base.services.swap_middleware.DeceptionProxyMiddleware' to MIDDLEWARE.
    This is the self-hosted agent mode.

MODE 2 — Reverse Proxy View (for clients who cannot modify their server)
    Expose /api/proxy/<site_id>/<path>/ and configure the client's nginx/caddy
    to forward all traffic here. The view handles the swap decision and either
    proxies to the real origin or serves a decoy.

MODE 3 — JS Snippet + Server-Side Gating (lightweight)
    The JS snippet sends activity reports. Your platform's API returns a
    backend_type field. The client's server uses your SDK middleware to check
    session status before serving each response.
    See: genius_mirage_sdk/ for the drop-in SDK clients.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Dict, Optional

import requests as http_client
from django.core.cache import cache
from django.http import HttpResponse, StreamingHttpResponse
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

# Paths that should never be intercepted (platform's own API, static files)
import re
_BYPASS = re.compile(
    r'^(/api/|/admin/|/static/|/media/|/favicon\.ico)',
    re.IGNORECASE,
)


# ═══════════════════════════════════════════════════════════════════════════════
# MODE 1 — DJANGO PROXY MIDDLEWARE
# This runs on the client's own Django server (SDK / agent mode).
# The client adds this to their MIDDLEWARE list with their site_id and the
# Genius Mirage platform URL configured in settings.
# ═══════════════════════════════════════════════════════════════════════════════

class DeceptionProxyMiddleware(MiddlewareMixin):
    """
    Drop-in Django middleware for Genius Mirage client sites.

    Settings required in client's settings.py:
        GENIUS_MIRAGE_SITE_ID   = 'your-site-id'
        GENIUS_MIRAGE_API_URL   = 'https://your-platform.com'
        GENIUS_MIRAGE_API_TOKEN = 'your-auth-token'

    This middleware:
      1. Reads the session's current backend_type from cache or the platform API.
      2. If 'real'      → does nothing, request proceeds normally.
      3. If 'deceptive' → calls the platform's decoy API to get the response
                          and short-circuits the request pipeline.
    """

    def process_request(self, request):
        from django.conf import settings

        if _BYPASS.match(request.path):
            return None

        site_id   = getattr(settings, 'GENIUS_MIRAGE_SITE_ID', None)
        api_url   = getattr(settings, 'GENIUS_MIRAGE_API_URL', '')
        api_token = getattr(settings, 'GENIUS_MIRAGE_API_TOKEN', '')

        if not site_id or not api_url:
            return None  # Not configured — pass through silently

        session_id = self._get_session_id(request)
        if not session_id:
            return None

        backend_type = self._get_backend_type(session_id, site_id, api_url, api_token, request)

        if backend_type != 'deceptive':
            return None  # Clean session — let Django handle it normally

        # ── FLAGGED SESSION — serve decoy ────────────────────────────────────
        decoy = self._fetch_decoy_response(
            session_id, site_id, api_url, api_token, request
        )
        if not decoy:
            return None  # Decoy fetch failed — fail open (don't break site)

        # Honour the decoy's response delay to mimic real backend latency
        delay_ms = decoy.get('response_delay_ms', 0)
        if delay_ms > 0:
            time.sleep(min(delay_ms / 1000.0, 2.0))

        response = HttpResponse(
            content=decoy.get('body', ''),
            status=decoy.get('status_code', 200),
            content_type=decoy.get('content_type', 'application/json'),
        )
        for k, v in (decoy.get('headers') or {}).items():
            # Never forward hop-by-hop headers
            if k.lower() not in ('transfer-encoding', 'connection', 'keep-alive'):
                response[k] = v

        return response

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _get_session_id(self, request) -> Optional[str]:
        try:
            sid = request.session.get('_gm_session_id')
            if not sid:
                sid = request.COOKIES.get('_gm_sid')
            return sid
        except Exception:
            return None

    def _get_backend_type(self, session_id, site_id, api_url, token, request) -> str:
        """Check cache first, then ask the platform API."""
        cache_key = f'gm_btype:{session_id}'
        cached    = cache.get(cache_key)
        if cached:
            return cached

        try:
            resp = http_client.get(
                f'{api_url}/api/swap/session-status/',
                params={'session_id': session_id, 'site_id': site_id},
                headers={'Authorization': f'Token {token}'},
                timeout=0.3,  # Hard 300ms timeout — never slow the site
            )
            if resp.status_code == 200:
                data = resp.json()
                btype = data.get('backend_type', 'real')
                # Cache for 60s — avoid hammering the API on every request
                cache.set(cache_key, btype, timeout=60)
                return btype
        except Exception as exc:
            logger.debug('[GM SDK] Status check failed (fail-open): %s', exc)

        return 'real'  # Fail open — never break the client site

    def _fetch_decoy_response(
        self, session_id, site_id, api_url, token, request
    ) -> Optional[Dict]:
        """Ask the Genius Mirage platform to generate the decoy response."""
        try:
            body = b''
            try:
                body = request.body
            except Exception:
                pass

            resp = http_client.post(
                f'{api_url}/api/swap/decoy-response/',
                json={
                    'session_id':   session_id,
                    'site_id':      site_id,
                    'path':         request.path,
                    'method':       request.method,
                    'query_string': request.META.get('QUERY_STRING', ''),
                    'body':         body.decode('utf-8', errors='replace'),
                    'user_agent':   request.META.get('HTTP_USER_AGENT', ''),
                    'headers': {
                        k.replace('HTTP_', '').replace('_', '-').title(): v
                        for k, v in request.META.items()
                        if k.startswith('HTTP_')
                    },
                },
                headers={'Authorization': f'Token {token}'},
                timeout=1.5,  # 1.5s max — attacker won't notice slight delay
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception as exc:
            logger.debug('[GM SDK] Decoy fetch failed: %s', exc)
        return None


# ═══════════════════════════════════════════════════════════════════════════════
# MODE 2 — REVERSE PROXY VIEWS (added to Genius Mirage platform's views.py)
# These are the server-side endpoints that handle the swap for clients who
# configured their nginx/Caddy to route traffic through the platform.
# ═══════════════════════════════════════════════════════════════════════════════

def session_status_view(request):
    """
    GET /api/swap/session-status/?session_id=X&site_id=Y
    Returns the backend_type for a session (real | deceptive).
    Called by client-side SDK middleware on every request.
    Responds in <10ms from cache.
    """
    from django.http import JsonResponse
    from base.models import ActiveSession

    session_id = request.GET.get('session_id', '')
    site_id    = request.GET.get('site_id', '')

    if not session_id:
        return JsonResponse({'backend_type': 'real'})

    # Check cache first (set by deception middleware when session was flagged)
    cache_key = f'session_btype:{session_id}'
    cached    = cache.get(cache_key)
    if cached:
        return JsonResponse({'backend_type': cached, 'from_cache': True})

    try:
        session = ActiveSession.objects.only(
            'backend_type', 'threat_level', 'engagement_status'
        ).get(session_id=session_id)
        btype = session.backend_type
        # Cache result for 60s
        cache.set(cache_key, btype, timeout=60)
        return JsonResponse({
            'backend_type':      btype,
            'threat_level':      session.threat_level,
            'engagement_status': session.engagement_status,
        })
    except ActiveSession.DoesNotExist:
        return JsonResponse({'backend_type': 'real'})
    except Exception as exc:
        logger.warning('[SwapLayer] session_status error: %s', exc)
        return JsonResponse({'backend_type': 'real'})


def decoy_response_view(request):
    """
    POST /api/swap/decoy-response/
    Body: {session_id, site_id, path, method, query_string, body, user_agent, headers}

    Called by the client SDK middleware when a session is flagged.
    Returns the full decoy response to serve to the attacker.
    """
    from django.http import JsonResponse
    from django.views.decorators.csrf import csrf_exempt
    from base.models import ActiveSession, RegisteredSite, DeceptionInteraction, AttackerProfile
    from base.services.decoy_engine import generate_decoy_response

    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    session_id = data.get('session_id', '')
    site_id    = data.get('site_id', '')

    # Fetch session
    try:
        session = ActiveSession.objects.select_related('site').get(session_id=session_id)
    except ActiveSession.DoesNotExist:
        return JsonResponse({'error': 'Session not found'}, status=404)

    # Verify site ownership via auth token
    try:
        site = RegisteredSite.objects.get(id=site_id)
        _verify_request_auth(request, site)
    except Exception as exc:
        return JsonResponse({'error': 'Unauthorised'}, status=403)

    # Get site profile
    site_profile = None
    try:
        site_profile = site.profile if hasattr(site, 'profile') else None
    except Exception:
        pass

    # Build request_data from POST body
    request_data = {
        'path':         data.get('path', '/'),
        'method':       data.get('method', 'GET'),
        'body':         data.get('body', ''),
        'query_string': data.get('query_string', ''),
        'user_agent':   data.get('user_agent', ''),
        'headers':      data.get('headers', {}),
    }

    # Generate the decoy response
    decoy = generate_decoy_response(session, request_data, site_profile)

    # Log the interaction to DeceptionInteraction table
    _log_decoy_interaction(session, site, request_data, decoy)

    return JsonResponse({
        'status_code':      decoy.status_code,
        'content_type':     decoy.content_type,
        'body':             decoy.body,
        'headers':          decoy.headers,
        'response_delay_ms': decoy.response_delay_ms,
    })


def full_proxy_view(request, site_id, path=''):
    """
    ALL METHODS /api/proxy/<site_id>/<path>
    
    Full reverse-proxy mode for clients who point their domain DNS here.
    
    For clean sessions  → transparently forwards the request to the real origin.
    For flagged sessions → serves the decoy response without ever touching origin.

    Client nginx config:
        location / {
            proxy_pass https://your-platform.com/api/proxy/SITE_ID/;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        }
    """
    from django.http import JsonResponse, StreamingHttpResponse
    from base.models import ActiveSession, RegisteredSite
    from base.services.decoy_engine import generate_decoy_response
    from base.services.threat_evaluator import evaluate_session

    # Get site
    try:
        site = RegisteredSite.objects.get(id=site_id, status__in=['active', 'monitoring'])
    except RegisteredSite.DoesNotExist:
        return HttpResponse('Not Found', status=404)

    # Resolve session
    session_id   = _resolve_session_id(request)
    session      = _get_or_init_session(session_id, site, request)
    site_profile = _get_profile(site)

    # Build request_data for evaluation
    try:
        raw_body = request.body.decode('utf-8', errors='replace')
    except Exception:
        raw_body = ''

    request_data = {
        'path':               '/' + path,
        'method':             request.method,
        'body':               raw_body,
        'query_string':       request.META.get('QUERY_STRING', ''),
        'user_agent':         request.META.get('HTTP_USER_AGENT', ''),
        'headers':            _extract_headers(request),
        'noscript_triggered': bool(cache.get(f'noscript_flag:{session_id}')),
    }

    # Determine routing: check existing flag first, then re-evaluate if clean
    is_flagged = (session.backend_type == 'deceptive')

    if not is_flagged:
        # Run evaluation on this request
        recent_logs = _recent_logs(session_id)
        eval_result = evaluate_session(
            session=session,
            activity_logs=recent_logs,
            site_profile=site_profile,
            request_data=request_data,
        )
        if eval_result.flagged:
            is_flagged = True
            session.backend_type      = 'deceptive'
            session.threat_level      = eval_result.threat_level
            session.engagement_status = 'deceiving'
            # Cache the flag immediately so all subsequent checks are instant
            cache.set(f'session_btype:{session_id}', 'deceptive', timeout=7200)
            techs = set(session.detected_techniques or [])
            techs.update(eval_result.techniques)
            session.detected_techniques = list(techs)
            session.save(update_fields=[
                'backend_type', 'threat_level', 'engagement_status', 'detected_techniques'
            ])

    if is_flagged:
        # ── DECEPTIVE PATH — serve decoy ─────────────────────────────────────
        decoy = generate_decoy_response(session, request_data, site_profile)

        _log_decoy_interaction(session, site, request_data, decoy)

        # Apply response delay (mimic real backend latency)
        if decoy.response_delay_ms > 0:
            time.sleep(min(decoy.response_delay_ms / 1000.0, 2.0))

        http_response = HttpResponse(
            content=decoy.body,
            status=decoy.status_code,
            content_type=decoy.content_type,
        )
        for k, v in decoy.headers.items():
            if k.lower() not in ('transfer-encoding', 'connection'):
                http_response[k] = v
        return http_response

    else:
        # ── CLEAN PATH — forward to real origin ──────────────────────────────
        return _proxy_to_origin(request, site, '/' + path, raw_body)


# ═══════════════════════════════════════════════════════════════════════════════
# PROXY FORWARDING — forwards clean sessions to the real backend
# ═══════════════════════════════════════════════════════════════════════════════

def _proxy_to_origin(request, site, path: str, raw_body: str) -> HttpResponse:
    """
    Transparently forward a clean session's request to the real backend.
    The client never knows the request passed through Genius Mirage.
    """
    origin = getattr(site, 'origin_url', None) or getattr(site, 'real_backend_url', None)
    if not origin:
        return HttpResponse('Origin not configured', status=502)

    origin = origin.rstrip('/')
    url    = f"{origin}{path}"
    qs     = request.META.get('QUERY_STRING', '')
    if qs:
        url = f"{url}?{qs}"

    # Forward headers — strip hop-by-hop and our own platform headers
    fwd_headers = {}
    for key, val in request.META.items():
        if key.startswith('HTTP_'):
            hdr = key[5:].replace('_', '-').title()
            if hdr.lower() not in ('host', 'connection', 'transfer-encoding',
                                   'te', 'upgrade', 'proxy-connection'):
                fwd_headers[hdr] = val

    fwd_headers['X-Real-IP']       = _get_ip(request)
    fwd_headers['X-Forwarded-For'] = _get_ip(request)

    try:
        origin_resp = http_client.request(
            method=request.method,
            url=url,
            headers=fwd_headers,
            data=raw_body.encode('utf-8', errors='replace') if raw_body else None,
            timeout=10,
            allow_redirects=False,
            stream=True,
        )

        # Stream the origin response back
        response = HttpResponse(
            content=origin_resp.content,
            status=origin_resp.status_code,
        )
        for k, v in origin_resp.headers.items():
            if k.lower() not in ('transfer-encoding', 'connection', 'content-encoding'):
                response[k] = v
        return response

    except http_client.exceptions.Timeout:
        return HttpResponse('Gateway Timeout', status=504)
    except http_client.exceptions.ConnectionError:
        return HttpResponse('Bad Gateway', status=502)
    except Exception as exc:
        logger.error('[SwapLayer] Proxy forward error: %s', exc)
        return HttpResponse('Bad Gateway', status=502)


# ═══════════════════════════════════════════════════════════════════════════════
# LOGGING — record every decoy interaction to the dashboard
# ═══════════════════════════════════════════════════════════════════════════════

def _log_decoy_interaction(session, site, request_data: Dict, decoy):
    """Save every decoy interaction to DeceptionInteraction for the dashboard."""
    try:
        from base.models import DeceptionInteraction, AttackerProfile, DeceptionEnvironment

        # Get or create attacker profile
        attacker, _ = AttackerProfile.objects.get_or_create(
            session_id=session.session_id,
            defaults={
                'ip_address':     session.ip_address,
                'user_agent':     request_data.get('user_agent', ''),
                'first_seen':     timezone.now(),
                'last_seen':      timezone.now(),
                'threat_level':   session.threat_level,
                'interaction_count': 1,
            },
        )
        if not _: # Already existed
            attacker.last_seen = timezone.now()
            attacker.interaction_count += 1
            attacker.save(update_fields=['last_seen', 'interaction_count'])

        # Get or create the DeceptionEnvironment for this session
        env, _ = DeceptionEnvironment.objects.get_or_create(
            active_session=session,
            defaults={
                'name':        f"Decoy for {session.domain} / {session.session_id[:8]}",
                'type':        'api',
                'status':      'active',
                'description': f"Auto-generated decoy for flagged session {session.session_id[:8]}",
                'site':        site,
                'deception_level': 'intermediate',
            },
        )

        # Record the interaction
        DeceptionInteraction.objects.create(
            environment=env,
            attacker=attacker,
            request_path=request_data.get('path', '/'),
            request_method=request_data.get('method', 'GET'),
            request_headers=request_data.get('headers', {}),
            request_body=str(request_data.get('body', ''))[:2000],
            response_status=decoy.status_code,
            response_body=str(decoy.body)[:2000],
            response_time_ms=decoy.response_delay_ms,
            was_deceptive=True,
            triggered_alert=True,
            technique_detected=decoy.deception_note[:200],
            timestamp=timezone.now(),
        )

        # Update environment counters
        DeceptionEnvironment.objects.filter(pk=env.pk).update(
            total_interactions=env.total_interactions + 1,
            last_triggered=timezone.now(),
            status='active',
        )

    except Exception as exc:
        logger.warning('[SwapLayer] Interaction logging error: %s', exc)


# ═══════════════════════════════════════════════════════════════════════════════
# SMALL HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _get_ip(request) -> str:
    xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
    return xff.split(',')[0].strip() or request.META.get('REMOTE_ADDR', '0.0.0.0')


def _extract_headers(request) -> Dict:
    h = {}
    for k, v in request.META.items():
        if k.startswith('HTTP_'):
            h[k[5:].replace('_', '-').title()] = v
    return h


def _resolve_session_id(request) -> str:
    import hashlib
    try:
        sid = request.session.get('_gm_session_id')
        if sid:
            return sid
    except Exception:
        pass
    ip = _get_ip(request)
    ua = request.META.get('HTTP_USER_AGENT', '')
    return hashlib.md5(f"{ip}:{ua[:60]}".encode()).hexdigest()


def _get_or_init_session(session_id: str, site, request):
    from base.models import ActiveSession
    session, _ = ActiveSession.objects.get_or_create(
        session_id=session_id,
        defaults={
            'domain':           site.domain,
            'ip_address':       _get_ip(request),
            'start_time':       timezone.now(),
            'last_activity':    timezone.now(),
            'backend_type':     'real',
            'threat_level':     'low',
            'engagement_status': 'learning',
            'interaction_count': 0,
            'detected_techniques': [],
            'site':             site,
            'is_active':        True,
        },
    )
    return session


def _get_profile(site):
    try:
        return site.profile
    except Exception:
        return None


def _recent_logs(session_id: str) -> list:
    try:
        from base.models import ActivityLog
        return list(
            ActivityLog.objects.filter(session_id=session_id)
            .order_by('-timestamp')[:30]
            .values('timestamp', 'method', 'endpoint', 'user_agent',
                    'status_code', 'suspicion_score', 'response_time')
        )
    except Exception:
        return []


def _verify_request_auth(request, site):
    """Verify the SDK token on requests from client sites."""
    from django.conf import settings
    import hashlib
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Token '):
        raise PermissionError('Missing auth token')
    token = auth[6:]
    expected = hashlib.md5(
        f"{site.id}:{site.domain}:{settings.SECRET_KEY}".encode()
    ).hexdigest()[:32]
    if token != expected:
        raise PermissionError('Invalid auth token')


# ═══════════════════════════════════════════════════════════════════════════════
# MODE 4 — COMBINED PROCESS ENDPOINT (v5.1)
# Primary SDK entry point for sites running their own server (Flask/Django/
# Express SDK). One request → full evaluation (if not yet flagged) → decoy
# response (if flagged) — all in a single round trip.
#
# This is what makes JS-snippet-free, full-fidelity evaluation possible: the
# SDK sees the REAL method, body, and headers of every request (including POST
# form submissions), so SQL injection in a login form, command injection in a
# "tools" feature, etc. are all visible to Tier 1/2/3 — not just GET query
# strings as with the JS snippet alone.
# ═══════════════════════════════════════════════════════════════════════════════

def swap_process_view(request):
    """
    POST /api/swap/process/

    Request JSON:
        {
          "session_id":   "...",
          "site_id":      "site-...",
          "path":         "/login",
          "method":       "POST",
          "query_string": "",
          "body":         "username=admin&password=' OR '1'='1",
          "user_agent":   "...",
          "headers":      {...},
          "ip_address":   "203.0.113.7"   (optional — SDK's view of client IP)
        }

    Response JSON (clean session):
        {"backend_type": "real", "eval": {"tier": 2, "score": 18}}

    Response JSON (flagged session — decoy ready to serve):
        {
          "backend_type": "deceptive",
          "status_code": 200, "content_type": "application/json",
          "body": "...", "headers": {...}, "response_delay_ms": 180,
          "eval": {"tier": 1, "score": 100, "threat_level": "critical",
                   "techniques": [...]}
        }

    Evaluation only runs while the session is NOT yet flagged. Once flagged,
    this endpoint skips straight to decoy generation for the rest of that
    attacker's session.
    """
    from django.http import JsonResponse
    from base.models import ActiveSession, RegisteredSite, ActivityLog
    from base.services.threat_evaluator import evaluate_session
    from base.services.decoy_engine import generate_decoy_response

    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)

    try:
        data = json.loads(request.body)
    except Exception:
        return JsonResponse({'error': 'Invalid JSON'}, status=400)

    site_id    = data.get('site_id', '')
    session_id = data.get('session_id', '')

    if not site_id or not session_id:
        return JsonResponse({'backend_type': 'real'})

    try:
        site = RegisteredSite.objects.get(id=site_id, status__in=['active', 'monitoring'])
    except RegisteredSite.DoesNotExist:
        return JsonResponse({'error': 'Unknown or inactive site'}, status=404)

    try:
        _verify_request_auth(request, site)
    except Exception:
        return JsonResponse({'error': 'Unauthorised'}, status=403)

    ip = data.get('ip_address') or '0.0.0.0'

    request_data = {
        'path':               data.get('path', '/'),
        'method':             data.get('method', 'GET'),
        'body':               data.get('body', ''),
        'query_string':       data.get('query_string', ''),
        'user_agent':         data.get('user_agent', ''),
        'headers':            data.get('headers', {}) or {},
        'noscript_triggered': bool(cache.get(f'noscript_flag:{session_id}')),
        # NEW — used by webhook_guard.py (T1-14) to catch forged/self-issued
        # payment-gateway callbacks. The SDK marks these based on the
        # GENIUS_MIRAGE_WEBHOOK_PATHS / GENIUS_MIRAGE_PAYMENT_INITIATE_PATHS
        # settings on the client site.
        'is_webhook_path':          bool(data.get('is_webhook_path')),
        'is_payment_initiate_path': bool(data.get('is_payment_initiate_path')),
        'ip_address':               ip,
        'site_id':                  site_id,
    }

    # If this request hit a declared "payment initiate" path, remember this
    # IP so a follow-up direct hit on the webhook path can be correlated
    # (T1-14 / WH-03 in webhook_guard.py).
    if request_data['is_payment_initiate_path']:
        try:
            from base.services.webhook_guard import mark_payment_initiate
            mark_payment_initiate(ip, site_id)
        except Exception:
            logger.debug("webhook_guard.mark_payment_initiate failed", exc_info=True)

    session, _created = ActiveSession.objects.get_or_create(
        session_id=session_id,
        defaults={
            'domain':            site.domain,
            'ip_address':        ip,
            'start_time':        timezone.now(),
            'last_activity':     timezone.now(),
            'backend_type':      'real',
            'threat_level':      'low',
            'engagement_status': 'learning',
            'interaction_count': 0,
            'detected_techniques': [],
            'site':              site,
            'is_active':         True,
        },
    )

    site_profile = _get_profile(site)

    # Previously this only ran while `session.backend_type != 'deceptive'` —
    # meaning the FIRST time a session got flagged, every subsequent request
    # from it was served a decoy without ever being evaluated again. That
    # silently broke three things at once: detected_techniques froze at
    # whatever was caught first (never reflecting later, different attacks
    # in the same session), every later ActivityLog row got suspicion_score
    # 0 (since there was no fresh eval_result to pull it from — this is
    # what made Activity Monitoring's flagged-rate metric read near 0%
    # despite `flagged=True` being set correctly), and Threat creation
    # below (which requires a non-None eval_result) could only ever fire
    # once per session's entire lifetime, no matter how many genuinely
    # different techniques were tried afterward.
    #
    # Always evaluating costs more (a Tier 3 AI call is possible on every
    # request instead of just the first), but Tier 1's deterministic
    # tripwires are cheap and fire immediately for continued attack
    # traffic, so the common case — the same attacker continuing the same
    # behavior — mostly short-circuits at Tier 1 anyway.
    recent_logs = _recent_logs(session_id)
    eval_result = evaluate_session(
        session=session,
        activity_logs=recent_logs,
        site_profile=site_profile,
        request_data=request_data,
    )

    session.threat_level = eval_result.threat_level
    if eval_result.flagged:
        session.backend_type      = 'deceptive'
        session.engagement_status = 'deceiving'
        techs = set(session.detected_techniques or [])
        techs.update(eval_result.techniques)
        session.detected_techniques = list(techs)
    else:
        session.engagement_status = 'analyzing' if eval_result.score >= 25 else 'learning'

    session.interaction_count += 1
    session.last_activity = timezone.now()
    if ip and ip != '0.0.0.0':
        session.ip_address = ip
    session.save()

    log = ActivityLog.objects.create(
        timestamp=timezone.now(),
        domain=site.domain,
        session_id=session_id,
        ip_address=ip,
        user_agent=request_data['user_agent'][:500],
        endpoint=request_data['path'][:500],
        method=request_data['method'][:10],
        status_code=200,
        response_time=0,
        suspicion_score=(eval_result.score if eval_result else 0),
        flagged=(session.backend_type == 'deceptive'),
        site=site,
        active_session=session,
        noscript_triggered=request_data['noscript_triggered'],
        eval_tier=(eval_result.tier if eval_result else 0),
        eval_reasons=(eval_result.reasons[:10] if eval_result else []),
    )

    if eval_result and eval_result.flagged:
        existing_indicators = set((session.threat.indicators or [])) if session.threat else set()
        new_techniques = set(eval_result.techniques or []) - existing_indicators
        if session.threat is None or new_techniques:
            _create_swap_threat_record(session, eval_result, site.domain, ip, site, log)

    try:
        site.sessions_monitored = (
            ActivityLog.objects.filter(site=site).values('session_id').distinct().count()
        )
        if session.backend_type == 'deceptive':
            site.threats_detected = ActivityLog.objects.filter(site=site, flagged=True).count()
        site.last_activity = timezone.now()
        site.save(update_fields=['sessions_monitored', 'threats_detected', 'last_activity'])
    except Exception as exc:
        logger.warning('[SwapLayer] Site counter update error: %s', exc)

    if session.backend_type == 'deceptive':
        # Manual gate: the session is flagged (backend_type='deceptive') but
        # the actual swap only engages if an operator has explicitly approved
        # it via the Active Sessions dashboard ("Approve Swap" button).
        # Until approved, we return 'flagged_pending_approval' so the SDK
        # continues serving real responses while the operator reviews the AI
        # analysis — detection is happening, the swap just isn't deployed yet.
        if not session.swap_approved:
            return JsonResponse({
                'backend_type': 'real',
                'flagged':       True,
                'swap_pending':  True,
                'eval': {
                    'tier':        eval_result.tier if eval_result else None,
                    'score':       eval_result.score if eval_result else None,
                    'threat_level': session.threat_level,
                    'techniques':  session.detected_techniques,
                },
            })
        decoy = generate_decoy_response(session, request_data, site_profile)
        _log_decoy_interaction(session, site, request_data, decoy)

        return JsonResponse({
            'backend_type':      'deceptive',
            'status_code':       decoy.status_code,
            'content_type':      decoy.content_type,
            'body':              decoy.body,
            'headers':           decoy.headers,
            'response_delay_ms': decoy.response_delay_ms,
            'eval': {
                'tier':         eval_result.tier if eval_result else None,
                'score':        eval_result.score if eval_result else None,
                'threat_level': session.threat_level,
                'techniques':   session.detected_techniques,
            },
        })

    return JsonResponse({
        'backend_type': 'real',
        'eval': {
            'tier':  eval_result.tier if eval_result else None,
            'score': eval_result.score if eval_result else 0,
        },
    })


def _create_swap_threat_record(session, eval_result, domain: str, ip: str, site, activity_log):
    """
    Threat-record creation used by swap_process_view. Mirrors
    DeceptionTrackingMiddleware._create_threat_record so dashboards behave
    identically regardless of which integration path flagged a session.
    """
    try:
        from base.models import Threat
        severity_map = {'low': 'low', 'medium': 'medium', 'high': 'high', 'critical': 'critical'}
        threat = Threat.objects.create(
            timestamp=timezone.now(),
            domain=domain,
            session_id=session.session_id,
            ip_address=ip,
            threat_type=', '.join(eval_result.techniques[:3]) or 'Unknown',
            severity=severity_map.get(eval_result.threat_level, 'medium'),
            indicators=eval_result.techniques,
            status='active',
            description=eval_result.explanation or f"Tier {eval_result.tier} evaluation flagged this session.",
            site=site,
            activity_log=activity_log,
            ai_confidence=eval_result.confidence / 100.0,
            risk_score=eval_result.score,
            technique=', '.join(eval_result.techniques[:5]),
        )
        session.threat = threat
        session.save(update_fields=['threat'])

        from base.services.attack_pattern_tracker import record_attack_patterns
        record_attack_patterns(eval_result, threat)
    except Exception as exc:
        logger.warning('[SwapLayer] Failed to create Threat record: %s', exc)
