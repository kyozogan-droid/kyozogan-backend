"""
deception_middleware.py
=======================
Drop this file into your Django app directory (same folder as models.py).
Then register it in settings.py:

    MIDDLEWARE = [
        ...
        'base.deception_middleware.DeceptionTrackingMiddleware',
    ]

What this middleware does (v5 — Three-Tier Evaluation)
======================================================
For every inbound HTTP request to a monitored registered-site domain:

  1. Extracts full request context (IP, UA, path, body, headers, session ID).
  2. Passes all context into the Three-Tier Evaluation Engine:
       Tier 1 — Deterministic wiretrips (instant binary flag)
       Tier 2 — Behavioural anomaly score accumulation
       Tier 3 — Groq AI contextual intent analysis (grey-zone sessions only)
  3. Creates / updates ActivityLog and ActiveSession records.
  4. Stamps request._evaluation_result so views/serializers can act on it.
  5. Emits a NO-JS noscript beacon endpoint (/api/track/noscript/) so sessions
     that disabled JavaScript are silently flagged at Tier 1.

The middleware NEVER crashes the request pipeline — all exceptions are caught
and logged.
"""

import time
import uuid
import re
import json
import logging
from django.utils import timezone
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

# ── Paths that should never be logged ───────────────────────────────────────
SKIP_PATHS = re.compile(
    r'^('
    r'/admin/'
    r'|/static/'
    r'|/media/'
    r'|/favicon\.ico'
    r'|/__debug__'
    r'|/api/auth/'
    r'|/api/track/'
    r'|/api/global/'
    r')',
    re.IGNORECASE,
)


class DeceptionTrackingMiddleware(MiddlewareMixin):
    """
    Middleware that logs all inbound HTTP requests, runs the three-tier
    evaluation engine, and updates ActiveSession / ActivityLog records.
    Must be placed AFTER session middleware in the MIDDLEWARE list.
    """

    def process_request(self, request):
        request._deception_start_time = time.monotonic()

        # Read and cache raw body so it can be inspected in process_response
        # (Django's request.body is a stream that can only be read once)
        try:
            request._deception_body = request.body.decode('utf-8', errors='replace')
        except Exception:
            request._deception_body = ''

        # Check if this session previously fired the noscript beacon
        # If so, stamp the flag onto the request so Tier 1 sees it
        try:
            from django.core.cache import cache as _cache
            if not hasattr(request, 'session'):
                request._noscript_flag = False
            else:
                sid = request.session.get('_deception_session_id', '')
                if sid:
                    request._noscript_flag = bool(_cache.get(f'noscript_flag:{sid}'))
                else:
                    request._noscript_flag = False
        except Exception:
            request._noscript_flag = False

    def process_response(self, request, response):
        if SKIP_PATHS.match(request.path):
            return response

        host = request.get_host().split(':')[0].lower()
        if not self._is_monitored_domain(host):
            return response

        try:
            self._record_and_evaluate(request, response, host)
        except Exception as exc:
            logger.exception("DeceptionTrackingMiddleware error: %s", exc)

        return response

    # ── Private helpers ──────────────────────────────────────────────────────

    def _is_monitored_domain(self, host: str) -> bool:
        try:
            from .models import RegisteredSite
            return RegisteredSite.objects.filter(
                domain__iexact=host, status__in=['active', 'monitoring']
            ).exists()
        except Exception:
            return False

    def _get_registered_site(self, host: str):
        try:
            from .models import RegisteredSite
            return RegisteredSite.objects.filter(domain__iexact=host).first()
        except Exception:
            return None

    def _get_client_ip(self, request) -> str:
        xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
        if xff:
            return xff.split(',')[0].strip()
        return request.META.get('REMOTE_ADDR', '0.0.0.0')

    def _get_or_create_session_id(self, request) -> str:
        if not hasattr(request, 'session'):
            return str(uuid.uuid4())
        session_id = request.session.get('_deception_session_id')
        if not session_id:
            session_id = str(uuid.uuid4())
            try:
                request.session['_deception_session_id'] = session_id
                request.session.modified = True
            except Exception:
                pass
        return session_id

    def _extract_headers(self, request) -> dict:
        """Extract relevant request headers as a plain dict."""
        headers = {}
        for key in ('HTTP_ACCEPT', 'HTTP_ACCEPT_ENCODING', 'HTTP_ACCEPT_LANGUAGE',
                    'HTTP_CONTENT_TYPE', 'HTTP_X_FORWARDED_FOR', 'CONTENT_TYPE',
                    'HTTP_AUTHORIZATION', 'HTTP_REFERER', 'HTTP_ORIGIN'):
            val = request.META.get(key, '')
            if val:
                clean_key = key.replace('HTTP_', '').replace('_', '-').title()
                headers[clean_key] = val
        return headers

    def _build_request_data(self, request, response) -> dict:
        """Build the request_data dict for the evaluation engine."""
        return {
            'path':               request.path,
            'user_agent':         request.META.get('HTTP_USER_AGENT', ''),
            'method':             request.method,
            'body':               getattr(request, '_deception_body', ''),
            'query_string':       request.META.get('QUERY_STRING', ''),
            'headers':            self._extract_headers(request),
            'noscript_triggered': getattr(request, '_noscript_flag', False),
            'status_code':        response.status_code,
        }

    def _get_or_create_active_session(self, session_id: str, ip: str,
                                       host: str, site):
        """Fetch or create the ActiveSession row — never crashes."""
        from .models import ActiveSession
        try:
            session = ActiveSession.objects.get(session_id=session_id)
            return session, False
        except ActiveSession.DoesNotExist:
            session = ActiveSession.objects.create(
                session_id=session_id,
                domain=host,
                ip_address=ip,
                start_time=timezone.now(),
                last_activity=timezone.now(),
                backend_type='real',
                threat_level='low',
                interaction_count=0,
                engagement_status='learning',
                detected_techniques=[],
                site=site,
                is_active=True,
            )
            return session, True

    def _get_recent_logs(self, session_id: str, limit: int = 30) -> list:
        """Return last N ActivityLog rows for a session as dicts."""
        try:
            from .models import ActivityLog
            logs = ActivityLog.objects.filter(
                session_id=session_id
            ).order_by('-timestamp')[:limit]
            result = []
            for log in reversed(list(logs)):
                result.append({
                    'timestamp':     log.timestamp,
                    'method':        log.method,
                    'endpoint':      log.endpoint,
                    'user_agent':    log.user_agent,
                    'status_code':   log.status_code,
                    'suspicion_score': log.suspicion_score,
                    'response_time': log.response_time,
                })
            return result
        except Exception:
            return []

    def _get_site_profile(self, site):
        try:
            if site:
                return site.profile
        except Exception:
            pass
        return None

    def _record_and_evaluate(self, request, response, host: str):
        from .models import ActivityLog, ActiveSession

        ip         = self._get_client_ip(request)
        session_id = self._get_or_create_session_id(request)
        ua         = request.META.get('HTTP_USER_AGENT', '')
        method     = request.method
        endpoint   = request.path
        status_code = response.status_code
        response_time = int(
            (time.monotonic() - getattr(request, '_deception_start_time', time.monotonic())) * 1000
        )

        site         = self._get_registered_site(host)
        site_profile = self._get_site_profile(site)

        # Fetch / create session row FIRST so we can pass it to evaluator
        active_session, is_new = self._get_or_create_active_session(
            session_id, ip, host, site
        )

        # Build the live request data dict
        request_data = self._build_request_data(request, response)

        # Get recent logs for the evaluator (Tier 2 and 3 need history)
        recent_logs = self._get_recent_logs(session_id)

        # ── Run the Three-Tier Evaluation Engine ─────────────────────────────
        from .services.threat_evaluator import evaluate_session
        eval_result = evaluate_session(
            session=active_session,
            activity_logs=recent_logs,
            site_profile=site_profile,
            request_data=request_data,
            session_data=None,          # evaluator builds this from logs
        )

        # Stamp result onto request so views can read it synchronously
        request._evaluation_result = eval_result

        # ── 1. Create ActivityLog ─────────────────────────────────────────────
        log = ActivityLog(
            timestamp=timezone.now(),
            domain=host,
            session_id=session_id,
            ip_address=ip,
            user_agent=ua,
            endpoint=endpoint,
            method=method,
            status_code=status_code,
            response_time=response_time,
            suspicion_score=eval_result.score,
            flagged=eval_result.flagged,
            site=site,
            active_session=active_session,
            noscript_triggered=request_data.get('noscript_triggered', False),
            eval_tier=eval_result.tier,
            eval_reasons=eval_result.reasons[:10],  # cap at 10 entries
        )
        log.save()

        # ── 2. Update ActiveSession ───────────────────────────────────────────
        active_session.interaction_count += 1
        active_session.last_activity      = timezone.now()
        active_session.threat_level       = eval_result.threat_level
        active_session.backend_type       = 'deceptive' if eval_result.flagged else 'real'
        active_session.engagement_status  = self._determine_engagement(eval_result)
        active_session.is_active          = True

        # Merge techniques without duplicates
        existing_techniques = set(active_session.detected_techniques or [])
        existing_techniques.update(eval_result.techniques)
        active_session.detected_techniques = list(existing_techniques)

        active_session.save(update_fields=[
            'interaction_count', 'last_activity', 'threat_level',
            'backend_type', 'engagement_status', 'detected_techniques', 'is_active',
        ])

        # ── 3. Update RegisteredSite aggregate counters ───────────────────────
        if site:
            try:
                from django.db.models import Count
                site.sessions_monitored = (
                    ActivityLog.objects.filter(site=site)
                    .values('session_id').distinct().count()
                )
                if eval_result.flagged:
                    site.threats_detected = ActivityLog.objects.filter(
                        site=site, flagged=True
                    ).count()
                site.last_activity = timezone.now()
                site.save(update_fields=['sessions_monitored', 'threats_detected', 'last_activity'])
            except Exception as exc:
                logger.warning("Site aggregate update error: %s", exc)

        # ── 4. Create a Threat record for the first flag, or for any
        #      genuinely new technique(s) discovered later in the same
        #      session — a long-lived flagged session that tries several
        #      different attack types should show up as more than one
        #      Threat, not just whichever technique happened to trip first.
        if eval_result.flagged:
            existing_indicators = set((active_session.threat.indicators or [])) if active_session.threat else set()
            new_techniques = set(eval_result.techniques or []) - existing_indicators
            if active_session.threat is None or new_techniques:
                self._create_threat_record(active_session, eval_result, host, ip, site, log)

    def _create_threat_record(self, session, eval_result, host, ip, site, activity_log):
        """Create a Threat entry the first time a session is flagged."""
        try:
            from .models import Threat
            severity_map = {
                'low': 'low', 'medium': 'medium',
                'high': 'high', 'critical': 'critical',
            }
            threat = Threat.objects.create(
                timestamp=timezone.now(),
                domain=host,
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

            from .services.attack_pattern_tracker import record_attack_patterns
            record_attack_patterns(eval_result, threat)
        except Exception as exc:
            logger.warning("Failed to create Threat record: %s", exc)

    @staticmethod
    def _determine_engagement(eval_result) -> str:
        if eval_result.flagged:
            return 'deceiving'
        if eval_result.score >= 25:
            return 'analyzing'
        return 'learning'
