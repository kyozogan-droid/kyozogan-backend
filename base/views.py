import hashlib
import json
import logging
import re
import base64
from urllib.parse import urlparse
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

from django.contrib.auth import authenticate
from django.core.cache import cache
from django.db.models import Count, Q, Avg, F, Sum, Max, Min
from django.http import HttpResponse, JsonResponse
from django.utils import timezone
from django.views.decorators.csrf import csrf_exempt

from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAuthenticated, IsAdminUser
from base.permissions import IsAppAdminUser
from rest_framework.response import Response
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.db.models import F
from rest_framework_simplejwt.tokens import RefreshToken

from django.conf import settings
from django.db import models

from .models import *  # includes Payment, SiteProfile, etc.
from .serializers import *


# ═══════════════════════════════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['POST'])
@permission_classes([AllowAny])
def register(request):
    serializer = RegisterSerializer(data=request.data)
    if serializer.is_valid():
        user = serializer.save()
        refresh = RefreshToken.for_user(user)
        return Response({
            'user': UserSerializer(user).data,
            'access': str(refresh.access_token),
            'refresh': str(refresh),
        }, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@permission_classes([AllowAny])
def login(request):
    email    = request.data.get('email', '').strip().lower()
    password = request.data.get('password', '')
    if not email or not password:
        return Response({'error': 'Email and password are required.'}, status=400)
    user = authenticate(request, username=email, password=password)
    if not user:
        return Response({'error': 'Invalid email or password.'}, status=401)
    refresh = RefreshToken.for_user(user)
    return Response({
        'user': UserSerializer(user).data,
        'access': str(refresh.access_token),
        'refresh': str(refresh),
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def me(request):
    return Response(UserSerializer(request.user).data)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def update_me(request):
    user = request.user
    if 'full_name'    in request.data: user.full_name    = request.data['full_name']
    if 'company_name' in request.data: user.company_name = request.data['company_name']
    user.save(update_fields=['full_name', 'company_name'])
    return Response(UserSerializer(user).data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def change_password(request):
    user = request.user
    current = request.data.get('current_password', '')
    new_pw  = request.data.get('new_password', '')

    if not user.check_password(current):
        return Response({'error': 'Current password is incorrect'}, status=400)
    if len(new_pw) < 8:
        return Response({'error': 'Password must be at least 8 characters'}, status=400)

    user.set_password(new_pw)
    user.save()
    return Response({'ok': True})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout(request):
    return Response({'message': 'Logged out successfully. Please discard your tokens.'})


# ═══════════════════════════════════════════════════════════════════════════════
# SITES
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def sites(request):
    if request.method == 'GET':
        sites_qs = RegisteredSite.objects.filter(owner_user=request.user)
        serializer = RegisteredSiteSerializer(sites_qs, many=True)
        return Response(serializer.data)

    if request.method == 'POST':
        limit = request.user.plan_limits.get('sites', -1)
        if limit != -1:
            current_count = RegisteredSite.objects.filter(owner_user=request.user).count()
            if current_count >= limit:
                return Response({
                    'error': f"Your {request.user.get_plan_display()} plan allows up to "
                             f"{limit} registered site(s). Upgrade your plan to add more.",
                    'plan_limit_reached': True,
                    'limit': limit,
                    'current_count': current_count,
                }, status=status.HTTP_403_FORBIDDEN)

    serializer = SiteCreateSerializer(data=request.data, context={'request': request})
    if serializer.is_valid():
        site = serializer.save()
        cache.delete(f'site_{site.domain}_active_sessions')
        cache.delete(f'site_{site.id}_metrics')

        # Auto-profile in background thread — returns immediately to the caller
        import threading
        def _run_profile(site_id):
            try:
                from .models import RegisteredSite as RS
                from .services.global_ai_analyzer import profile_site
                s = RS.objects.get(id=site_id)
                profile_site(s)
                print(f"[profiler] {s.domain} profiled OK")
            except Exception as exc:
                print(f"[profiler] Failed for site {site_id}: {exc}")
        threading.Thread(target=_run_profile, args=(site.id,), daemon=True).start()

        return Response(RegisteredSiteSerializer(site).data, status=status.HTTP_201_CREATED)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def site_detail(request, site_id):
    try:
        site = RegisteredSite.objects.get(id=site_id, owner_user=request.user)
    except RegisteredSite.DoesNotExist:
        return Response({'error': 'Site not found'}, status=404)

    if request.method == 'GET':
        return Response(RegisteredSiteSerializer(site).data)

    if request.method == 'PUT':
        serializer = RegisteredSiteSerializer(site, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=400)

    site.delete()
    return Response({'message': 'Site deleted successfully'}, status=204)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_site_metrics(request, site_id):
    try:
        site = RegisteredSite.objects.get(id=site_id, owner_user=request.user)
    except RegisteredSite.DoesNotExist:
        return Response({'error': 'Site not found'}, status=404)

    site.sessions_monitored += request.data.get('sessions_monitored', 0)
    site.threats_detected   += request.data.get('threats_detected', 0)
    site.save()
    return Response(RegisteredSiteSerializer(site).data)


# ═══════════════════════════════════════════════════════════════════════════════
# SNIPPET  (FIXED — now generates inline JS, not a <script src> tag)
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_installation_snippet(request, site_id):
    try:
        site = RegisteredSite.objects.get(id=site_id, owner_user=request.user)
    except RegisteredSite.DoesNotExist:
        return Response({'error': 'Site not found'}, status=404)

    site_token = hashlib.md5(
        f"{site.id}:{site.domain}:{settings.SECRET_KEY}".encode()
    ).hexdigest()[:32]

    track_url = request.build_absolute_uri('/api/track/public/')

    # ── IMPROVED Universal inline snippet with better error handling ──
    universal_snippet = f"""<!-- Genius Mirage Tracker — paste just before </body> -->
<script>
(function() {{
    'use strict';
    
    // Configuration
    var _gm = {{
        site: "{site.id}",
        token: "{site_token}",
        url: "{track_url}"
    }};
    
    // Queue for requests if sendBeacon fails
    var pendingRequests = [];
    
    function send(extra) {{
        var payload = {{
            site_id: _gm.site,
            token: _gm.token,
            page_url: window.location.href,
            referrer: document.referrer,
            user_agent: navigator.userAgent,
            timestamp: Date.now()
        }};
        
        // Merge extra data if provided
        if (extra) {{
            for (var key in extra) {{
                if (extra.hasOwnProperty(key)) {{
                    payload[key] = extra[key];
                }}
            }}
        }}
        
        // Use sendBeacon for page unload, fetch for regular requests
        if (extra && extra.event === 'unload') {{
            if (navigator.sendBeacon) {{
                var blob = new Blob([JSON.stringify(payload)], {{type: 'application/json'}});
                navigator.sendBeacon(_gm.url, blob);
            }}
        }} else {{
            // Use fetch with timeout
            fetch(_gm.url, {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify(payload),
                keepalive: true
            }}).catch(function(err) {{
                console.warn('[GM] Tracking failed:', err);
                // Queue failed request
                pendingRequests.push(payload);
                // Try to replay after 5 seconds
                setTimeout(replayPending, 5000);
            }});
        }}
    }}
    
    function replayPending() {{
        if (pendingRequests.length === 0) return;
        var requests = pendingRequests.slice();
        pendingRequests = [];
        requests.forEach(function(payload) {{
            fetch(_gm.url, {{
                method: 'POST',
                headers: {{'Content-Type': 'application/json'}},
                body: JSON.stringify(payload),
                keepalive: true
            }}).catch(function() {{
                pendingRequests.push(payload);
            }});
        }});
    }}
    
    // Send pageview when DOM is ready
    if (document.readyState === 'loading') {{
        document.addEventListener('DOMContentLoaded', function() {{
            send({{ event: 'pageview' }});
        }});
    }} else {{
        send({{ event: 'pageview' }});
    }}
    
    // Track clicks on links and buttons
    document.addEventListener('click', function(e) {{
        var target = e.target.closest('a, button');
        if (target) {{
            var targetUrl = target.href || target.tagName;
            send({{ event: 'click', target: targetUrl }});
        }}
    }});
    
    // Track page unload
    window.addEventListener('beforeunload', function() {{
        send({{ event: 'unload' }});
    }});
    
    // Optional: Log that tracker is loaded (remove in production)
    // console.log('[GM] Tracker loaded for site:', _gm.site);
}})();
</script>
<!-- End Genius Mirage Tracker -->"""

    react_snippet = f"""// components/GeniusMirageTracker.tsx
'use client';

import {{ useEffect }} from 'react';

const TRACK_URL = "{track_url}";
const SITE_ID   = "{site.id}";
const TOKEN     = "{site_token}";

export default function GeniusMirageTracker() {{
  useEffect(() => {{
    const payload = {{
      site_id:    SITE_ID,
      token:      TOKEN,
      page_url:   window.location.href,
      referrer:   document.referrer,
      user_agent: navigator.userAgent,
      timestamp:  Date.now(),
      event:      'pageview',
    }};
    const blob = new Blob([JSON.stringify(payload)], {{ type: 'application/json' }});
    navigator.sendBeacon(TRACK_URL, blob);
  }}, []);
  return null;
}}
// Add <GeniusMirageTracker /> to your root layout or _app.tsx"""

    platforms = [
        {
            'id': 'html',
            'label': 'HTML / Static',
            'steps': [
                'Copy the snippet below.',
                'Paste it just before the closing </body> tag on every page.',
                'Save and redeploy.',
                'Click "Check Installation" to confirm.',
            ],
            'snippet': universal_snippet,
        },
        {
            'id': 'react',
            'label': 'React / Next.js',
            'steps': [
                'Create components/GeniusMirageTracker.tsx with the code below.',
                'Import and render <GeniusMirageTracker /> in your root layout.',
                'For Next.js App Router add "use client" at the top.',
                'Deploy, then click "Check Installation".',
            ],
            'snippet': react_snippet,
        },
        {
            'id': 'wordpress',
            'label': 'WordPress',
            'steps': [
                'Log in to WP Admin.',
                'Go to Appearance → Theme File Editor → footer.php.',
                'Paste the universal snippet just before </body>.',
                'Click "Update File".',
            ],
            'snippet': universal_snippet,
        },
        {
            'id': 'shopify',
            'label': 'Shopify',
            'steps': [
                'Go to Online Store → Themes → Actions → Edit code.',
                'Open theme.liquid.',
                'Paste the universal snippet just before </body>.',
                'Save.',
            ],
            'snippet': universal_snippet,
        },
    ]

    return Response({
        'site_id':    site.id,
        'domain':     site.domain,
        'snippet':    universal_snippet,
        'ingest_url': track_url,
        'platforms':  platforms,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# VERIFY SNIPPET
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def verify_snippet_installation(request, site_id):
    """
    Two-stage verification:
    1. Fetch the target site's homepage and check that the GM snippet is in the HTML.
       This is the only trustworthy check — if the snippet is not in the page source,
       it is NOT installed, regardless of whether we have activity logs (which could
       come from manual API calls during development).
    2. If the page cannot be fetched (e.g. local dev site that our server can't reach),
       fall back to checking for recent ActivityLog rows from the LAST 5 MINUTES only —
       this proves live traffic is flowing through, not just old test calls.
    """
    try:
        site = RegisteredSite.objects.get(id=site_id, owner_user=request.user)
    except RegisteredSite.DoesNotExist:
        return Response({'error': 'Site not found'}, status=404)

    import requests as http_requests

    domain   = site.domain
    protocol = 'http' if ('localhost' in domain or '127.0.0.1' in domain) else 'https'

    # ── Stage 1: fetch the actual page and inspect the HTML ─────────────────
    try:
        try:
            resp = http_requests.get(
                f"{protocol}://{domain}/",
                timeout=10,
                verify=True,
                headers={'User-Agent': 'GeniusMirage-Verifier/1.0'},
            )
        except http_requests.exceptions.SSLError:
            # Invalid/self-signed cert on the client's site — retry once
            # without verification rather than disabling it unconditionally.
            logger.info('[Verifier] SSL cert issue on %s — retrying without verification', domain)
            import warnings, urllib3
            with warnings.catch_warnings():
                warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)
                resp = http_requests.get(
                    f"{protocol}://{domain}/",
                    timeout=10,
                    verify=False,
                    headers={'User-Agent': 'GeniusMirage-Verifier/1.0'},
                )
        html = resp.text

        # The snippet sets window._gm with the site id — both must be present
        snippet_marker  = '_gm'
        site_id_present = str(site.id) in html

        if snippet_marker in html and site_id_present:
            if site.status == 'monitoring':
                site.status = 'active'
                site.save(update_fields=['status'])
            return Response({'installed': True, 'method': 'html_scan'})

        # Page fetched but snippet not found
        return Response({
            'installed': False,
            'method':    'html_scan',
            'error':     'Snippet not found in page source. Make sure you pasted it before </body> and republished.',
        })

    except http_requests.exceptions.ConnectionError:
        pass   # Site unreachable from our server — try fallback
    except Exception as exc:
        pass   # Any other fetch error — try fallback

    # ── Stage 2: fallback — check for live traffic in the last 5 minutes ────
    # This covers the case where the site runs on a local/private network that
    # our Django server cannot reach, but the browser can.
    from django.utils import timezone as tz
    from datetime import timedelta
    recent_cutoff = tz.now() - timedelta(minutes=5)
    has_recent_traffic = ActivityLog.objects.filter(
        site=site,
        timestamp__gte=recent_cutoff,
    ).exists()

    if has_recent_traffic:
        if site.status == 'monitoring':
            site.status = 'active'
            site.save(update_fields=['status'])
        return Response({
            'installed': True,
            'method':    'live_traffic',
        })

    return Response({
        'installed': False,
        'method':    'fallback',
        'error':     (
            'Could not reach your site from our server. '
            'Paste the snippet in your site and visit a page — '
            'then click Check Installation again within 5 minutes.'
        ),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC TRACKING ENDPOINT  (FIXED — accepts JSON POST, returns JSON, adds CORS)
# ═══════════════════════════════════════════════════════════════════════════════

@csrf_exempt
def track_request_public(request):
    """
    Public tracking endpoint - no authentication required.
    Fixed CORS headers to work from any origin.
    """
    # CORS helper function
    def cors_response(data, status=200):
        response = JsonResponse(data, status=status)
        # Allow any origin to call this endpoint
        origin = request.headers.get('Origin', '*')
        response['Access-Control-Allow-Origin'] = origin
        response['Access-Control-Allow-Methods'] = 'POST, GET, OPTIONS'
        response['Access-Control-Allow-Headers'] = 'Content-Type'
        response['Access-Control-Allow-Credentials'] = 'true'
        response['Access-Control-Max-Age'] = '86400'
        return response

    # Handle preflight OPTIONS request (browser sends this first)
    if request.method == 'OPTIONS':
        return cors_response({})

    # Only accept POST requests
    if request.method != 'POST':
        return cors_response({'error': 'POST required'}, status=405)

    # Parse request body
    try:
        data = json.loads(request.body)
    except (json.JSONDecodeError, Exception) as exc:
        print(f"[tracker] JSON parse error: {exc}")
        return cors_response({'error': 'Invalid JSON'}, status=400)

    site_id = data.get('site_id') or data.get('site')
    token = data.get('token', '')

    if not site_id:
        return cors_response({'error': 'site_id required'}, status=400)

    # Find the site
    try:
        site = RegisteredSite.objects.get(id=site_id, status__in=['active', 'monitoring'])
    except RegisteredSite.DoesNotExist:
        print(f"[tracker] Unknown site_id={site_id}")
        return cors_response({'error': 'Unknown site'}, status=404)

    # Validate token
    expected_token = hashlib.md5(
        f"{site.id}:{site.domain}:{settings.SECRET_KEY}".encode()
    ).hexdigest()[:32]
    token_valid = (token == expected_token)

    # Get client IP
    raw_ip = (
        request.META.get('HTTP_X_FORWARDED_FOR', '').split(',')[0].strip()
        or request.META.get('REMOTE_ADDR', '')
    )
    
    import ipaddress
    try:
        ip = str(ipaddress.ip_address(raw_ip))
    except ValueError:
        ip = '127.0.0.1'

    user_agent = (data.get('user_agent') or request.META.get('HTTP_USER_AGENT', ''))[:500]
    page_url = data.get('page_url', '/')[:500]

    # Calculate suspicion score
    suspicion_score = _calc_suspicion(ip, user_agent, page_url)
    if not token_valid:
        suspicion_score = min(100, suspicion_score + 30)
    is_flagged = suspicion_score > 65

    # Generate session ID
    session_id = hashlib.md5(f"{ip}:{site.id}:{user_agent[:80]}".encode()).hexdigest()
    now = timezone.now()

    # Create ActivityLog
    activity_log = None
    try:
        activity_log = ActivityLog.objects.create(
            timestamp=now,
            domain=site.domain,
            session_id=session_id,
            ip_address=ip,
            user_agent=user_agent,
            endpoint=page_url,
            method='POST',
            status_code=200,
            response_time=0,
            suspicion_score=suspicion_score,
            flagged=is_flagged,
            site=site,
        )
        print(f"[tracker] ActivityLog created: {activity_log.id} for {site.domain}")
    except Exception as exc:
        print(f"[tracker] ActivityLog ERROR: {exc}")

    # Create or update ActiveSession
    session = None
    try:
        session, created = ActiveSession.objects.get_or_create(
            session_id=session_id,
            site=site,
            defaults={
                'domain': site.domain,
                'ip_address': ip,
                'backend_type': 'deceptive' if is_flagged else 'real',
                'threat_level': _threat_level(suspicion_score),
                'engagement_status': 'deceiving' if is_flagged else 'analyzing',
                'interaction_count': 1,
                'last_activity': now,
                'is_active': True,
            },
        )
        
        if not created:
            updated = ActiveSession.objects.filter(pk=session.pk).update(
                last_activity=now,
                interaction_count=F('interaction_count') + 1,
                is_active=True,
                backend_type='deceptive' if is_flagged else session.backend_type,
                engagement_status='deceiving' if is_flagged else session.engagement_status,
            )
            if updated:
                session.refresh_from_db()
        
        print(f"[tracker] ActiveSession {'created' if created else 'updated'}: {session.session_id[:8]}")
    except Exception as exc:
        print(f"[tracker] ActiveSession ERROR: {exc}")

    # Link ActivityLog to ActiveSession
    if activity_log and session:
        try:
            activity_log.active_session = session
            activity_log.save(update_fields=['active_session'])
        except Exception as exc:
            print(f"[tracker] Failed to link: {exc}")

    # Update site counters
    try:
        RegisteredSite.objects.filter(id=site.id).update(
            sessions_monitored=F('sessions_monitored') + 1,
            threats_detected=F('threats_detected') + (1 if is_flagged else 0),
            last_activity=now,
        )
        print(f"[tracker] Site {site.domain} updated: sessions={site.sessions_monitored + 1}")
    except Exception as exc:
        print(f"[tracker] Site counter ERROR: {exc}")

    # Create Threat if flagged
    if is_flagged and session:
        try:
            Threat.objects.get_or_create(
                session_id=session_id,
                site=site,
                defaults={
                    'timestamp': now,
                    'domain': site.domain,
                    'ip_address': ip,
                    'threat_type': 'Suspicious Activity Detected',
                    'severity': _threat_level(suspicion_score),
                    'indicators': [
                        f"Suspicion score: {suspicion_score}",
                        f"Path: {page_url[:100]}",
                    ],
                    'description': f"Suspicious activity from {ip} on {site.domain}",
                    'status': 'active',
                    'activity_log': activity_log,
                    'risk_score': suspicion_score,
                },
            )
            print(f"[tracker] Threat created for flagged session")
        except Exception as exc:
            print(f"[tracker] Threat creation ERROR: {exc}")

    return cors_response({
        'ok': True,
        'session_id': session_id,
        'suspicion_score': suspicion_score,
        'flagged': is_flagged,
    })

# ═══════════════════════════════════════════════════════════════════════════════
# ACTIVITY LOGS
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def activity_logs(request):
    if request.method == 'GET':
        qs = ActivityLog.objects.filter(site__owner_user=request.user).select_related('site')

        domain     = request.query_params.get('domain')
        ip_address = request.query_params.get('ip_address')
        session_id = request.query_params.get('session_id')
        flagged    = request.query_params.get('flagged')
        limit      = int(request.query_params.get('limit', 100))

        if domain:     qs = qs.filter(domain__icontains=domain)
        if ip_address: qs = qs.filter(ip_address__icontains=ip_address)
        if session_id: qs = qs.filter(session_id__icontains=session_id)
        if flagged is not None:
            qs = qs.filter(flagged=flagged.lower() == 'true')

        return Response(ActivityLogSerializer(qs[:limit], many=True).data)

    serializer = ActivityLogCreateSerializer(data=request.data)
    if serializer.is_valid():
        log = serializer.save()
        return Response(ActivityLogSerializer(log).data, status=201)
    return Response(serializer.errors, status=400)


@api_view(['GET', 'DELETE'])
@permission_classes([IsAuthenticated])
def activity_log_detail(request, log_id):
    try:
        log = ActivityLog.objects.get(id=log_id, site__owner_user=request.user)
    except ActivityLog.DoesNotExist:
        return Response({'error': 'Activity log not found'}, status=404)

    if request.method == 'GET':
        return Response(ActivityLogSerializer(log).data)
    log.delete()
    return Response({'message': 'Deleted'}, status=204)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def activity_logs_summary(request):
    logs = ActivityLog.objects.filter(site__owner_user=request.user)
    total          = logs.count()
    flagged        = logs.filter(flagged=True).count()
    avg_suspicion  = logs.aggregate(Avg('suspicion_score'))['suspicion_score__avg'] or 0
    domain_stats   = logs.values('domain').annotate(
        count=Count('id'),
        avg_suspicion=Avg('suspicion_score'),
        flagged_count=Count('id', filter=Q(flagged=True)),
    ).order_by('-count')
    recent_flagged = logs.filter(flagged=True)[:10]
    return Response({
        'total_logs':         total,
        'flagged_logs':       flagged,
        'avg_suspicion_score': round(avg_suspicion, 2),
        'domain_stats':       list(domain_stats),
        'recent_flagged':     ActivityLogSerializer(recent_flagged, many=True).data,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# THREATS
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def threats(request):
    if request.method == 'GET':
        qs     = Threat.objects.filter(site__owner_user=request.user)
        domain = request.query_params.get('domain')
        sev    = request.query_params.get('severity')
        st     = request.query_params.get('status')
        sid    = request.query_params.get('session_id')
        limit  = int(request.query_params.get('limit', 100))

        if domain: qs = qs.filter(domain__icontains=domain)
        if sev:    qs = qs.filter(severity=sev)
        if st:     qs = qs.filter(status=st)
        if sid:    qs = qs.filter(session_id__icontains=sid)
        return Response(ThreatSerializer(qs[:limit], many=True).data)

    serializer = ThreatCreateSerializer(data=request.data)
    if serializer.is_valid():
        site_id = request.data.get('site')
        if site_id:
            try:
                site = RegisteredSite.objects.get(id=site_id, owner_user=request.user)
                serializer.save(site=site)
            except RegisteredSite.DoesNotExist:
                return Response({'error': 'Site not found or access denied'}, status=403)
        else:
            serializer.save()
        return Response(serializer.data, status=201)
    return Response(serializer.errors, status=400)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def threat_detail(request, threat_id):
    try:
        threat = Threat.objects.get(id=threat_id, site__owner_user=request.user)
    except Threat.DoesNotExist:
        return Response({'error': 'Threat not found'}, status=404)

    if request.method == 'GET':
        return Response(ThreatSerializer(threat).data)
    if request.method == 'PUT':
        s = ThreatSerializer(threat, data=request.data, partial=True)
        if s.is_valid():
            s.save()
            return Response(s.data)
        return Response(s.errors, status=400)
    threat.delete()
    return Response({'message': 'Deleted'}, status=204)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_threat_status(request, threat_id):
    try:
        threat = Threat.objects.get(id=threat_id, site__owner_user=request.user)
    except Threat.DoesNotExist:
        return Response({'error': 'Threat not found'}, status=404)

    new_status = request.data.get('status')
    if new_status not in ['active', 'contained', 'resolved']:
        return Response({'error': 'Invalid status'}, status=400)
    threat.status = new_status
    threat.save()
    return Response(ThreatSerializer(threat).data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def threats_summary(request):
    qs = Threat.objects.filter(site__owner_user=request.user)
    return Response({
        'total_threats':     qs.count(),
        'active_threats':    qs.filter(status='active').count(),
        'contained_threats': qs.filter(status='contained').count(),
        'resolved_threats':  qs.filter(status='resolved').count(),
        'severity_stats':    list(qs.values('severity').annotate(count=Count('id')).order_by('-count')),
        'domain_stats':      list(qs.values('domain').annotate(
            count=Count('id'),
            active_count=Count('id', filter=Q(status='active')),
        ).order_by('-count')[:5]),
        'recent_threats':    ThreatSerializer(qs[:10], many=True).data,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ACTIVE SESSIONS
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def active_sessions(request):
    cutoff = timezone.now() - timedelta(minutes=30)

    if request.method == 'GET':
        # Auto-expire stale sessions
        ActiveSession.objects.filter(
            site__owner_user=request.user,
            is_active=True,
            last_activity__lt=cutoff,
        ).update(is_active=False)

        qs = ActiveSession.objects.filter(
            site__owner_user=request.user,
            is_active=True,
            last_activity__gte=cutoff,
        ).select_related('site', 'threat')

        domain   = request.query_params.get('domain')
        bt       = request.query_params.get('backend_type')
        tl       = request.query_params.get('threat_level')
        es       = request.query_params.get('engagement_status')
        limit    = int(request.query_params.get('limit', 100))

        if domain: qs = qs.filter(domain__icontains=domain)
        if bt:     qs = qs.filter(backend_type=bt)
        if tl:     qs = qs.filter(threat_level=tl)
        if es:     qs = qs.filter(engagement_status=es)
        return Response(ActiveSessionSerializer(qs[:limit], many=True).data)

    serializer = ActiveSessionCreateSerializer(data=request.data)
    if serializer.is_valid():
        site_id = request.data.get('site')
        site    = None
        if site_id:
            try:
                site = RegisteredSite.objects.get(id=site_id, owner_user=request.user)
            except RegisteredSite.DoesNotExist:
                return Response({'error': 'Site not found'}, status=403)

        # Return existing session if one already exists
        existing = ActiveSession.objects.filter(
            session_id=request.data.get('session_id'), is_active=True
        ).first()
        if existing:
            existing.last_activity    = timezone.now()
            existing.interaction_count = F('interaction_count') + 1
            existing.save()
            existing.refresh_from_db()
            return Response(ActiveSessionSerializer(existing).data)

        session = serializer.save(site=site) if site else serializer.save()
        if site:
            RegisteredSite.objects.filter(id=site.id).update(
                sessions_monitored=F('sessions_monitored') + 1
            )
        return Response(ActiveSessionSerializer(session).data, status=201)
    return Response(serializer.errors, status=400)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def active_session_detail(request, session_id):
    try:
        session = ActiveSession.objects.get(id=session_id, site__owner_user=request.user)
    except ActiveSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)

    if request.method == 'GET':
        return Response(ActiveSessionSerializer(session).data)
    if request.method == 'PUT':
        s = ActiveSessionSerializer(session, data=request.data, partial=True)
        if s.is_valid():
            s.save()
            return Response(s.data)
        return Response(s.errors, status=400)
    session.is_active = False
    session.save()
    return Response({'message': 'Session terminated'}, status=204)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_session_interaction(request, session_id):
    try:
        session = ActiveSession.objects.get(
            id=session_id, site__owner_user=request.user, is_active=True
        )
    except ActiveSession.DoesNotExist:
        return Response({'error': 'Active session not found'}, status=404)

    session.interaction_count += request.data.get('interaction_count', 1)
    session.last_activity      = timezone.now()

    techs = request.data.get('detected_techniques', [])
    if techs:
        session.detected_techniques = list(set(session.detected_techniques) | set(techs))

    if request.data.get('threat_level'):
        session.threat_level = request.data['threat_level']
    if request.data.get('engagement_status'):
        session.engagement_status = request.data['engagement_status']

    session.save()
    return Response(ActiveSessionSerializer(session).data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def active_sessions_summary(request):
    cutoff = timezone.now() - timedelta(minutes=30)
    qs     = ActiveSession.objects.filter(
        site__owner_user=request.user, is_active=True, last_activity__gte=cutoff
    )
    return Response({
        'total_sessions':     qs.count(),
        'deceptive_sessions': qs.filter(backend_type='deceptive').count(),
        'real_sessions':      qs.filter(backend_type='real').count(),
        'threat_stats':       list(qs.values('threat_level').annotate(count=Count('id')).order_by('-count')),
        'engagement_stats':   list(qs.values('engagement_status').annotate(count=Count('id')).order_by('-count')),
        'most_active':        ActiveSessionSerializer(qs.order_by('-interaction_count')[:5], many=True).data,
        'avg_interactions':   round(qs.aggregate(avg=Avg('interaction_count'))['avg'] or 0, 2),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACK PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def attack_patterns(request):
    if request.method == 'GET':
        qs     = AttackPattern.objects.all()
        cat    = request.query_params.get('category')
        sev    = request.query_params.get('severity')
        search = request.query_params.get('search')
        limit  = int(request.query_params.get('limit', 100))

        if cat:    qs = qs.filter(category=cat)
        if sev:    qs = qs.filter(severity=sev)
        if search: qs = qs.filter(
            Q(technique__icontains=search) |
            Q(description__icontains=search) |
            Q(indicators__icontains=search)
        )
        return Response(AttackPatternSerializer(qs[:limit], many=True).data)

    technique = request.data.get('technique')
    existing  = AttackPattern.objects.filter(technique=technique).first()
    if existing:
        existing.frequency += 1
        existing.last_seen  = timezone.now()
        existing.save()
        return Response(AttackPatternSerializer(existing).data)

    serializer = AttackPatternCreateSerializer(data=request.data)
    if serializer.is_valid():
        pattern = serializer.save(frequency=1, detection_count=1)
        return Response(AttackPatternSerializer(pattern).data, status=201)
    return Response(serializer.errors, status=400)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def attack_pattern_detail(request, pattern_id):
    try:
        pattern = AttackPattern.objects.get(id=pattern_id)
    except AttackPattern.DoesNotExist:
        return Response({'error': 'Attack pattern not found'}, status=404)

    if request.method == 'GET':
        return Response(AttackPatternSerializer(pattern).data)
    if request.method == 'PUT':
        s = AttackPatternSerializer(pattern, data=request.data, partial=True)
        if s.is_valid():
            s.save()
            return Response(s.data)
        return Response(s.errors, status=400)
    pattern.delete()
    return Response({'message': 'Deleted'}, status=204)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def attack_patterns_summary(request):
    qs = AttackPattern.objects.all()
    return Response({
        'total_patterns':    qs.count(),
        'total_detections':  qs.aggregate(total=Sum('detection_count'))['total'] or 0,
        'critical_patterns': qs.filter(severity='critical').count(),
        'high_patterns':     qs.filter(severity='high').count(),
        'category_stats':    list(qs.values('category').annotate(count=Count('id'), total_frequency=Sum('frequency')).order_by('-count')),
        'severity_stats':    list(qs.values('severity').annotate(count=Count('id'), total_frequency=Sum('frequency')).order_by('-count')),
        'most_frequent':     AttackPatternSerializer(qs.order_by('-frequency')[:5], many=True).data,
        'recent_patterns':   AttackPatternSerializer(qs.order_by('-last_seen')[:10], many=True).data,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def pattern_learning_trends(request):
    hours      = int(request.query_params.get('hours', 24))
    start_time = timezone.now() - timedelta(hours=hours)
    trends     = PatternLearningData.objects.filter(timestamp__gte=start_time).order_by('timestamp')
    if not trends.exists():
        return Response(_empty_trends())
    return Response(PatternLearningDataSerializer(trends, many=True).data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_pattern_learning(request):
    new_p  = request.data.get('new_patterns', 0)
    rep_p  = request.data.get('repeating_patterns', 0)
    today  = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    obj, created = PatternLearningData.objects.get_or_create(
        timestamp__gte=today,
        defaults={
            'new_patterns':       new_p,
            'repeating_patterns': rep_p,
            'total_patterns':     AttackPattern.objects.count(),
        },
    )
    if not created:
        obj.new_patterns       += new_p
        obj.repeating_patterns += rep_p
        obj.total_patterns      = AttackPattern.objects.count()
        obj.save()
    return Response({'message': 'Learning data updated'})


# ═══════════════════════════════════════════════════════════════════════════════
# SETTINGS
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def system_settings(request):
    obj, _ = SystemSettings.objects.get_or_create(pk=1)
    is_admin = getattr(request.user, 'is_admin_user', False)

    if request.method == 'GET':
        cache_key = 'system_settings' if is_admin else 'system_settings_public'
        cached = cache.get(cache_key)
        if cached:
            return Response(cached)
        data = SystemSettingsSerializer(obj).data
        if not is_admin:
            # Non-admins get a safe subset — enough for the Settings page
            # to render meaningfully instead of 403ing, without exposing
            # operational details only relevant to a platform admin.
            safe_fields = {
                'deception_level', 'suspicion_threshold',
                'session_timeout', 'data_logging_enabled', 'learning_mode',
            }
            data = {k: v for k, v in data.items() if k in safe_fields}
        cache.set(cache_key, data, 3600)
        return Response(data)

    if not is_admin:
        return Response(
            {'error': 'Admin access required to modify system settings.'}, status=403
        )
    s = SystemSettingsSerializer(obj, data=request.data, partial=True)
    if s.is_valid():
        s.save(updated_by=request.user)
        cache.delete('system_settings')
        cache.delete('system_settings_public')
        return Response(s.data)
    return Response(s.errors, status=400)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def test_ai_connection(request):
    """
    POST /api/auth/settings/system/test-ai/

    Admin-only. Makes one real, minimal call to Groq using whichever key
    is currently active (admin-configured key takes priority over the
    GROQ_API_KEY env var — see global_ai_analyzer._resolve_groq_api_key).
    A key merely being saved doesn't mean it's valid/unexpired/reachable,
    so the admin panel's status badge is driven by this live check, not
    just by groq_api_key_set.
    """
    if not getattr(request.user, 'is_admin_user', False):
        return Response({'error': 'Admin access required.'}, status=403)

    from .services.global_ai_analyzer import _groq_client, _resolve_ai_settings
    import time

    cfg = _resolve_ai_settings()
    provider, model, key = cfg['provider'], cfg['model'], cfg['api_key']

    if not key:
        env_var = 'OPENAI_API_KEY' if provider == 'openai' else 'GROQ_API_KEY'
        return Response({
            'connected': False,
            'configured': False,
            'message': f'No {provider.upper()} API key configured (neither in System Settings nor the {env_var} environment variable).',
        })

    started = time.monotonic()
    try:
        client = _groq_client()  # provider-aware despite the name — see global_ai_analyzer.py
        completion = client.chat.completions.create(
            model=model,
            messages=[{"role": "user", "content": "Reply with exactly one word: OK"}],
            max_tokens=5,
            timeout=10,
        )
        latency_ms = round((time.monotonic() - started) * 1000)
        reply = (completion.choices[0].message.content or '').strip()
        key_from_db = (
            SystemSettings.objects.filter(pk=1, openai_api_key__gt='').exists() if provider == 'openai'
            else SystemSettings.objects.filter(pk=1, groq_api_key__gt='').exists()
        )
        return Response({
            'connected': True,
            'configured': True,
            'provider': provider,
            'model': model,
            'latency_ms': latency_ms,
            'key_source': 'admin_panel' if key_from_db else 'environment_variable',
            'message': f'{provider.capitalize()} responded in {latency_ms}ms (reply: "{reply}").',
        })
    except Exception as exc:
        latency_ms = round((time.monotonic() - started) * 1000)
        logger.warning("AI connection test failed (%s): %s", provider, exc)
        return Response({
            'connected': False,
            'configured': True,
            'provider': provider,
            'model': model,
            'latency_ms': latency_ms,
            'message': f'A key is configured but the test call failed: {exc}',
        })


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def user_preferences(request):
    prefs, _ = UserPreferences.objects.get_or_create(user=request.user)
    if request.method == 'GET':
        return Response(UserPreferencesSerializer(prefs).data)
    s = UserPreferencesSerializer(prefs, data=request.data, partial=True)
    if s.is_valid():
        s.save()
        return Response(s.data)
    return Response(s.errors, status=400)


@api_view(['POST'])
@permission_classes([IsAppAdminUser])
def reset_settings(request):
    obj, _ = SystemSettings.objects.get_or_create(pk=1)
    obj.suspicion_threshold      = 65
    obj.auto_engagement_enabled  = True
    obj.learning_mode            = True
    obj.deception_level          = 'advanced'
    obj.session_timeout          = 30
    obj.max_concurrent_sessions  = 100
    obj.data_logging_enabled     = True
    obj.alert_notifications      = True
    obj.updated_by               = request.user
    obj.save()
    cache.delete('system_settings')
    return Response({'message': 'Settings reset to defaults'})


@api_view(['GET'])
@permission_classes([IsAppAdminUser])
def settings_audit_log(request):
    limit = int(request.query_params.get('limit', 50))
    logs  = SettingsAuditLog.objects.all()[:limit]
    return Response(SettingsAuditLogSerializer(logs, many=True).data)


# ═══════════════════════════════════════════════════════════════════════════════
# THREAT INTELLIGENCE
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def threat_intelligence(request):
    if request.method == 'GET':
        qs       = ThreatIntelligence.objects.all()
        source   = request.query_params.get('source')
        st       = request.query_params.get('status')
        min_risk = request.query_params.get('min_risk')
        tech     = request.query_params.get('technique')
        limit    = int(request.query_params.get('limit', 100))

        if source:   qs = qs.filter(source=source)
        if st:       qs = qs.filter(status=st)
        if min_risk: qs = qs.filter(risk_score__gte=int(min_risk))
        if tech:     qs = qs.filter(technique__icontains=tech)
        return Response(ThreatIntelligenceSerializer(qs[:limit], many=True).data)

    s = ThreatIntelligenceCreateSerializer(data=request.data)
    if s.is_valid():
        intel = s.save()
        if intel.risk_score >= 70:
            _update_attack_pattern_from_intel(intel)
        return Response(ThreatIntelligenceSerializer(intel).data, status=201)
    return Response(s.errors, status=400)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def threat_intelligence_detail(request, intel_id):
    try:
        intel = ThreatIntelligence.objects.get(id=intel_id)
    except ThreatIntelligence.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)

    if request.method == 'GET':
        return Response(ThreatIntelligenceSerializer(intel).data)
    if request.method == 'PUT':
        s = ThreatIntelligenceSerializer(intel, data=request.data, partial=True)
        if s.is_valid():
            s.save()
            return Response(s.data)
        return Response(s.errors, status=400)
    intel.delete()
    return Response({'message': 'Deleted'}, status=204)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def threat_intelligence_stats(request):
    qs = ThreatIntelligence.objects.all()
    return Response({
        'total_entries':     qs.count(),
        'avg_risk_score':    round(qs.aggregate(avg=Avg('risk_score'))['avg'] or 0, 2),
        'high_risk_count':   qs.filter(risk_score__gte=70).count(),
        'source_stats':      list(qs.values('source').annotate(count=Count('id'), avg_risk=Avg('risk_score')).order_by('-count')),
        'status_stats':      list(qs.values('status').annotate(count=Count('id')).order_by('-count')),
        'technique_stats':   list(qs.exclude(technique__isnull=True).exclude(technique='').values('technique').annotate(count=Count('id'), avg_risk=Avg('risk_score')).order_by('-count')[:10]),
        'recent_high_risk':  ThreatIntelligenceSerializer(qs.filter(risk_score__gte=70)[:10], many=True).data,
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def share_threat_intelligence(request, intel_id):
    try:
        intel = ThreatIntelligence.objects.get(id=intel_id)
    except ThreatIntelligence.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)

    share_to = request.data.get('share_to')
    if not share_to:
        return Response({'error': 'share_to required'}, status=400)

    ThreatIntelligenceShare.objects.create(
        threat_intel=intel, shared_to=share_to, shared_by=request.user
    )
    intel.is_shared = True
    intel.shared_at = timezone.now()
    intel.save()
    return Response({'message': f'Shared to {share_to}'})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def threat_intelligence_feed(request):
    last_id = request.query_params.get('last_id')
    limit   = int(request.query_params.get('limit', 50))
    qs      = ThreatIntelligence.objects.filter(id__gt=last_id) if last_id else ThreatIntelligence.objects.all()
    return Response(ThreatIntelligenceSerializer(qs[:limit], many=True).data)


# ═══════════════════════════════════════════════════════════════════════════════
# ANALYTICS
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_analytics_trends(request):
    time_range = request.query_params.get('range', '24h')
    metric     = request.query_params.get('metric', 'attacks_detected')
    end_date   = timezone.now()

    if time_range == '24h':
        start_date, interval = end_date - timedelta(hours=24), 'hour'
    elif time_range == '7d':
        start_date, interval = end_date - timedelta(days=7), 'day'
    elif time_range == '30d':
        start_date, interval = end_date - timedelta(days=30), 'day'
    else:
        start_date, interval = end_date - timedelta(days=90), 'week'

    analytics = AnalyticsData.objects.filter(
        metric_type=metric, timestamp__gte=start_date, timestamp__lte=end_date
    ).order_by('timestamp')

    data, current = [], start_date
    step = timedelta(hours=1) if interval == 'hour' else timedelta(days=1 if interval == 'day' else 7)
    while current <= end_date:
        period_end  = current + step
        period_data = analytics.filter(timestamp__gte=current, timestamp__lt=period_end)
        total_value = period_data.aggregate(Sum('value'))['value__sum'] or 0
        fmt         = '%H:00' if interval == 'hour' else '%Y-%m-%d'
        data.append({'time': current.strftime(fmt), 'value': total_value})
        current = period_end

    return Response({'metric': metric, 'time_range': time_range, 'data': data})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_attack_locations(request):
    limit = int(request.query_params.get('limit', 10))
    return Response(AttackLocationSerializer(AttackLocation.objects.all()[:limit], many=True).data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_skill_distribution(request):
    return Response(AttackerSkillDistributionSerializer(AttackerSkillDistribution.objects.all(), many=True).data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_analytics_summary(request):
    time_range = request.query_params.get('range', 'today')
    now        = timezone.now()

    if time_range == 'today':
        start_date = now.replace(hour=0, minute=0, second=0, microsecond=0)
    elif time_range == 'week':
        start_date = now - timedelta(days=7)
    elif time_range == 'month':
        start_date = now - timedelta(days=30)
    else:
        start_date = now - timedelta(days=365)

    analytics       = AnalyticsData.objects.filter(timestamp__gte=start_date)
    total_attacks   = analytics.filter(metric_type='attacks_detected').aggregate(Sum('value'))['value__sum'] or 0
    total_trapped   = analytics.filter(metric_type='attackers_trapped').aggregate(Sum('value'))['value__sum'] or 0
    avg_response    = analytics.filter(metric_type='avg_response_time').aggregate(Avg('value'))['value__avg'] or 0
    peak_envs       = analytics.filter(metric_type='environments_active').aggregate(Max('value'))['value__max'] or 0
    prev_start      = start_date - (now - start_date)
    prev_attacks    = AnalyticsData.objects.filter(
        timestamp__gte=prev_start, timestamp__lt=start_date, metric_type='attacks_detected'
    ).aggregate(Sum('value'))['value__sum'] or 0
    attack_trend    = ((total_attacks - prev_attacks) / prev_attacks * 100) if prev_attacks > 0 else 0

    return Response({
        'total_attacks':            total_attacks,
        'total_attackers_trapped':  total_trapped,
        'avg_response_time':        round(avg_response, 2),
        'peak_active_environments': peak_envs,
        'attack_trend_percent':     round(attack_trend, 1),
        'time_range':               time_range,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_historical_snapshots(request):
    days       = int(request.query_params.get('days', 30))
    start_date = timezone.now().date() - timedelta(days=days)
    snapshots  = AnalyticsSnapshot.objects.filter(date__gte=start_date).order_by('date')
    return Response(AnalyticsSnapshotSerializer(snapshots, many=True).data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_analytics_data(request):
    metric_type = request.data.get('metric_type')
    value       = request.data.get('value')
    site_id     = request.data.get('site')

    if not metric_type or value is None:
        return Response({'error': 'Missing required fields'}, status=400)

    kwargs = {'metric_type': metric_type, 'value': value}
    if site_id:
        try:
            kwargs['site'] = RegisteredSite.objects.get(id=site_id, owner_user=request.user)
        except RegisteredSite.DoesNotExist:
            pass

    AnalyticsData.objects.create(**kwargs)

    today          = timezone.now().date()
    snap, _        = AnalyticsSnapshot.objects.get_or_create(date=today)
    today_analytics = AnalyticsData.objects.filter(timestamp__date=today)
    snap.total_attacks            = today_analytics.filter(metric_type='attacks_detected').aggregate(Sum('value'))['value__sum'] or 0
    snap.total_attackers_trapped  = today_analytics.filter(metric_type='attackers_trapped').aggregate(Sum('value'))['value__sum'] or 0
    snap.avg_response_time        = today_analytics.filter(metric_type='avg_response_time').aggregate(Avg('value'))['value__avg'] or 0
    snap.peak_active_environments = today_analytics.filter(metric_type='environments_active').aggregate(Max('value'))['value__max'] or 0
    snap.save()
    return Response({'message': 'Analytics updated'})


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_attack_patterns_stats(request):
    qs = AttackPattern.objects.all()
    return Response({
        'total_patterns':        qs.count(),
        'top_techniques':        AttackPatternSerializer(qs.order_by('-frequency')[:10], many=True).data,
        'techniques_by_category': list(qs.values('category').annotate(count=Count('id'), total_frequency=Sum('frequency')).order_by('-total_frequency')),
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_attack_location(request):
    country      = request.data.get('country')
    country_code = request.data.get('country_code')
    attacks      = request.data.get('attacks', 1)

    if not country or not country_code:
        return Response({'error': 'Missing country info'}, status=400)

    loc, created = AttackLocation.objects.get_or_create(
        country=country, country_code=country_code, defaults={'attacks': attacks}
    )
    if not created:
        loc.attacks += attacks
        loc.save()
    return Response(AttackLocationSerializer(loc).data, status=201 if created else 200)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_skill_distribution(request):
    for item in request.data.get('distribution', []):
        sl  = item.get('skill_level')
        pct = item.get('percentage')
        if sl and pct is not None:
            AttackerSkillDistribution.objects.update_or_create(
                skill_level=sl, defaults={'percentage': pct}
            )
    return Response({'message': 'Skill distribution updated'})


# ═══════════════════════════════════════════════════════════════════════════════
# ATTACKER PROFILES
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def attackers(request):
    if request.method == 'GET':
        qs    = AttackerProfile.objects.all()
        skill = request.query_params.get('skill_level')
        st    = request.query_params.get('status')
        ctry  = request.query_params.get('country')
        mts   = request.query_params.get('min_threat_score')
        limit = int(request.query_params.get('limit', 100))

        if skill: qs = qs.filter(skill_level=skill)
        if st:    qs = qs.filter(status=st)
        if ctry:  qs = qs.filter(country__icontains=ctry)
        if mts:   qs = qs.filter(threat_score__gte=int(mts))
        return Response(AttackerProfileSerializer(qs[:limit], many=True).data)

    s = AttackerCreateSerializer(data=request.data)
    if s.is_valid():
        return Response(AttackerProfileSerializer(s.save()).data, status=201)
    return Response(s.errors, status=400)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def attacker_detail(request, attacker_id):
    try:
        attacker = AttackerProfile.objects.get(id=attacker_id)
    except AttackerProfile.DoesNotExist:
        return Response({'error': 'Attacker not found'}, status=404)

    if request.method == 'GET':
        return Response(AttackerProfileSerializer(attacker).data)
    if request.method == 'PUT':
        s = AttackerProfileSerializer(attacker, data=request.data, partial=True)
        if s.is_valid():
            s.save()
            return Response(s.data)
        return Response(s.errors, status=400)
    attacker.delete()
    return Response({'message': 'Deleted'}, status=204)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def attacker_behavior_logs(request, attacker_id):
    try:
        attacker = AttackerProfile.objects.get(id=attacker_id)
    except AttackerProfile.DoesNotExist:
        return Response({'error': 'Attacker not found'}, status=404)

    limit = int(request.query_params.get('limit', 50))
    return Response(AttackerBehaviorLogSerializer(attacker.behavior_logs.all()[:limit], many=True).data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def add_behavior_log(request, attacker_id):
    try:
        attacker = AttackerProfile.objects.get(id=attacker_id)
    except AttackerProfile.DoesNotExist:
        return Response({'error': 'Attacker not found'}, status=404)

    s = AttackerBehaviorLogSerializer(data=request.data)
    if s.is_valid():
        log = s.save(attacker=attacker)
        attacker.total_interactions += 1
        attacker.last_activity       = timezone.now()
        if log.technique and log.technique not in attacker.techniques:
            attacker.techniques.append(log.technique)
        threat_map = {
            'probe': 5, 'attack': 15, 'lateral_movement': 20,
            'data_exfiltration': 25, 'privilege_escalation': 20,
            'persistence': 15, 'evasion': 10,
        }
        attacker.threat_score = min(100, attacker.threat_score + threat_map.get(log.behavior_type, 5))
        attacker.save()
        return Response(s.data, status=201)
    return Response(s.errors, status=400)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def attackers_summary(request):
    qs = AttackerProfile.objects.all()
    return Response({
        'total_attackers':   qs.count(),
        'active_attackers':  qs.filter(status='active').count(),
        'trapped_attackers': qs.filter(status='trapped').count(),
        'avg_threat_score':  round(qs.aggregate(avg=Avg('threat_score'))['avg'] or 0, 2),
        'skill_stats':       list(qs.values('skill_level').annotate(count=Count('id')).order_by('-count')),
        'country_stats':     list(qs.values('country').annotate(count=Count('id'), avg_threat=Avg('threat_score')).order_by('-count')[:10]),
        'recent_attackers':  AttackerProfileSerializer(qs.order_by('-first_seen')[:10], many=True).data,
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_attacker_behavior_analysis(request, attacker_id):
    try:
        attacker = AttackerProfile.objects.get(id=attacker_id)
    except AttackerProfile.DoesNotExist:
        return Response({'error': 'Attacker not found'}, status=404)

    if request.data.get('behavior_summary'):
        attacker.behavior_summary = request.data['behavior_summary']
    if request.data.get('deception_susceptibility') is not None:
        attacker.deception_susceptibility = request.data['deception_susceptibility']
    if request.data.get('preferred_targets'):
        attacker.preferred_targets = request.data['preferred_targets']
    attacker.save()
    return Response(AttackerProfileSerializer(attacker).data)


# ═══════════════════════════════════════════════════════════════════════════════
# DECEPTION ENVIRONMENTS
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def deception_environments(request):
    if request.method == 'GET':
        qs      = DeceptionEnvironment.objects.all()
        env_type = request.query_params.get('type')
        st       = request.query_params.get('status')
        site_id  = request.query_params.get('site')
        limit    = int(request.query_params.get('limit', 100))

        if env_type: qs = qs.filter(type=env_type)
        if st:       qs = qs.filter(status=st)
        if site_id:  qs = qs.filter(site_id=site_id)
        return Response(DeceptionEnvironmentSerializer(qs[:limit], many=True).data)

    s = DeceptionEnvironmentCreateSerializer(data=request.data)
    if s.is_valid():
        return Response(DeceptionEnvironmentSerializer(s.save()).data, status=201)
    return Response(s.errors, status=400)


@api_view(['GET', 'PUT', 'DELETE'])
@permission_classes([IsAuthenticated])
def deception_environment_detail(request, env_id):
    try:
        env = DeceptionEnvironment.objects.get(id=env_id)
    except DeceptionEnvironment.DoesNotExist:
        return Response({'error': 'Environment not found'}, status=404)

    if request.method == 'GET':
        return Response(DeceptionEnvironmentSerializer(env).data)
    if request.method == 'PUT':
        s = DeceptionEnvironmentSerializer(env, data=request.data, partial=True)
        if s.is_valid():
            s.save()
            return Response(s.data)
        return Response(s.errors, status=400)
    env.delete()
    return Response({'message': 'Deleted'}, status=204)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def record_interaction(request, env_id):
    try:
        env = DeceptionEnvironment.objects.get(id=env_id)
    except DeceptionEnvironment.DoesNotExist:
        return Response({'error': 'Environment not found'}, status=404)

    env.total_interactions += 1
    env.last_triggered      = timezone.now()
    recent = DeceptionInteraction.objects.filter(
        environment=env, timestamp__gte=timezone.now() - timedelta(minutes=5)
    ).count()
    env.status = 'under_attack' if recent > 10 else ('active' if recent > 5 else 'idle')
    env.save()

    s = DeceptionInteractionSerializer(data=request.data)
    if s.is_valid():
        return Response(s.save(environment=env).__dict__, status=201)
    return Response(s.errors, status=400)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def environment_interactions(request, env_id):
    try:
        env = DeceptionEnvironment.objects.get(id=env_id)
    except DeceptionEnvironment.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)
    limit = int(request.query_params.get('limit', 50))
    return Response(DeceptionInteractionSerializer(env.interactions.all()[:limit], many=True).data)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def update_environment_ai(request, env_id):
    try:
        env = DeceptionEnvironment.objects.get(id=env_id)
    except DeceptionEnvironment.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)

    level = request.data.get('ai_adaptation_level')
    if level is not None:
        env.ai_adaptation_level = min(100, max(0, int(level)))
        env.save()
        EnvironmentMetrics.objects.create(
            environment=env,
            attacker_count=env.attacker_count,
            interactions_per_minute=env.total_interactions / 60 if env.total_interactions else 0,
            deception_effectiveness=env.ai_adaptation_level,
            resource_usage=level,
        )
    return Response(DeceptionEnvironmentSerializer(env).data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def environments_summary(request):
    qs = DeceptionEnvironment.objects.all()
    return Response({
        'total_environments':     qs.count(),
        'active_environments':    qs.filter(status='active').count(),
        'under_attack':           qs.filter(status='under_attack').count(),
        'compromised':            qs.filter(status='compromised').count(),
        'total_attackers_trapped': qs.aggregate(total=Sum('attacker_count'))['total'] or 0,
        'total_interactions':     qs.aggregate(total=Sum('total_interactions'))['total'] or 0,
        'avg_ai_adaptation':      round(qs.aggregate(avg=Avg('ai_adaptation_level'))['avg'] or 0, 2),
        'recent_deployments':     qs.filter(created_at__gte=timezone.now() - timedelta(days=7)).count(),
        'type_stats':             list(qs.values('type').annotate(count=Count('id'), total_attackers=Sum('attacker_count')).order_by('-count')),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATED TRACK ENDPOINT  (private, called by your own middleware)
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def track_request(request):
    data           = request.data
    domain         = data.get('domain')
    ip_address     = data.get('ip_address')
    user_agent     = data.get('user_agent', '')
    request_path   = data.get('request_path', '/')
    request_method = data.get('request_method', 'GET')
    response_status = data.get('response_status', 200)
    response_time  = data.get('response_time_ms', 0)

    suspicion_score = _calc_suspicion(ip_address, user_agent, request_path)
    is_flagged      = suspicion_score > 65

    try:
        site = RegisteredSite.objects.get(domain__iexact=domain, owner_user=request.user)
    except RegisteredSite.DoesNotExist:
        return Response({'error': 'Domain not registered'}, status=404)

    session_id = hashlib.md5(f"{ip_address}:{domain}:{user_agent[:100]}".encode()).hexdigest()[:32]

    ActivityLog.objects.create(
        timestamp=timezone.now(), domain=domain, session_id=session_id,
        ip_address=ip_address, user_agent=user_agent, endpoint=request_path,
        method=request_method, status_code=response_status,
        response_time=response_time, suspicion_score=suspicion_score,
        flagged=is_flagged, site=site,
    )

    session, created = ActiveSession.objects.get_or_create(
        session_id=session_id, site=site,
        defaults={
            'domain': domain, 'ip_address': ip_address,
            'backend_type': 'deceptive' if is_flagged else 'real',
            'threat_level': _threat_level(suspicion_score),
            'engagement_status': 'deceiving' if is_flagged else 'analyzing',
            'interaction_count': 1,
        },
    )
    if not created:
        session.last_activity     = timezone.now()
        session.interaction_count = F('interaction_count') + 1
        if is_flagged:
            session.backend_type      = 'deceptive'
            session.engagement_status = 'deceiving'
        session.save()

    RegisteredSite.objects.filter(id=site.id).update(
        sessions_monitored=F('sessions_monitored') + 1,
        threats_detected=F('threats_detected') + (1 if is_flagged else 0),
    )

    return Response({
        'success': True, 'session_id': session_id,
        'suspicion_score': suspicion_score, 'flagged': is_flagged,
        'backend_type': session.backend_type,
    })


# ═══════════════════════════════════════════════════════════════════════════════
# HELPERS  (private — not exposed as endpoints)
# ═══════════════════════════════════════════════════════════════════════════════

def _add_cors(response):
    """Attach CORS headers so the JS snippet can POST from any origin."""
    response['Access-Control-Allow-Origin']  = '*'
    response['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    response['Access-Control-Allow-Headers'] = 'Content-Type'
    return response


def _threat_level(score: int) -> str:
    if score > 80: return 'critical'
    if score > 60: return 'high'
    if score > 30: return 'medium'
    return 'low'


def _calc_suspicion(ip: str, user_agent: str, path: str) -> int:
    score = 0
    ua    = (user_agent or '').lower()
    p     = (path or '').lower()

    for agent in ['sqlmap', 'nikto', 'nmap', 'dirbuster', 'gobuster',
                  'masscan', 'zap', 'burpsuite', 'scrapy']:
        if agent in ua:
            score += 20
            break

    for bot in ['headless', 'phantomjs', 'selenium', 'webdriver',
                'python-requests', 'python-urllib', 'go-http-client']:
        if bot in ua:
            score += 15
            break

    for probe in ['admin', 'wp-admin', 'phpmyadmin', '.env', '.git',
                  'config', 'backup', 'passwd', 'etc/passwd', 'shell']:
        if probe in p:
            score += 20
            break

    return min(score, 100)


def _get_client_ip(request) -> str:
    xff = request.META.get('HTTP_X_FORWARDED_FOR', '')
    return xff.split(',')[0].strip() if xff else request.META.get('REMOTE_ADDR', '')


def _update_attack_pattern_from_intel(intel) -> None:
    if not intel.technique:
        return
    pattern, created = AttackPattern.objects.get_or_create(
        technique=intel.technique,
        defaults={
            'category':        'Other',
            'severity':        'high' if intel.risk_score >= 70 else 'medium',
            'description':     intel.description,
            'indicators':      intel.indicators,
            'mitre_id':        intel.mitre_attack_id,
            'frequency':       1,
            'detection_count': 1,
        },
    )
    if not created:
        pattern.frequency       += 1
        pattern.detection_count += 1
        pattern.last_seen        = timezone.now()
        if intel.indicators:
            pattern.indicators = list(set(pattern.indicators) | set(intel.indicators))
        pattern.save()


def _empty_trends() -> list:
    """
    Real, honestly-empty trend buckets for when no PatternLearningData
    exists yet — used to show real timestamps with zero activity rather
    than the fabricated placeholder numbers (12, 23, 156...) this used to
    return, which made an idle/new system's chart look like it had real
    attack traffic when it didn't.
    """
    trends = []
    for hour in range(0, 24, 4):
        trends.append({
            'timestamp':          (timezone.now() - timedelta(hours=24 - hour)).strftime('%Y-%m-%d %H:%M:%S'),
            'new_patterns':       0,
            'repeating_patterns': 0,
            'total_patterns':     AttackPattern.objects.count(),
        })
    return trends

# ═══════════════════════════════════════════════════════════════════════════════
# SITE PROFILING  — AI reads the registered site and builds a behaviour profile
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_site_profile(request, site_id):
    """Return the current AI profile for a site."""
    try:
        site = RegisteredSite.objects.get(id=site_id, owner_user=request.user)
    except RegisteredSite.DoesNotExist:
        return Response({'error': 'Site not found'}, status=404)

    try:
        from .models import SiteProfile
        profile = SiteProfile.objects.get(site=site)
        return Response({
            'site_id':              site.id,
            'domain':               site.domain,
            'status':               profile.status,
            'site_purpose':         profile.site_purpose,
            'site_type':            profile.site_type,
            'expected_paths':       profile.expected_paths,
            'normal_actions':       profile.normal_actions,
            'suspicious_signals':   profile.suspicious_signals,
            'sensitive_areas':      profile.sensitive_areas,
            'pages_crawled':        profile.pages_crawled,
            'crawl_error':          profile.crawl_error,
            'updated_at':           profile.updated_at,
        })
    except SiteProfile.DoesNotExist:
        return Response({'site_id': site.id, 'domain': site.domain, 'status': 'not_started'})


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def trigger_site_profile(request, site_id):
    """
    Trigger AI profiling for a registered site.
    Crawls the site, sends content to Groq, stores the resulting profile.
    This can take 5–15 seconds — call it asynchronously from the frontend.
    """
    try:
        site = RegisteredSite.objects.get(id=site_id, owner_user=request.user)
    except RegisteredSite.DoesNotExist:
        return Response({'error': 'Site not found'}, status=404)

    try:
        from .services.global_ai_analyzer import profile_site
        result = profile_site(site)
        return Response(result)
    except RuntimeError as exc:
        # GROQ_API_KEY not set
        return Response({'error': str(exc)}, status=503)
    except Exception as exc:
        return Response({'error': f'Profiling failed: {exc}'}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_session_ai_analysis(request, session_id):
    """
    On-demand AI analysis for a session, and — critically — if the result
    is flagged, it now writes that verdict back into the detection pipeline
    instead of being discarded. This is what makes Active Sessions' AI
    analysis consistent with Threat Detection and Activity Monitoring:
    previously this was entirely read-only (analyze, return, forget), which
    is why it could show accurate techniques while the other pages showed
    nothing for the same session.
    """
    try:
        session = ActiveSession.objects.get(id=session_id, site__owner_user=request.user)
    except ActiveSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)

    logs = list(
        ActivityLog.objects.filter(session_id=session.session_id)
        .order_by('-timestamp')[:30]
        .values('timestamp', 'method', 'endpoint', 'user_agent', 'suspicion_score', 'flagged')
    )
    for log in logs:
        if hasattr(log['timestamp'], 'isoformat'):
            log['timestamp'] = log['timestamp'].isoformat()

    site_profile = None
    if session.site:
        try:
            from .models import SiteProfile
            site_profile = SiteProfile.objects.get(site=session.site, status='ready')
        except Exception:
            pass

    try:
        from .services.global_ai_analyzer import analyze_session
        result = analyze_session(session, logs, site_profile)
    except RuntimeError as exc:
        return Response({'error': str(exc), 'ai_powered': False}, status=503)
    except Exception as exc:
        return Response({'error': f'Analysis failed: {exc}', 'ai_powered': False}, status=500)

    if result.get('flagged'):
        _apply_ai_analysis_verdict(session, result)

    return Response(result)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def approve_session_swap(request, session_id):
    """
    Operator manually approves the deceptive backend swap for a flagged session.
    Call this after reviewing the AI threat analysis in the Active Sessions page.
    Once approved, subsequent requests from this session will be served decoy
    responses instead of real responses.
    """
    try:
        session = ActiveSession.objects.get(
            id=session_id, site__owner_user=request.user, is_active=True,
        )
    except ActiveSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)

    if session.backend_type != 'deceptive':
        return Response({'error': 'Session is not flagged — only flagged sessions can be approved for swap'}, status=400)

    session.swap_approved = True
    session.engagement_status = 'deceiving'
    session.save(update_fields=['swap_approved', 'engagement_status'])

    logger.info('[ManualSwap] Operator %s approved swap for session %s (site: %s)',
                request.user.email, session.session_id, session.domain)

    return Response({
        'session_id':    session.session_id,
        'swap_approved': True,
        'message':       'Swap approved. Subsequent requests from this session will now receive deceptive responses.',
    })


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def revoke_session_swap(request, session_id):
    """Revoke a previously approved swap, reverting the session to real responses."""
    try:
        session = ActiveSession.objects.get(id=session_id, site__owner_user=request.user)
    except ActiveSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)

    session.swap_approved = False
    session.save(update_fields=['swap_approved'])
    return Response({'session_id': session.session_id, 'swap_approved': False})


def _apply_ai_analysis_verdict(session, result: dict) -> None:
    """
    Write a flagged on-demand AI verdict back into the detection pipeline —
    session state, Threat record, AttackPattern, and the most recent
    ActivityLog's suspicion score.  Fails soft so it never breaks the
    analysis response itself.
    """
    try:
        techniques = result.get('techniques') or []
        existing_indicators = set((session.threat.indicators or [])) if session.threat else set()
        new_techniques = set(techniques) - existing_indicators

        session.threat_level       = result.get('threat_level', session.threat_level)
        session.backend_type       = 'deceptive'
        session.engagement_status  = 'deceiving'
        merged                     = set(session.detected_techniques or [])
        merged.update(techniques)
        session.detected_techniques = list(merged)
        session.save(update_fields=[
            'threat_level', 'backend_type', 'engagement_status', 'detected_techniques'
        ])

        latest_log = (
            ActivityLog.objects.filter(session_id=session.session_id)
            .order_by('-timestamp').first()
        )
        if latest_log is not None:
            latest_log.suspicion_score = max(
                latest_log.suspicion_score or 0, result.get('risk_score', 0)
            )
            latest_log.flagged = True
            latest_log.save(update_fields=['suspicion_score', 'flagged'])

        if (session.threat is None or new_techniques) and session.site is not None:
            from types import SimpleNamespace
            from .services.swap_middleware import _create_swap_threat_record
            adapter = SimpleNamespace(
                techniques=techniques,
                threat_level=result.get('threat_level', 'medium'),
                explanation=result.get('explanation', 'Flagged by on-demand AI session analysis.'),
                tier=3,
                confidence=result.get('confidence', 70),
                score=result.get('risk_score', 0),
                flagged=True,
            )
            _create_swap_threat_record(
                session, adapter, session.domain, session.ip_address,
                session.site, latest_log,
            )

        from .services.attack_pattern_tracker import record_attack_patterns
        record_attack_patterns(adapter if 'adapter' in dir() else session, session.threat)

    except Exception as exc:
        logger.warning('[AIAnalysis] Failed to apply verdict back to pipeline: %s', exc)


# ═══════════════════════════════════════════════════════════════════════════════
# PAYMENTS  — M-Pesa STK Push + PayPal Orders
# ═══════════════════════════════════════════════════════════════════════════════
import base64 as _b64
from datetime import datetime as _dt

# ── Plan pricing ──────────────────────────────────────────────────────────────
PLANS = {
    'pro':        {'name': 'Pro',        'usd': 29,  'kes': 3800},
    'enterprise': {'name': 'Enterprise', 'usd': 99,  'kes': 13000},
}


# ─── M-Pesa ───────────────────────────────────────────────────────────────────

def _mpesa_token():
    """Fetch a Safaricom OAuth token using sandbox credentials."""
    consumer_key    = settings.MPESA_CONSUMER_KEY
    consumer_secret = settings.MPESA_CONSUMER_SECRET
    credentials     = _b64.b64encode(f"{consumer_key}:{consumer_secret}".encode()).decode()

    import requests as _r
    resp = _r.get(
        'https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials',
        headers={'Authorization': f'Basic {credentials}'},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()['access_token']


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def mpesa_stk_push(request):
    """
    Initiate an M-Pesa STK push to the user's phone.
    Body: { plan: 'pro'|'enterprise', phone: '2547XXXXXXXX' }
    """
    plan_key = request.data.get('plan', 'pro')
    phone    = request.data.get('phone', '').strip().replace('+', '')

    if plan_key not in PLANS:
        return Response({'error': 'Invalid plan'}, status=400)
    if not phone or len(phone) < 9:
        return Response({'error': 'Valid phone number required (format: 2547XXXXXXXX)'}, status=400)

    plan      = PLANS[plan_key]
    amount    = plan['kes']
    shortcode = settings.MPESA_SHORTCODE
    passkey   = settings.MPESA_PASSKEY
    timestamp = _dt.now().strftime('%Y%m%d%H%M%S')
    password  = _b64.b64encode(f"{shortcode}{passkey}{timestamp}".encode()).decode()

    callback_url = request.build_absolute_uri('/api/payments/mpesa/callback/')

    try:
        token = _mpesa_token()
        import requests as _r
        resp = _r.post(
            'https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest',
            json={
                'BusinessShortCode': shortcode,
                'Password':          password,
                'Timestamp':         timestamp,
                'TransactionType':   'CustomerPayBillOnline',
                'Amount':            amount,
                'PartyA':            phone,
                'PartyB':            shortcode,
                'PhoneNumber':       phone,
                'CallBackURL':       callback_url,
                'AccountReference':  f'GeniusMirage-{plan_key.upper()}',
                'TransactionDesc':   f'Genius Mirage {plan["name"]} subscription',
            },
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type':  'application/json',
            },
            timeout=15,
        )
        data = resp.json()

        if data.get('ResponseCode') == '0':
            # Store pending payment in session so callback can match it
            Payment.objects.create(
                user        = request.user,
                plan        = plan_key,
                provider    = 'mpesa',
                amount      = amount,
                currency    = 'KES',
                checkout_id = data.get('CheckoutRequestID', ''),
                status      = 'pending',
            )
            return Response({
                'ok':                True,
                'checkout_request_id': data.get('CheckoutRequestID'),
                'message':           f'STK push sent to {phone}. Enter your M-Pesa PIN to complete.',
            })
        else:
            return Response({'error': data.get('errorMessage', 'STK push failed')}, status=400)

    except Exception as exc:
        return Response({'error': f'M-Pesa error: {exc}'}, status=500)


@csrf_exempt
@require_http_methods(['POST'])
def mpesa_callback(request):
    """Safaricom posts payment result here."""
    try:
        body     = json.loads(request.body)
        result   = body['Body']['stkCallback']
        code     = result['ResultCode']
        checkout = result['CheckoutRequestID']

        payment = Payment.objects.filter(checkout_id=checkout).first()
        if payment:
            if code == 0:
                payment.status = 'completed'
                payment.save(update_fields=['status'])
                # Upgrade user plan
                user = payment.user
                user.plan = payment.plan
                user.save(update_fields=['plan'])
            else:
                payment.status = 'failed'
                payment.save(update_fields=['status'])
    except Exception as exc:
        print(f'[mpesa_callback] Error: {exc}')

    return HttpResponse('OK')


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def mpesa_payment_status(request, checkout_id):
    """Poll payment status from the frontend."""
    try:
        payment = Payment.objects.get(checkout_id=checkout_id, user=request.user)
        return Response({
            'status': payment.status,
            'plan':   payment.plan,
        })
    except Payment.DoesNotExist:
        return Response({'error': 'Payment not found'}, status=404)


# ─── PayPal ───────────────────────────────────────────────────────────────────

def _paypal_token():
    client_id     = settings.PAYPAL_CLIENT_ID
    client_secret = settings.PAYPAL_CLIENT_SECRET
    base_url      = settings.PAYPAL_BASE_URL   # https://api-m.sandbox.paypal.com

    import requests as _r
    resp = _r.post(
        f'{base_url}/v1/oauth2/token',
        data={'grant_type': 'client_credentials'},
        auth=(client_id, client_secret),
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()['access_token']


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def paypal_create_order(request):
    """
    Create a PayPal order and return the approval URL.
    Body: { plan: 'pro'|'enterprise' }
    """
    plan_key = request.data.get('plan', 'pro')
    if plan_key not in PLANS:
        return Response({'error': 'Invalid plan'}, status=400)

    plan     = PLANS[plan_key]
    base_url = settings.PAYPAL_BASE_URL

    try:
        token = _paypal_token()
        import requests as _r
        resp = _r.post(
            f'{base_url}/v2/checkout/orders',
            json={
                'intent': 'CAPTURE',
                'purchase_units': [{
                    'reference_id': f'{request.user.id}-{plan_key}',
                    'description':  f'Genius Mirage {plan["name"]} subscription',
                    'amount': {
                        'currency_code': 'USD',
                        'value':         str(plan['usd']),
                    },
                }],
                'application_context': {
                    'brand_name':   'Genius Mirage',
                    'return_url':   request.build_absolute_uri('/api/payments/paypal/capture/'),
                    'cancel_url':   request.build_absolute_uri('/api/payments/paypal/cancel/'),
                    'landing_page': 'BILLING',
                    'user_action':  'PAY_NOW',
                },
            },
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type':  'application/json',
            },
            timeout=15,
        )
        data     = resp.json()
        order_id = data.get('id')

        if order_id:
            Payment.objects.create(
                user        = request.user,
                plan        = plan_key,
                provider    = 'paypal',
                amount      = plan['usd'],
                currency    = 'USD',
                checkout_id = order_id,
                status      = 'pending',
            )
            # Find the approval link
            approve_url = next(
                (l['href'] for l in data.get('links', []) if l['rel'] == 'approve'),
                None,
            )
            return Response({'ok': True, 'order_id': order_id, 'approve_url': approve_url})
        else:
            return Response({'error': data.get('message', 'Failed to create order')}, status=400)

    except Exception as exc:
        return Response({'error': f'PayPal error: {exc}'}, status=500)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def paypal_capture_order(request):
    """
    Capture (finalise) a PayPal order after the user approves it.
    Body: { order_id: '...' }
    """
    order_id = request.data.get('order_id')
    if not order_id:
        return Response({'error': 'order_id required'}, status=400)

    base_url = settings.PAYPAL_BASE_URL

    try:
        token = _paypal_token()
        import requests as _r
        resp = _r.post(
            f'{base_url}/v2/checkout/orders/{order_id}/capture',
            headers={
                'Authorization': f'Bearer {token}',
                'Content-Type':  'application/json',
            },
            timeout=15,
        )
        data   = resp.json()
        status = data.get('status')

        payment = Payment.objects.filter(checkout_id=order_id, user=request.user).first()
        if payment:
            if status == 'COMPLETED':
                payment.status = 'completed'
                payment.save(update_fields=['status'])
                user = payment.user
                user.plan = payment.plan
                user.save(update_fields=['plan'])
                return Response({'ok': True, 'status': 'completed', 'plan': payment.plan})
            else:
                payment.status = 'failed'
                payment.save(update_fields=['status'])
                return Response({'ok': False, 'status': status})

        return Response({'error': 'Payment record not found'}, status=404)

    except Exception as exc:
        return Response({'error': f'Capture error: {exc}'}, status=500)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_subscription(request):
    """Return current user's plan and limits."""
    user = request.user
    return Response({
        'plan':        user.plan,
        'is_admin':    user.is_admin_user,
        'limits':      user.plan_limits,
        'plan_name':   dict(user.PLAN_CHOICES).get(user.plan, 'Free'),
    })


# ═══════════════════════════════════════════════════════════════════════════════
# ADMIN DASHBOARD API  — only accessible to admin users
# ═══════════════════════════════════════════════════════════════════════════════

def _require_admin(request):
    """Returns None if admin, or a Response error if not."""
    user = request.user
    if not (user.is_authenticated and (getattr(user, 'is_admin_user', False) or user.is_superuser or user.is_staff)):
        return Response({'error': 'Admin access required'}, status=403)
    return None


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_overview(request):
    """Global platform stats for the admin dashboard."""
    err = _require_admin(request)
    if err: return err

    from django.db.models import Sum, Avg, Count
    from datetime import timedelta

    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d  = now - timedelta(days=7)

    users        = CustomUser.objects.all()
    sites        = RegisteredSite.objects.all()
    threats      = Threat.objects.all()
    logs         = ActivityLog.objects.all()
    sessions     = ActiveSession.objects.all()
    payments_qs  = Payment.objects.all()

    return Response({
        'users': {
            'total':      users.count(),
            'admin':      users.filter(plan='admin').count(),
            'pro':        users.filter(plan='pro').count(),
            'enterprise': users.filter(plan='enterprise').count(),
            'free':       users.filter(plan='free').count(),
            'new_24h':    users.filter(date_joined__gte=last_24h).count(),
            'new_7d':     users.filter(date_joined__gte=last_7d).count(),
        },
        'sites': {
            'total':      sites.count(),
            'active':     sites.filter(status='active').count(),
            'monitoring': sites.filter(status='monitoring').count(),
            'paused':     sites.filter(status='paused').count(),
        },
        'threats': {
            'total':    threats.count(),
            'active':   threats.filter(status='active').count(),
            'critical': threats.filter(severity='critical').count(),
            'last_24h': threats.filter(timestamp__gte=last_24h).count(),
        },
        'activity': {
            'total_logs':    logs.count(),
            'flagged_logs':  logs.filter(flagged=True).count(),
            'logs_24h':      logs.filter(timestamp__gte=last_24h).count(),
            'active_sessions': sessions.filter(is_active=True).count(),
        },
        'revenue': {
            'total_payments':    payments_qs.filter(status='completed').count(),
            'total_revenue_usd': float(payments_qs.filter(status='completed', currency='USD').aggregate(t=Sum('amount'))['t'] or 0),
            'total_revenue_kes': float(payments_qs.filter(status='completed', currency='KES').aggregate(t=Sum('amount'))['t'] or 0),
            'pending_payments':  payments_qs.filter(status='pending').count(),
        },
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_users_list(request):
    """List all users with their plan and site count."""
    err = _require_admin(request)
    if err: return err

    from django.db.models import Count
    users = CustomUser.objects.annotate(
        site_count=Count('sites')  
    ).order_by('-date_joined')

    data = []
    for u in users:
        data.append({
            'id':           u.id,
            'email':        u.email,
            'full_name':    u.full_name or '',
            'company_name': u.company_name or '',
            'plan':         u.plan,
            'is_admin':     u.is_admin_user,
            'is_active':    u.is_active,
            'site_count':   u.site_count,
            'date_joined':  u.date_joined.isoformat() if u.date_joined else None,
            'last_login':   u.last_login.isoformat()  if u.last_login  else None,
        })
    return Response(data)


@api_view(['PATCH'])
@permission_classes([IsAuthenticated])
def admin_update_user(request, user_id):
    """Update a user's plan or active status."""
    err = _require_admin(request)
    if err: return err

    try:
        target = CustomUser.objects.get(id=user_id)
    except CustomUser.DoesNotExist:
        return Response({'error': 'User not found'}, status=404)

    if 'plan' in request.data:
        allowed = [c[0] for c in CustomUser.PLAN_CHOICES]
        if request.data['plan'] not in allowed:
            return Response({'error': 'Invalid plan'}, status=400)
        target.plan = request.data['plan']
        if request.data['plan'] == 'admin':
            target.is_staff = True
            target.is_superuser = True

    if 'is_active' in request.data:
        target.is_active = bool(request.data['is_active'])

    target.save()
    return Response({
        'id':        target.id,
        'email':     target.email,
        'plan':      target.plan,
        'is_active': target.is_active,
        'is_admin':  target.is_admin_user,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_payments_list(request):
    """List all payments across all users."""
    err = _require_admin(request)
    if err: return err

    payments = Payment.objects.select_related('user').order_by('-created_at')
    data = []
    for p in payments:
        data.append({
            'id':          p.id,
            'user_email':  p.user.email,
            'user_name':   p.user.full_name or p.user.email,
            'plan':        p.plan,
            'provider':    p.provider,
            'amount':      float(p.amount),
            'currency':    p.currency,
            'status':      p.status,
            'checkout_id': p.checkout_id,
            'created_at':  p.created_at.isoformat(),
        })
    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_sites_list(request):
    """All registered sites across all users."""
    err = _require_admin(request)
    if err: return err

    sites = RegisteredSite.objects.select_related('owner_user').order_by('-registered_date')
    data = []
    for s in sites:
        data.append({
            'id':                 s.id,
            'domain':             s.domain,
            'owner':              s.owner,
            'owner_email':        s.owner_user.email if s.owner_user else '',
            'status':             s.status,
            'sessions_monitored': s.sessions_monitored,
            'threats_detected':   s.threats_detected,
            'registered_date':    s.registered_date.isoformat() if s.registered_date else None,
            'last_activity':      s.last_activity.isoformat()   if s.last_activity   else None,
        })
    return Response(data)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def admin_notifications(request):
    """
    Real-time notifications for the admin: recent threats + flagged activity.
    """
    err = _require_admin(request)
    if err: return err

    from datetime import timedelta
    cutoff = timezone.now() - timedelta(hours=24)

    notifications = []

    # Critical threats in last 24h
    for t in Threat.objects.filter(severity='critical', timestamp__gte=cutoff).order_by('-timestamp')[:5]:
        notifications.append({
            'type':      'critical_threat',
            'title':     'Critical Threat Detected',
            'body':      f'{t.threat_type} on {t.domain} from {t.ip_address}',
            'timestamp': t.timestamp.isoformat(),
            'severity':  'critical',
        })

    # Recently flagged sessions
    for s in ActiveSession.objects.filter(backend_type='deceptive', last_activity__gte=cutoff).order_by('-last_activity')[:5]:
        notifications.append({
            'type':      'deceptive_session',
            'title':     'Attacker Being Deceived',
            'body':      f'Session from {s.ip_address} on {s.domain} — {s.interaction_count} interactions',
            'timestamp': s.last_activity.isoformat(),
            'severity':  'high',
        })

    # New user registrations
    for u in CustomUser.objects.filter(date_joined__gte=cutoff).order_by('-date_joined')[:3]:
        notifications.append({
            'type':      'new_user',
            'title':     'New User Registered',
            'body':      f'{u.email} — {u.plan} plan',
            'timestamp': u.date_joined.isoformat(),
            'severity':  'info',
        })

    # Sort by timestamp desc
    notifications.sort(key=lambda n: n['timestamp'], reverse=True)

    return Response(notifications[:15])


# ═══════════════════════════════════════════════════════════════════════════════
# THREE-TIER EVALUATION — NEW VIEWS (v5)
# ═══════════════════════════════════════════════════════════════════════════════

@csrf_exempt
@require_http_methods(["GET", "HEAD"])
def noscript_beacon(request):
    """
    No-JS Tier 1 trap endpoint.

    The installation snippet injects this into every monitored page:

        <noscript>
          <link rel="stylesheet"
                href="https://your-platform.com/api/track/noscript/?s=SESSION_ID">
        </noscript>

    A real browser with JS enabled never loads this URL.
    A browser with JS disabled (or a headless bot) loads it automatically,
    which fires this view — setting a server-side flag on the session
    so the next request is immediately routed to the decoy backend.

    Returns a 1×1 transparent GIF (tiny, silent, invisible to the attacker).
    """
    session_id = request.GET.get('s') or request.GET.get('session_id')
    domain     = request.GET.get('d') or request.get_host().split(':')[0]

    if session_id:
        try:
            from .models import ActiveSession
            from .services.threat_evaluator import EvaluationResult
            from django.core.cache import cache

            # Flag in cache so middleware picks it up on the very next request
            cache.set(f'noscript_flag:{session_id}', True, timeout=3600)

            # If session row already exists — mark it immediately
            try:
                session = ActiveSession.objects.get(session_id=session_id)
                session.backend_type      = 'deceptive'
                session.threat_level      = 'high'
                session.engagement_status = 'deceiving'
                # Add technique
                techs = set(session.detected_techniques or [])
                techs.add('JavaScript Disabled (No-JS Evasion Attempt)')
                session.detected_techniques = list(techs)
                session.save(update_fields=[
                    'backend_type', 'threat_level',
                    'engagement_status', 'detected_techniques',
                ])
                logger.info("[T1] No-JS beacon fired for session %s on %s", session_id, domain)
            except ActiveSession.DoesNotExist:
                pass  # Session not yet created — cache flag will be picked up on first request

        except Exception as exc:
            logger.warning("[noscript_beacon] Error: %s", exc)

    # Return a 1×1 transparent GIF — completely silent to the attacker
    gif_bytes = (
        b'\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x80\x00\x00'
        b'\xff\xff\xff\x00\x00\x00\x21\xf9\x04\x00\x00\x00\x00\x00'
        b'\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b'
    )
    return HttpResponse(gif_bytes, content_type='image/gif')


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_evaluation_status(request, session_id):
    """
    Returns the latest three-tier evaluation result for a session.
    Used by the frontend dashboard to show tier breakdown details.
    """
    try:
        session = ActiveSession.objects.get(session_id=session_id)
    except ActiveSession.DoesNotExist:
        return Response({'error': 'Session not found'}, status=404)

    # Check ownership
    if session.site and session.site.owner_user != request.user:
        if not request.user.is_admin_user:
            return Response({'error': 'Forbidden'}, status=403)

    # Pull recent logs
    logs = list(
        ActivityLog.objects.filter(session_id=session_id)
        .order_by('-timestamp')[:30]
        .values('timestamp', 'method', 'endpoint', 'user_agent',
                'status_code', 'suspicion_score', 'response_time')
    )

    # Get site profile
    site_profile = None
    if session.site:
        try:
            site_profile = session.site.profile
        except Exception:
            pass

    # Run the evaluator
    from .services.threat_evaluator import evaluate_session
    result = evaluate_session(
        session=session,
        activity_logs=logs,
        site_profile=site_profile,
    )

    return Response({
        'session_id':         session_id,
        'flagged':            result.flagged,
        'tier':               result.tier,
        'score':              result.score,
        'threat_level':       result.threat_level,
        'techniques':         result.techniques,
        'reasons':            result.reasons,
        'deception_strategy': result.deception_strategy,
        'confidence':         result.confidence,
        'ai_powered':         result.ai_powered,
        'explanation':        result.explanation,
        'soft_isolation':     result.soft_isolation,
        'tier1_triggers':     result.tier1_triggers,
        'tier2_breakdown':    result.tier2_breakdown,
        'tier3_analysis':     result.tier3_analysis,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_installation_snippet_v5(request, site_id):
    """
    Returns the v5 installation snippet for a registered site.

    This snippet is what client sites embed into their HTML. It handles:
      1. JS-based activity tracking (requests, navigation, timing)
      2. Noscript beacon — silently flags sessions that disabled JS (Tier 1)
      3. Honeypot hidden form field — auto-injected into all forms (Tier 1)
      4. Proof-of-Work token — gatekeeper against raw HTTP scrapers

    The snippet is 100% passive and non-blocking. It never slows the page.
    """
    try:
        site = RegisteredSite.objects.get(id=site_id, owner_user=request.user)
    except RegisteredSite.DoesNotExist:
        return Response({'error': 'Site not found'}, status=404)

    platform_url  = request.build_absolute_uri('/').rstrip('/')
    noscript_url  = f"{platform_url}/api/track/noscript/"
    track_url     = f"{platform_url}/api/track/public/"

    snippet = f"""<!-- ╔══════════════════════════════════════════════════════╗ -->
<!-- ║   Genius Mirage  |  Protection Snippet v5           ║ -->
<!-- ║   Site: {site.domain:<44} ║ -->
<!-- ╚══════════════════════════════════════════════════════╝ -->
<script>
(function() {{
  'use strict';
  var GM = {{
    siteId:   '{site.id}',
    domain:   '{site.domain}',
    trackUrl: '{track_url}',
    sid:      null,

    // ── Session ID management ────────────────────────────────────────────────
    getSessionId: function() {{
      if (GM.sid) return GM.sid;
      var k = '_gm_sid_{site.id}';
      var v = sessionStorage.getItem(k);
      if (!v) {{
        v = 'gm-' + Date.now().toString(36) + '-' + Math.random().toString(36).substr(2, 9);
        sessionStorage.setItem(k, v);
      }}
      GM.sid = v;
      return v;
    }},

    // ── Inject noscript beacon ──────────────────────────────────────────────
    // If JS is disabled, the browser loads this URL automatically (Tier 1 trap)
    injectNoscript: function() {{
      var ns = document.createElement('noscript');
      var s  = GM.getSessionId();
      ns.innerHTML = '<link rel="stylesheet" href="{noscript_url}?s=' + s + '&d={site.domain}">';
      document.head.appendChild(ns);
    }},

    // ── Inject honeypot hidden field into all forms ─────────────────────────
    // Real users never see or touch this field. Attackers who manipulate
    // form params will change it, triggering Tier 1 immediately.
    injectHoneyFields: function() {{
      var forms = document.querySelectorAll('form');
      forms.forEach(function(f) {{
        if (!f.querySelector('[name="_gm_role"]')) {{
          var inp = document.createElement('input');
          inp.type  = 'hidden';
          inp.name  = '_gm_role';
          inp.value = 'visitor';
          inp.style.display = 'none';
          f.appendChild(inp);
        }}
      }});
      // Also watch for dynamically-added forms
      if (window.MutationObserver) {{
        var obs = new MutationObserver(function() {{ GM.injectHoneyFields(); }});
        obs.observe(document.body, {{ childList: true, subtree: true }});
      }}
    }},

    // ── Page timing tracker ─────────────────────────────────────────────────
    _pageStart:  Date.now(),
    _prevPath:   location.pathname,

    // ── Send activity to platform ───────────────────────────────────────────
    send: function(extra) {{
      var payload = Object.assign({{
        session_id:  GM.getSessionId(),
        domain:      GM.domain,
        site_id:     GM.siteId,
        endpoint:    location.pathname + location.search,
        method:      'GET',
        user_agent:  navigator.userAgent,
        referrer:    document.referrer,
        timestamp:   new Date().toISOString(),
        dwell_ms:    Date.now() - GM._pageStart,
        screen:      screen.width + 'x' + screen.height,
        lang:        navigator.language,
        js_enabled:  true
      }}, extra || {{}});

      // Use sendBeacon where available (non-blocking, survives page unload)
      var data = JSON.stringify(payload);
      if (navigator.sendBeacon) {{
        navigator.sendBeacon(GM.trackUrl, new Blob([data], {{type: 'application/json'}}));
      }} else {{
        var xhr = new XMLHttpRequest();
        xhr.open('POST', GM.trackUrl, true);
        xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(data);
      }}
    }},

    // ── Track page unload (captures dwell time) ─────────────────────────────
    trackUnload: function() {{
      GM.send({{ dwell_ms: Date.now() - GM._pageStart, event: 'unload' }});
    }},

    // ── Track SPA navigation (React/Vue/Angular) ────────────────────────────
    trackNavigation: function() {{
      var curr = location.pathname;
      if (curr !== GM._prevPath) {{
        GM.send({{ event: 'navigate', from: GM._prevPath }});
        GM._prevPath = curr;
        GM._pageStart = Date.now();
      }}
    }},

    // ── Initialise ──────────────────────────────────────────────────────────
    init: function() {{
      GM.injectNoscript();

      document.addEventListener('DOMContentLoaded', function() {{
        GM.injectHoneyFields();
        GM.send({{ event: 'pageview' }});
      }});

      window.addEventListener('beforeunload', GM.trackUnload);

      // Poll for SPA navigation every 500ms
      setInterval(GM.trackNavigation, 500);
    }}
  }};

  GM.init();
}})();
</script>
<!-- End Genius Mirage Snippet -->"""

    return Response({
        'site_id':   site.id,
        'domain':    site.domain,
        'snippet':   snippet,
        'version':   'v5',
    })


# ═══════════════════════════════════════════════════════════════════════════════
# SWAP LAYER VIEWS (v5)
# ═══════════════════════════════════════════════════════════════════════════════

from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods


@csrf_exempt
@require_http_methods(["GET"])
def session_status(request):
    """
    GET /api/swap/session-status/?session_id=X&site_id=Y
    Called by client SDK middleware on every request (hard 300ms timeout from client).
    Returns backend_type: real | deceptive — answered from cache in <5ms.
    """
    from base.services.swap_middleware import session_status_view
    return session_status_view(request)


@csrf_exempt
@require_http_methods(["POST"])
def decoy_response(request):
    """
    POST /api/swap/decoy-response/
    Called by client SDK when a session is flagged.
    Runs the decoy engine and returns the full response to serve the attacker.
    """
    from base.services.swap_middleware import decoy_response_view
    return decoy_response_view(request)


@csrf_exempt
def proxy_root(request, site_id):
    """
    ALL /api/proxy/<site_id>/
    Full reverse-proxy root for clients who point their DNS here.
    """
    from base.services.swap_middleware import full_proxy_view
    return full_proxy_view(request, site_id, path='')


@csrf_exempt
def proxy_path(request, site_id, fwd_path=''):
    """
    ALL /api/proxy/<site_id>/<path>
    Full reverse-proxy with path for clients who point their DNS here.
    """
    from base.services.swap_middleware import full_proxy_view
    return full_proxy_view(request, site_id, path=fwd_path)


# ═══════════════════════════════════════════════════════════════════════════════
# SDK CONFIG ENDPOINT (v5.1) — site owner retrieves credentials for the
# Django/Flask/Express SDK middleware.
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_sdk_config(request, site_id):
    """
    GET /api/auth/sites/<site_id>/sdk-config/

    Returns the configuration values the site owner needs to plug into
    genius_mirage_sdk (Django / Flask / Express) on their own server:

        {
          "site_id":   "site-...",
          "api_url":   "http://127.0.0.1:8000",
          "api_token": "<32-char token>"
        }

    The token is deterministically derived from (site_id, domain, SECRET_KEY)
    so it never needs to be stored separately — it can be regenerated any
    time by calling this endpoint again.
    """
    import hashlib as _hashlib
    from django.conf import settings

    try:
        site = RegisteredSite.objects.get(id=site_id, owner_user=request.user)
    except RegisteredSite.DoesNotExist:
        return Response({'error': 'Site not found'}, status=404)

    token = _hashlib.md5(
        f"{site.id}:{site.domain}:{settings.SECRET_KEY}".encode()
    ).hexdigest()[:32]

    api_url = request.build_absolute_uri('/').rstrip('/')

    return Response({
        'site_id':   site.id,
        'domain':    site.domain,
        'api_url':   api_url,
        'api_token': token,
        'usage': {
            'flask': (
                "from genius_mirage_sdk.flask_sdk import GeniusMirageFlask\n"
                "GeniusMirageFlask(app, site_id='%s', api_url='%s', api_token='%s')"
            ) % (site.id, api_url, token),
            'django_settings': (
                "GENIUS_MIRAGE_SITE_ID = '%s'\n"
                "GENIUS_MIRAGE_API_URL = '%s'\n"
                "GENIUS_MIRAGE_API_TOKEN = '%s'"
            ) % (site.id, api_url, token),
            'express': (
                "app.use(require('./genius_mirage_sdk/express_sdk')({\n"
                "  siteId: '%s',\n  apiUrl: '%s',\n  apiToken: '%s',\n}));"
            ) % (site.id, api_url, token),
        },
    })


@csrf_exempt
@require_http_methods(["POST"])
def swap_process(request):
    """
    POST /api/swap/process/
    Primary SDK entry point — single round trip: evaluate (if needed) + decoy.
    See base.services.swap_middleware.swap_process_view for full docs.
    """
    from base.services.swap_middleware import swap_process_view
    return swap_process_view(request)


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTIVE DECEPTION LOOP — API ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['GET', 'POST'])
@permission_classes([IsAuthenticated])
def deception_targets(request):
    """List or create DeceptionTarget records for the requesting user's sites."""
    from base.models import DeceptionTarget, RegisteredSite
    from base.serializers import DeceptionTargetSerializer

    if request.method == 'GET':
        site_ids = RegisteredSite.objects.filter(owner_user=request.user).values_list('id', flat=True)
        targets  = DeceptionTarget.objects.filter(site_id__in=site_ids).select_related('site')
        return Response(DeceptionTargetSerializer(targets, many=True).data)

    serializer = DeceptionTargetSerializer(data=request.data)
    if serializer.is_valid():
        site_id = request.data.get('site')
        try:
            site = RegisteredSite.objects.get(id=site_id, owner_user=request.user)
        except RegisteredSite.DoesNotExist:
            return Response({'error': 'Site not found or not owned by you'}, status=404)
        target = serializer.save(site=site)
        return Response(DeceptionTargetSerializer(target).data, status=201)
    return Response(serializer.errors, status=400)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def deception_target_detail(request, target_id):
    from base.models import DeceptionTarget
    from base.serializers import DeceptionTargetSerializer
    try:
        target = DeceptionTarget.objects.get(pk=target_id, site__owner_user=request.user)
    except DeceptionTarget.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)
    if request.method == 'GET':
        return Response(DeceptionTargetSerializer(target).data)
    s = DeceptionTargetSerializer(target, data=request.data, partial=True)
    if s.is_valid():
        s.save()
        return Response(s.data)
    return Response(s.errors, status=400)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def run_remediation(request, target_id):
    """Trigger an AI-powered remediation analysis for a DeceptionTarget."""
    from base.models import DeceptionTarget
    try:
        target = DeceptionTarget.objects.get(pk=target_id, site__owner_user=request.user)
    except DeceptionTarget.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)

    if not target.allow_automated_remediation_analysis:
        return Response({
            'error': 'Automated remediation analysis is not enabled for this site. '
                     'Enable it in the Deception Target settings first.'
        }, status=403)

    log_file = request.FILES.get('log_file')
    log_content = log_file.read().decode('utf-8', errors='replace') if log_file else None

    import threading
    from base.services.remediation_engine import run_remediation_for_target_sync

    def _bg():
        run_remediation_for_target_sync(target_id, log_content)

    threading.Thread(target=_bg, daemon=True).start()

    return Response({
        'status':    'running',
        'message':   'Remediation analysis started in background. '
                     'A blueprint will appear in your Remediation Dashboard when complete.',
        'target_id': target_id,
    })


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def list_blueprints(request, target_id):
    """List all StrategicDefenseBlueprints for a DeceptionTarget."""
    from base.models import DeceptionTarget, StrategicDefenseBlueprint
    from base.serializers import StrategicDefenseBlueprintSerializer
    try:
        target = DeceptionTarget.objects.get(pk=target_id, site__owner_user=request.user)
    except DeceptionTarget.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)
    bps = StrategicDefenseBlueprint.objects.filter(target=target).order_by('-created_at')
    return Response(StrategicDefenseBlueprintSerializer(bps, many=True).data)


@api_view(['GET', 'PUT'])
@permission_classes([IsAuthenticated])
def blueprint_detail(request, blueprint_id):
    """Get or update a blueprint's status/notes."""
    from base.models import StrategicDefenseBlueprint
    from base.serializers import StrategicDefenseBlueprintSerializer
    try:
        bp = StrategicDefenseBlueprint.objects.get(
            id=blueprint_id, target__site__owner_user=request.user
        )
    except StrategicDefenseBlueprint.DoesNotExist:
        return Response({'error': 'Not found'}, status=404)
    if request.method == 'GET':
        return Response(StrategicDefenseBlueprintSerializer(bp).data)
    allowed = {'status', 'operator_notes'}
    data = {k: v for k, v in request.data.items() if k in allowed}
    s = StrategicDefenseBlueprintSerializer(bp, data=data, partial=True)
    if s.is_valid():
        s.save()
        return Response(s.data)
    return Response(s.errors, status=400)


@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_shell_url(request, session_id):
    """Return the WebSocket URL for the honeypot shell for a given session."""
    from base.services.web_terminal_emulator import get_shell_websocket_url
    url = get_shell_websocket_url(session_id)
    if url is None:
        return Response(
            {'error': 'Session not eligible for shell honeypot '
                      '(must be flagged and swap-approved).'},
            status=400
        )
    return Response({'ws_url': url, 'session_id': session_id})


# ═══════════════════════════════════════════════════════════════════════════════
# PROXY PIPELINE ENDPOINTS — called by the universal proxy sidecar
# ═══════════════════════════════════════════════════════════════════════════════

@api_view(['POST'])
@permission_classes([AllowAny])   # proxy uses its own token, not user JWT
def proxy_schema_ingest(request):
    """
    Called by the universal proxy after forwarding a clean (non-flagged)
    request and getting a JSON response back from the upstream.

    Body:
        {
            "site_id":      "site-xxxx",
            "path":         "/api/v1/orders",
            "method":       "GET",
            "response_body": "{\"id\": 42, \"user\": \"alice\", ...}",
            "sdk_token":    "token"
        }

    The proxy verifies its SDK token, then fires passive_schema_ingest_sync()
    in a background thread so the proxy's response time is never affected.
    """
    import threading, hashlib
    from django.conf import settings as dj_settings

    site_id  = request.data.get('site_id', '')
    sdk_token = request.data.get('sdk_token', '')

    # Validate the SDK token (same HMAC as swap/process)
    try:
        site = RegisteredSite.objects.get(id=site_id)
        expected = hashlib.md5(
            f"{site.id}:{site.domain}:{dj_settings.SECRET_KEY}".encode()
        ).hexdigest()[:32]
        if not hmac_compare(expected, sdk_token):
            return Response({'error': 'Invalid token'}, status=403)
    except RegisteredSite.DoesNotExist:
        return Response({'error': 'Site not found'}, status=404)

    path          = request.data.get('path', '')
    method        = request.data.get('method', 'GET')
    response_body = request.data.get('response_body', '')

    if not path or not response_body:
        return Response({'status': 'skipped', 'reason': 'empty path or body'})

    def _ingest():
        try:
            from base.services.decoy_engine_upgrade import passive_schema_ingest_sync
            passive_schema_ingest_sync(path, method, response_body, site_id)
        except Exception as exc:
            logger.debug("[SchemaIngest] Background error: %s", exc)

    threading.Thread(target=_ingest, daemon=True).start()
    return Response({'status': 'accepted'})


@api_view(['POST'])
@permission_classes([AllowAny])
def proxy_ai_decoy(request):
    """
    Called by the universal proxy when a flagged (swap_approved) session
    hits an endpoint for which we have a schema blueprint. Returns an
    AI-synthesised JSON response body that fits the real endpoint's shape.

    Body:
        {
            "site_id":    "site-xxxx",
            "path":       "/api/v1/orders",
            "method":     "GET",
            "sdk_token":  "token"
        }

    Returns:
        { "body": "{ ... synthetic JSON ... }", "content_type": "application/json" }
    """
    import asyncio, hashlib
    from django.conf import settings as dj_settings

    site_id   = request.data.get('site_id', '')
    sdk_token = request.data.get('sdk_token', '')

    try:
        site = RegisteredSite.objects.get(id=site_id)
        expected = hashlib.md5(
            f"{site.id}:{site.domain}:{dj_settings.SECRET_KEY}".encode()
        ).hexdigest()[:32]
        if not hmac_compare(expected, sdk_token):
            return Response({'error': 'Invalid token'}, status=403)
    except RegisteredSite.DoesNotExist:
        return Response({'error': 'Site not found'}, status=404)

    path   = request.data.get('path', '')
    method = request.data.get('method', 'GET')

    try:
        from base.models import DeceptionTarget, SchemaEndpointBlueprint
        target = DeceptionTarget.objects.get(site=site, allow_schema_mirroring=True)
        bp = SchemaEndpointBlueprint.objects.get(target=target, path=path, method=method.upper())
        structure = bp.structure
    except Exception:
        # No blueprint for this endpoint — fall back to generic decoy
        return Response({'body': '{"status": "ok", "data": []}', 'content_type': 'application/json'})

    try:
        from base.services.decoy_engine_upgrade import generate_ai_decoy_response
        body = asyncio.run(generate_ai_decoy_response(path, method, structure))
        return Response({'body': body, 'content_type': 'application/json'})
    except Exception as exc:
        logger.warning("[AiDecoy] Generation failed: %s", exc)
        return Response({'body': '{"status": "ok", "data": []}', 'content_type': 'application/json'})


def hmac_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    import hmac as _hmac
    return _hmac.compare_digest(a.encode(), b.encode())
