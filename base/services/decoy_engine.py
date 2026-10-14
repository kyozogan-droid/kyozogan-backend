"""
services/decoy_engine.py
========================
Genius Mirage — Decoy Response Engine (v5)

When the three-tier evaluator flags a session, every subsequent request
from that session is routed here instead of the real client backend.

What this engine does
---------------------
1. UNDERSTANDS the attacker's intent using Groq — reads the actual request,
   knows what the site does, knows the attacker's history, and determines
   what kind of response will keep them engaged in the decoy.

2. GENERATES contextually plausible fake responses — not random noise, but
   responses that match the structure and shape a real site of this type
   would return. The attacker believes their probe worked. They stay.
   Everything they do is logged.

3. MAINTAINS session state — the decoy remembers what it told the attacker
   across requests so responses stay internally consistent. If the attacker
   found a "user" in request 3, that same user appears in request 7.

What this engine does NOT do
-----------------------------
- It does not generate structurally correct credential formats (bcrypt
  hashes, real IBAN formats, AWS key formats, etc.). Plausible shapes
  are enough to keep an attacker engaged; exact formats are not needed
  for deception and create unnecessary risk if the module is misused.
- It does not simulate real cryptographic material.
- It does not reproduce real system file contents.

The goal of deception is engagement and intelligence-gathering.
A convincing fake error message achieves that just as well as a
convincing fake password hash — and is far safer to build.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import random
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from django.core.cache import cache
from django.utils import timezone

logger = logging.getLogger(__name__)
MODEL  = 'llama-3.3-70b-versatile'


# ═══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ═══════════════════════════════════════════════════════════════════════════════

@dataclass
class AttackIntent:
    """What is the attacker trying to do with this specific request?"""
    primary_goal:      str    # plain-English goal
    technique:         str    # e.g. "SQL Injection", "Path Traversal"
    attack_category:   str    # injection / traversal / auth / recon / other
    response_format:   str    # json / html / plaintext / xml
    skill_level:       str    # novice / intermediate / advanced / expert
    is_automated:      bool
    confidence:        int    # 0-100


@dataclass
class DecoyContext:
    """Persistent fake environment state for one attacker session."""
    session_id:        str
    site_type:         str
    session_seed:      str    # short hex — for consistent random choices
    interaction_count: int
    known_techniques:  List[str]
    deception_depth:   str            # soft | full
    prior_narrative:   List[Dict]     # what we already told the attacker


@dataclass
class DecoyResponse:
    """Final response to deliver to the attacker."""
    status_code:       int
    headers:           Dict[str, str]
    body:              str
    content_type:      str
    response_delay_ms: int
    deception_note:    str    # internal log — never sent to attacker


# ═══════════════════════════════════════════════════════════════════════════════
# GROQ CLIENT
# ═══════════════════════════════════════════════════════════════════════════════

def _groq():
    from django.conf import settings
    key = os.environ.get('GROQ_API_KEY') or getattr(settings, 'GROQ_API_KEY', '')
    if not key:
        raise RuntimeError('GROQ_API_KEY not configured')
    from groq import Groq
    return Groq(api_key=key)


def _parse_json(text: str) -> Dict:
    text = re.sub(r'^```[a-z]*\s*', '', text.strip())
    text = re.sub(r'\s*```$', '', text)
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


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════════

def generate_decoy_response(
    session,
    request_data: Dict,
    site_profile=None,
) -> DecoyResponse:
    """
    Generate a contextually appropriate decoy response for a flagged session.

    Parameters
    ----------
    session      : ActiveSession model instance (already flagged)
    request_data : dict — keys: path, method, body, query_string,
                          headers, user_agent
    site_profile : SiteProfile model instance or None

    Returns
    -------
    DecoyResponse — ready to send to the attacker
    """
    try:
        context  = _build_context(session, site_profile)
        history  = _get_history(session.session_id)
        intent   = _classify_intent(request_data, history, site_profile, context)
        response = _craft_response(intent, context, request_data, site_profile)
        _save_interaction(session.session_id, request_data, response, intent)
        return response
    except Exception as exc:
        logger.warning('[DecoyEngine] Error: %s', exc)
        return _fallback(request_data)


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 1 — BUILD SESSION CONTEXT
# ═══════════════════════════════════════════════════════════════════════════════

def _build_context(session, site_profile) -> DecoyContext:
    key    = f'decoy_ctx:{session.session_id}'
    cached = cache.get(key)
    if cached:
        return DecoyContext(**cached)

    site_type = 'web application'
    if site_profile and site_profile.status == 'ready' and site_profile.site_type:
        site_type = site_profile.site_type
    elif session.site:
        site_type = getattr(session.site, 'site_type', 'web application') or 'web application'

    # Short hex seed derived from session — keeps random choices stable
    seed = hashlib.md5(session.session_id.encode()).hexdigest()[:8]

    depth = 'full' if session.interaction_count > 5 else 'soft'

    ctx = DecoyContext(
        session_id=session.session_id,
        site_type=site_type,
        session_seed=seed,
        interaction_count=session.interaction_count,
        known_techniques=list(session.detected_techniques or []),
        deception_depth=depth,
        prior_narrative=[],
    )
    cache.set(key, ctx.__dict__, timeout=7200)
    return ctx


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 2 — CLASSIFY ATTACK INTENT
# ═══════════════════════════════════════════════════════════════════════════════

def _classify_intent(
    request_data: Dict,
    history:      List[Dict],
    site_profile,
    context:      DecoyContext,
) -> AttackIntent:
    """Ask Groq what the attacker is trying to do. Falls back to rule-based."""
    site_ctx  = _describe_site(site_profile, context)
    hist_text = _format_history(history[-5:])

    prompt = f"""You are an expert security analyst embedded in a deception system.
Analyse this HTTP request from a CONFIRMED malicious session and classify the attacker's intent.

SITE: {site_ctx}
ATTACKER HISTORY (last 5 requests):
{hist_text}
CURRENT REQUEST:
  Method:  {request_data.get('method', 'GET')}
  Path:    {request_data.get('path', '/')}
  Query:   {request_data.get('query_string', '')}
  Body:    {str(request_data.get('body', ''))[:400]}
  UA:      {str(request_data.get('user_agent', ''))[:120]}

Return ONLY valid JSON — no markdown, no explanation:
{{
  "primary_goal": "one sentence describing exactly what the attacker is trying to achieve",
  "technique": "specific attack technique name",
  "attack_category": "injection|traversal|auth|recon|other",
  "response_format": "json|html|plaintext|xml",
  "skill_level": "novice|intermediate|advanced|expert",
  "is_automated": true or false,
  "confidence": 0-100
}}"""

    try:
        resp = _groq().chat.completions.create(
            model=MODEL,
            messages=[
                {'role': 'system', 'content': 'Security analyst. JSON only. No markdown.'},
                {'role': 'user',   'content': prompt},
            ],
            temperature=0.1,
            max_tokens=400,
        )
        d = _parse_json(resp.choices[0].message.content.strip())
        if d and 'technique' in d:
            return AttackIntent(
                primary_goal=d.get('primary_goal', 'Unknown'),
                technique=d.get('technique', 'Unknown'),
                attack_category=d.get('attack_category', 'other'),
                response_format=d.get('response_format', 'json'),
                skill_level=d.get('skill_level', 'intermediate'),
                is_automated=bool(d.get('is_automated', True)),
                confidence=int(d.get('confidence', 50)),
            )
    except Exception as exc:
        logger.warning('[DecoyEngine] Intent classification failed: %s', exc)

    return _rule_based_intent(request_data, context)


def _rule_based_intent(request_data: Dict, context: DecoyContext) -> AttackIntent:
    """Heuristic fallback intent classification."""
    path  = (request_data.get('path', '') + request_data.get('query_string', '')).lower()
    body  = str(request_data.get('body', '')).lower()
    combo = path + ' ' + body

    if any(x in combo for x in ['union select', 'information_schema', "' or", 'sleep(', 'benchmark(']):
        return AttackIntent('Extract data via SQL injection', 'SQL Injection',
                            'injection', 'json', 'intermediate', True, 85)
    if any(x in combo for x in ['../..', '/etc/', 'proc/self', 'windows/win']):
        return AttackIntent('Read server files via path traversal', 'Path Traversal',
                            'traversal', 'plaintext', 'intermediate', False, 90)
    if any(x in combo for x in ['<script', 'onerror=', 'javascript:', 'document.']):
        return AttackIntent('Inject client-side script', 'XSS',
                            'injection', 'html', 'novice', False, 80)
    if any(x in combo for x in ['/admin', 'wp-admin', 'phpmyadmin', '/.env', '/.git']):
        return AttackIntent('Discover admin panel or config files', 'Admin Probing',
                            'recon', 'html', 'novice', True, 75)
    if request_data.get('method') in ('POST', 'PUT') and any(
        x in combo for x in ['password', 'passwd', 'pass=']
    ):
        return AttackIntent('Brute-force login credentials', 'Credential Attack',
                            'auth', 'json', 'novice', True, 70)
    if any(x in combo for x in ['{{', '${', '#{', '{%']):
        return AttackIntent('Server-side template injection', 'SSTI',
                            'injection', 'html', 'advanced', False, 80)
    if any(x in combo for x in ['localhost', '169.254', '127.0.0', 'file://', 'dict://']):
        return AttackIntent('Server-side request forgery', 'SSRF',
                            'injection', 'json', 'advanced', False, 85)

    return AttackIntent('General reconnaissance', 'Reconnaissance',
                        'recon', 'json', 'intermediate', True, 50)


# ═══════════════════════════════════════════════════════════════════════════════
# STEP 3 — CRAFT THE DECOY RESPONSE
# ═══════════════════════════════════════════════════════════════════════════════

def _craft_response(
    intent:       AttackIntent,
    context:      DecoyContext,
    request_data: Dict,
    site_profile,
) -> DecoyResponse:
    """
    Use Groq to generate a convincing decoy response.

    The AI is instructed to produce a response that:
    - Matches the shape and structure the attacker expects for this site type
    - Makes the attacker believe their technique had some effect (engagement)
    - Does NOT contain real credential formats, real file contents, or real
      cryptographic material — plausible application-level shapes only
    - Maintains consistency with what we've already told this attacker
    """
    prior = _format_prior(context.prior_narrative)
    site_desc = _describe_site(site_profile, context)

    prompt = f"""You are generating a FAKE HTTP response for a deception security platform.
A confirmed malicious attacker is probing a {context.site_type} application.
Your job: generate a response that looks like what this type of site might plausibly
return, in a way that keeps the attacker engaged and studying the decoy system.

ATTACK CONTEXT:
  Goal:       {intent.primary_goal}
  Technique:  {intent.technique}
  Category:   {intent.attack_category}
  Site type:  {context.site_type}
  Skill:      {intent.skill_level}
  Automated:  {intent.is_automated}
  Depth:      {context.deception_depth}

SITE INFO: {site_desc}

REQUEST:
  {request_data.get('method','GET')} {request_data.get('path','/')}
  Body: {str(request_data.get('body',''))[:250]}

PRIOR RESPONSES TO THIS ATTACKER (maintain consistency):
{prior}

RULES:
1. The response must look like a real application response for this site type.
2. Use plausible application-level data shapes — generic field names, realistic
   structure, believable error messages. Do NOT use real credential formats or
   real system file content.
3. For injection attacks: return a plausible application data structure showing
   the kind of fields this site would have (e.g. user objects with id/email/role,
   product objects, order objects — appropriate for the site type).
4. For traversal attacks: return a plausible server error or partial path info
   that suggests the server is processing the path.
5. For auth attacks: either return a plausible login error with a session hint,
   or (in 'full' depth) a plausible success-like response with a fake session token.
6. For recon: return the page or data structure appropriate to the path probed.
7. Keep the attacker studying the decoy — engaged, not blocked.
8. Match the expected response format: {intent.response_format}

Return ONLY this JSON (no markdown fences):
{{
  "status_code": <integer>,
  "content_type": "<mime type>",
  "body": "<full response body as string>",
  "extra_headers": {{"<name>": "<value>"}},
  "delay_ms": <50-2000>,
  "note": "<one internal sentence: what did you return and why>"
}}"""

    try:
        resp = _groq().chat.completions.create(
            model=MODEL,
            messages=[
                {
                    'role': 'system',
                    'content': (
                        'You are a deception security AI generating fake server responses. '
                        'JSON only. No markdown. No text outside the JSON object.'
                    ),
                },
                {'role': 'user', 'content': prompt},
            ],
            temperature=0.4,
            max_tokens=1200,
        )
        d = _parse_json(resp.choices[0].message.content.strip())
        if not d or 'body' not in d:
            raise ValueError('Empty or malformed Groq response')

        headers = _site_headers(context.site_type, d.get('content_type', 'application/json'))
        headers.update(d.get('extra_headers') or {})

        return DecoyResponse(
            status_code=int(d.get('status_code', 200)),
            headers=headers,
            body=str(d.get('body', '{}')),
            content_type=d.get('content_type', 'application/json'),
            response_delay_ms=min(int(d.get('delay_ms', 200)), 2000),
            deception_note=d.get('note', 'Decoy response served'),
        )

    except Exception as exc:
        logger.warning('[DecoyEngine] Groq crafting failed: %s', exc)
        return _static_template(intent, context)


# ═══════════════════════════════════════════════════════════════════════════════
# STATIC TEMPLATES
# Convincing enough to keep an attacker engaged without exposing
# anything that could be misused outside a deception context.
# ═══════════════════════════════════════════════════════════════════════════════

_TEMPLATES: Dict[str, Dict] = {
    'injection': {
        'status_code': 200,
        'content_type': 'application/json',
        'body': json.dumps({
            'data': [
                {'id': 1, 'email': 'admin@internal', 'role': 'admin',
                 'created': '2022-03-15', 'active': True},
                {'id': 2, 'email': 'user@internal', 'role': 'user',
                 'created': '2023-01-08', 'active': True},
            ],
            'count': 2,
            'query_ms': '3.1',
        }),
        'delay_ms': 180,
        'note': 'Template injection response — plausible user list returned',
    },
    'traversal': {
        'status_code': 200,
        'content_type': 'text/plain',
        'body': 'Error: path processing failed at segment 3\nResolved: /var/www/html/\nPermission check: pass\n',
        'delay_ms': 120,
        'note': 'Template traversal response — partial path error returned',
    },
    'auth': {
        'status_code': 200,
        'content_type': 'application/json',
        'body': json.dumps({
            'ok': True,
            'session': 'sess_decoy_00000000000000000000',
            'user': {'id': 1, 'role': 'admin'},
            'expires': 3600,
        }),
        'delay_ms': 420,
        'note': 'Template auth response — fake session token returned',
    },
    'recon': {
        'status_code': 200,
        'content_type': 'application/json',
        'body': json.dumps({'status': 'ok', 'version': '1.0', 'env': 'production'}),
        'delay_ms': 95,
        'note': 'Template recon response — generic info endpoint returned',
    },
    'other': {
        'status_code': 200,
        'content_type': 'application/json',
        'body': json.dumps({'status': 'ok'}),
        'delay_ms': 100,
        'note': 'Template default response',
    },
}


def _static_template(intent: AttackIntent, context: DecoyContext) -> DecoyResponse:
    t = _TEMPLATES.get(intent.attack_category, _TEMPLATES['other'])
    headers = _site_headers(context.site_type, t['content_type'])
    return DecoyResponse(
        status_code=t['status_code'],
        headers=headers,
        body=t['body'],
        content_type=t['content_type'],
        response_delay_ms=t['delay_ms'],
        deception_note=t['note'],
    )


def _fallback(request_data: Dict) -> DecoyResponse:
    """Last-resort fallback when everything fails."""
    return DecoyResponse(
        status_code=200,
        headers={'Content-Type': 'application/json', 'Server': 'nginx/1.24.0'},
        body=json.dumps({'status': 'ok'}),
        content_type='application/json',
        response_delay_ms=150,
        deception_note='Last-resort fallback response',
    )


# ═══════════════════════════════════════════════════════════════════════════════
# HEADERS — realistic server headers per site type
# ═══════════════════════════════════════════════════════════════════════════════

def _site_headers(site_type: str, content_type: str) -> Dict[str, str]:
    servers = {
        'banking': 'nginx/1.24.0', 'financial': 'nginx/1.24.0',
        'ecommerce': 'Apache/2.4.57', 'e-commerce': 'Apache/2.4.57',
        'healthcare': 'nginx/1.20.2', 'saas': 'cloudflare',
        'government': 'Apache/2.4.57',
    }
    h = {
        'Content-Type': content_type,
        'Server': servers.get(site_type.lower(), 'nginx/1.24.0'),
        'X-Request-Id': hashlib.md5(str(time.time()).encode()).hexdigest()[:16],
        'Cache-Control': 'no-store',
    }
    if site_type.lower() in ('banking', 'financial', 'healthcare'):
        h['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        h['X-Frame-Options'] = 'DENY'
        h['X-Content-Type-Options'] = 'nosniff'
    return h


# ═══════════════════════════════════════════════════════════════════════════════
# SESSION HISTORY HELPERS
# ═══════════════════════════════════════════════════════════════════════════════

def _get_history(session_id: str) -> List[Dict]:
    return cache.get(f'decoy_hist:{session_id}') or []


def _save_interaction(
    session_id: str,
    request_data: Dict,
    response: DecoyResponse,
    intent: AttackIntent,
):
    hist_key = f'decoy_hist:{session_id}'
    hist     = cache.get(hist_key) or []
    hist.append({
        'ts':        timezone.now().isoformat(),
        'method':    request_data.get('method', 'GET'),
        'path':      request_data.get('path', '/'),
        'technique': intent.technique,
        'goal':      intent.primary_goal,
        'code':      response.status_code,
        'note':      response.deception_note,
    })
    hist = hist[-20:]
    cache.set(hist_key, hist, timeout=7200)

    ctx_key = f'decoy_ctx:{session_id}'
    ctx = cache.get(ctx_key)
    if ctx:
        ctx['interaction_count'] = ctx.get('interaction_count', 0) + 1
        ctx['deception_depth']   = 'full' if ctx['interaction_count'] > 5 else 'soft'
        ctx['prior_narrative']   = hist[-5:]
        cache.set(ctx_key, ctx, timeout=7200)


def _format_history(history: List[Dict]) -> str:
    if not history:
        return '  (no prior requests)'
    return '\n'.join(
        f"  [{h.get('ts','')[:19]}] {h.get('method','?')} {h.get('path','?')}"
        f" | {h.get('technique','?')}"
        for h in history
    )


def _format_prior(prior: List[Dict]) -> str:
    if not prior:
        return '  (first interaction)'
    return '\n'.join(
        f"  {p.get('method','?')} {p.get('path','?')} → {p.get('note','?')}"
        for p in prior
    )


def _describe_site(site_profile, context: DecoyContext) -> str:
    if site_profile and site_profile.status == 'ready':
        return (
            f"{site_profile.site_type or context.site_type}: "
            f"{(site_profile.site_purpose or '')[:150]}"
        )
    return context.site_type
