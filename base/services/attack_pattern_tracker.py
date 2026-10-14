"""
services/attack_pattern_tracker.py
====================================
Connects real, live detections to the Attack Patterns dashboard page.

Before this module existed, `AttackPattern` and `PatternLearningData` were
only ever written to from one place: `_update_attack_pattern_from_intel`,
which runs when threat intelligence is *shared in* from another
organization. The actual detection pipeline — every SQL injection, path
traversal, IDOR attempt, etc. that `threat_evaluator.py` catches on real
traffic, every day — never touched either model. The Attack Patterns page
would stay empty (or only show data seeded from the intel-sharing flow)
even on a system that was actively detecting and deceiving attackers
constantly.

Both places that create a `Threat` record on a real detection —
`services/swap_middleware.py` and `deception_middleware.py` — call
`record_attack_patterns()` right after creating that Threat, so the
dashboard now reflects live activity.
"""

from __future__ import annotations

import logging
from typing import Iterable

from django.db.models import Q
from django.utils import timezone

logger = logging.getLogger(__name__)


# Keyword -> category mapping, applied to technique names as they come out
# of threat_evaluator.py / behavioral_detector.py (e.g. "Definitive SQL
# injection", "Path Traversal Attempt", "Admin Panel Probe"). Order matters —
# first match wins, so more specific categories are listed before "Other".
_CATEGORY_KEYWORDS = [
    (('scanner', 'nmap', 'sqlmap', 'nikto', 'masscan', 'attack tool'), 'Network Attacks'),
    (('sql injection', 'union select', 'sql syntax', 'database'),      'Database Attacks'),
    (('brute', 'credential', 'login', 'password', 'auth'),            'Authentication Attacks'),
    (('path traversal', 'file', 'backup', 'linux path', '.env', '.git', '.ssh'), 'File System Attacks'),
    (('xss', 'script', 'ssti', 'template', 'command injection', 'code injection'), 'Injection Attacks'),
    (('api', 'idor', 'sensitive'),                                    'API Attacks'),
    (('port', 'forwarding', 'spoof'),                                 'Network Attacks'),
]

# Fallback per-technique severity, used only if we're creating a brand new
# AttackPattern and don't have a better signal from the eval result itself.
_HIGH_SEVERITY_HINTS = ('critical', 'definitive', 'scanner', 'brute')


def _infer_category(technique: str) -> str:
    lowered = technique.lower()
    for keywords, category in _CATEGORY_KEYWORDS:
        if any(kw in lowered for kw in keywords):
            return category
    return 'Other'


def _infer_severity(technique: str, threat_level: str) -> str:
    if threat_level in ('high', 'critical'):
        return threat_level
    lowered = technique.lower()
    if any(hint in lowered for hint in _HIGH_SEVERITY_HINTS):
        return 'high'
    return threat_level or 'medium'


def record_attack_patterns(eval_result, threat) -> None:
    """
    Given the EvaluationResult from threat_evaluator and the Threat record
    just created from it, create-or-update an AttackPattern for each
    detected technique, and roll today's PatternLearningData counters.

    Deliberately fails soft (logs and returns) — a bug here must never
    prevent the actual Threat record or the deception response, since
    dashboard bookkeeping is secondary to the detection/deception path
    itself actually working.
    """
    try:
        from base.models import AttackPattern, PatternLearningData, Threat

        techniques: Iterable[str] = [t for t in (eval_result.techniques or []) if t][:5]
        if not techniques:
            return

        any_new = False
        any_repeat = False

        for technique in techniques:
            pattern, created = AttackPattern.objects.get_or_create(
                technique=technique,
                defaults={
                    'category':        _infer_category(technique),
                    'severity':        _infer_severity(technique, eval_result.threat_level),
                    'description':     eval_result.explanation or (
                        f"Detected via Tier {eval_result.tier} evaluation."
                    ),
                    'indicators':      list(techniques),
                    'frequency':       1,
                    'detection_count': 1,
                    'last_seen':       timezone.now(),
                },
            )
            if created:
                any_new = True
            else:
                any_repeat = True
                pattern.frequency       += 1
                pattern.detection_count += 1
                pattern.last_seen        = timezone.now()
                # Severity can escalate (e.g. a technique first seen at
                # 'medium' later shows up in a 'critical' session) but we
                # never downgrade it automatically — a human should decide
                # a pattern is less severe than previously recorded.
                new_severity = _infer_severity(technique, eval_result.threat_level)
                severity_rank = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
                if severity_rank.get(new_severity, 0) > severity_rank.get(pattern.severity, 0):
                    pattern.severity = new_severity
                if techniques:
                    pattern.indicators = list(set(pattern.indicators or []) | set(techniques))
                pattern.save()

            # Recompute distinct affected sites for this technique directly
            # from Threat records, rather than blindly incrementing a
            # counter (which would overcount every time the same site
            # triggers the same technique again). Threat.technique is a
            # comma-joined string of up to 5 technique names, so match on
            # containment rather than equality.
            pattern.sites_affected = (
                Threat.objects.filter(technique__icontains=technique)
                .values('site_id').distinct().count()
            )
            pattern.save(update_fields=['sites_affected'])

        _roll_learning_counters(new_patterns=1 if any_new else 0,
                                 repeating_patterns=1 if any_repeat else 0)

    except Exception as exc:
        logger.warning('[AttackPatternTracker] Failed to record pattern: %s', exc)


def _roll_learning_counters(new_patterns: int, repeating_patterns: int) -> None:
    """Roll today's PatternLearningData bucket forward by one detection
    event. Mirrors what the (still-available) manual
    `update_pattern_learning` API endpoint does, so both paths stay
    consistent — this just means real detections now update it too,
    instead of requiring someone/something to call that endpoint by hand."""
    from base.models import AttackPattern, PatternLearningData

    today = timezone.now().replace(hour=0, minute=0, second=0, microsecond=0)
    obj, created = PatternLearningData.objects.get_or_create(
        timestamp__gte=today,
        defaults={
            'new_patterns':       new_patterns,
            'repeating_patterns': repeating_patterns,
            'total_patterns':     AttackPattern.objects.count(),
        },
    )
    if not created:
        obj.new_patterns       += new_patterns
        obj.repeating_patterns += repeating_patterns
        obj.total_patterns      = AttackPattern.objects.count()
        obj.save()
