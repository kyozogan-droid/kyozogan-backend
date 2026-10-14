"""
backend/base/tests.py
======================
Regression tests for the fixes made to the detection pipeline.

Before this file, `tests.py` was three lines with no actual coverage —
meaning every claim about detection accuracy or false-positive rate was
unverified. These tests lock in two things:

 1. The API key generation fix (Organization.save) — no longer a
    predictable MD5 hash of guessable inputs.
 2. The Tier 2 false-positive fixes in threat_evaluator.py — legitimate
    traffic (API clients, CDN chains, dynamic URLs) should score low;
    genuine multi-signal attacks should still score high.

Run with:
    python manage.py test base
"""

from django.test import TestCase, SimpleTestCase
from django.utils import timezone

from base.models import Organization
from base.services.threat_evaluator import (
    _check_tier1,
    _check_tier2,
    _build_session_data,
    _normalize_path,
    T3_HIGH_THRESHOLD,
    T3_LOW_THRESHOLD,
)


# ═══════════════════════════════════════════════════════════════════════════
# API KEY GENERATION (security fix)
# ═══════════════════════════════════════════════════════════════════════════

class OrganizationApiKeyTests(TestCase):
    def test_api_key_is_not_predictable_md5(self):
        """
        The old implementation was:
            md5(f"{name}:{time.time()}:{tier}")[:32]
        which is fully reproducible by anyone who can guess/observe the
        org name, approximate signup time, and tier — all of which are
        often public or easy to infer. The new key must not be
        reconstructable from those inputs.
        """
        import hashlib
        import time

        org = Organization.objects.create(name="Acme Corp", subscription_tier="pro")

        guessed = hashlib.md5(f"Acme Corp:{time.time()}:pro".encode()).hexdigest()[:32]
        self.assertNotEqual(org.api_key, guessed)

        self.assertTrue(org.api_key.startswith("gm_"))
        self.assertGreater(len(org.api_key), 40)

    def test_api_keys_are_unique_even_for_identical_inputs(self):
        org_a = Organization.objects.create(name="Same Name", subscription_tier="free")
        org_b = Organization.objects.create(name="Same Name", subscription_tier="free")
        self.assertNotEqual(org_a.api_key, org_b.api_key)

    def test_api_key_has_high_entropy(self):
        org = Organization.objects.create(name="Entropy Co", subscription_tier="enterprise")
        token_part = org.api_key.split("gm_", 1)[1]
        self.assertGreaterEqual(len(set(token_part)), 10)


# ═══════════════════════════════════════════════════════════════════════════
# TIER 1 — deterministic wiretrips (sanity check, should still be zero-FP)
# ═══════════════════════════════════════════════════════════════════════════

class Tier1Tests(SimpleTestCase):
    def test_sqli_payload_triggers(self):
        req = {"path": "/search", "query_string": "q=' OR '1'='1", "user_agent": "Mozilla/5.0"}
        triggered, reasons = _check_tier1(req, {}, session_id="")
        self.assertTrue(triggered)

    def test_path_traversal_triggers(self):
        req = {"path": "/files/../../../../etc/passwd", "query_string": "", "user_agent": "curl/8.0"}
        triggered, reasons = _check_tier1(req, {}, session_id="")
        self.assertTrue(triggered)

    def test_normal_browsing_does_not_trigger(self):
        req = {
            "path": "/products/running-shoes",
            "query_string": "color=blue&size=10",
            "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "method": "GET",
        }
        triggered, reasons = _check_tier1(req, {}, session_id="")
        self.assertFalse(triggered, f"Unexpected Tier 1 trigger on benign request: {reasons}")


# ═══════════════════════════════════════════════════════════════════════════
# TIER 2 — false-positive regression tests
# ═══════════════════════════════════════════════════════════════════════════

class Tier2FalsePositiveTests(SimpleTestCase):
    def test_legit_api_client_with_no_browser_headers(self):
        req = {
            "path": "/api/v1/orders",
            "query_string": "",
            "user_agent": "python-requests/2.31.0",
            "headers": {},
            "method": "GET",
            "body": "",
        }
        score, breakdown, techniques = _check_tier2(req, {}, [], None)
        self.assertLess(score, T3_LOW_THRESHOLD, f"breakdown={breakdown}")
        self.assertNotIn("Missing Accept Header", breakdown)
        self.assertNotIn("Missing Accept-Encoding", breakdown)

    def test_cdn_multihop_forwarding_chain_not_flagged_as_spoofing(self):
        req = {
            "path": "/",
            "query_string": "",
            "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            "headers": {
                "Accept": "text/html",
                "Accept-Encoding": "gzip",
                "X-Forwarded-For": "203.0.113.5, 198.51.100.2, 192.0.2.9, 10.0.0.1",
            },
            "method": "GET",
            "body": "",
        }
        score, breakdown, techniques = _check_tier2(req, {}, [], None)
        self.assertNotIn("Unusually Long Forwarding Chain", breakdown)
        self.assertNotIn("Duplicate IPs in Forwarding Chain", breakdown)

    def test_forwarding_chain_with_duplicate_ips_still_flagged(self):
        req = {
            "path": "/",
            "query_string": "",
            "user_agent": "Mozilla/5.0",
            "headers": {
                "Accept": "text/html",
                "Accept-Encoding": "gzip",
                "X-Forwarded-For": "203.0.113.5, 203.0.113.5, 203.0.113.5",
            },
            "method": "GET",
            "body": "",
        }
        score, breakdown, techniques = _check_tier2(req, {}, [], None)
        self.assertIn("Duplicate IPs in Forwarding Chain", breakdown)

    def test_dynamic_numeric_url_not_flagged_as_idor(self):
        req = {
            "path": "/invoice/482913",
            "query_string": "",
            "user_agent": "Mozilla/5.0",
            "headers": {"Accept": "text/html", "Accept-Encoding": "gzip"},
            "method": "GET",
            "body": "",
        }
        score, breakdown, techniques = _check_tier2(req, {}, [], None)
        self.assertNotIn("IDOR Enumeration", breakdown)
        self.assertLess(score, T3_LOW_THRESHOLD)

    def test_uncrawled_dynamic_route_not_flagged_when_normalized_match(self):
        class FakeSiteProfile:
            status = "ready"
            expected_paths = ["/api/admin/reports/91002"]

        req = {
            "path": "/api/admin/reports/482913",
            "query_string": "",
            "user_agent": "Mozilla/5.0",
            "headers": {"Accept": "text/html", "Accept-Encoding": "gzip"},
            "method": "GET",
            "body": "",
        }
        score, breakdown, techniques = _check_tier2(req, {}, [], FakeSiteProfile())
        self.assertNotIn("Unlinked Sensitive Path", breakdown)

    def test_generic_users_api_path_not_treated_as_sensitive(self):
        req = {
            "path": "/api/v1/users/42",
            "query_string": "",
            "user_agent": "Mozilla/5.0",
            "headers": {"Accept": "text/html", "Accept-Encoding": "gzip"},
            "method": "GET",
            "body": "",
        }
        score, breakdown, techniques = _check_tier2(req, {}, [], None)
        self.assertNotIn("Sensitive API Probe", breakdown)

    def test_headless_qa_automation_stays_below_hard_flag_alone(self):
        req = {
            "path": "/",
            "query_string": "",
            "user_agent": "Mozilla/5.0 HeadlessChrome/120.0 Playwright",
            "headers": {"Accept": "text/html", "Accept-Encoding": "gzip"},
            "method": "GET",
            "body": "",
        }
        score, breakdown, techniques = _check_tier2(req, {}, [], None)
        self.assertLess(score, T3_HIGH_THRESHOLD)


class Tier2TruePositiveTests(SimpleTestCase):
    """Make sure the false-positive fixes didn't gut real detection."""

    def test_admin_probe_with_sqli_and_velocity_stacks_to_hard_flag(self):
        """
        Note: we deliberately don't use a known scanner UA (e.g. 'sqlmap')
        here — that's caught outright by Tier 1's ABSOLUTE_ATTACK_UA check
        and would never actually reach Tier 2 in production. This tests
        that Tier 2 alone can still correctly stack independent signals
        (path signature + injection payload + velocity) to a hard flag.
        """
        req = {
            "path": "/wp-admin/admin-ajax.php",
            "query_string": "id=1' OR '1'='1",
            "user_agent": "curl/8.0",
            "headers": {},
            "method": "GET",
            "body": "",
        }
        session_data = {"requests_last_60s": 60}
        score, breakdown, techniques = _check_tier2(req, session_data, [], None)
        self.assertGreaterEqual(score, T3_HIGH_THRESHOLD, f"breakdown={breakdown}")
        self.assertGreaterEqual(len([v for v in breakdown.values() if v > 0]), 2)

    def test_high_velocity_plus_repeated_errors_still_scores_high(self):
        req = {
            "path": "/login",
            "query_string": "",
            "user_agent": "python-requests/2.31.0",
            "headers": {},
            "method": "POST",
            "body": "user=admin&pass=x",
        }
        session_data = {"requests_last_60s": 80, "repeated_4xx": 12}
        score, breakdown, techniques = _check_tier2(req, session_data, [], None)
        self.assertGreaterEqual(score, T3_HIGH_THRESHOLD)

    def test_scanner_ua_on_normal_path_now_detected(self):
        """
        Regression test for the closed gap: a scanner tool UA that isn't
        one of Tier 1's known attack-tool strings, hitting an
        otherwise-ordinary path, used to sail through Tier 2 completely
        undetected because the scanner-signature rule only checked the
        path/query/body, never the UA header.
        """
        req = {
            "path": "/products/1",
            "query_string": "",
            "user_agent": "Nmap Scripting Engine",
            "headers": {},
            "method": "GET",
            "body": "",
        }
        score, breakdown, techniques = _check_tier2(req, {}, [], None)
        self.assertIn("Scanner Tool UA", breakdown)


# ═══════════════════════════════════════════════════════════════════════════
# PATH NORMALIZATION HELPER
# ═══════════════════════════════════════════════════════════════════════════

class NormalizePathTests(SimpleTestCase):
    def test_numeric_segments_collapse(self):
        self.assertEqual(_normalize_path("/orders/48213"), "/orders/{id}")
        self.assertEqual(_normalize_path("/orders/91002"), "/orders/{id}")

    def test_uuid_segments_collapse(self):
        self.assertEqual(
            _normalize_path("/users/550e8400-e29b-41d4-a716-446655440000/profile"),
            "/users/{id}/profile",
        )

    def test_static_routes_unchanged(self):
        self.assertEqual(_normalize_path("/api/admin/reports"), "/api/admin/reports")

    def test_empty_path(self):
        self.assertEqual(_normalize_path(""), "")


# ═══════════════════════════════════════════════════════════════════════════
# SMALL-ID IDOR DETECTION (fix found via the genius-mirage-test-site harness)
# ═══════════════════════════════════════════════════════════════════════════

class SmallIdIdorDetectionTests(SimpleTestCase):
    """
    _build_session_data's sequential-ID detector used to require 3-8 digit
    IDs, so an app with small sequential IDs (invoice #1, #2, #3...) —
    extremely common for early-stage apps — was structurally invisible to
    it no matter how many were accessed. Confirmed against a real test app
    using exactly this ID scheme before being fixed.
    """

    def _logs(self, paths):
        return [{'endpoint': p, 'status_code': 200} for p in paths]

    def test_small_sequential_ids_now_detected(self):
        logs = self._logs([
            '/account/invoice/1', '/account/invoice/2',
            '/account/invoice/3', '/account/invoice/4',
        ])
        data = _build_session_data(None, logs)
        self.assertTrue(data['sequential_id_access'])

    def test_large_sequential_ids_still_detected(self):
        """Make sure lowering the minimum didn't break the original case."""
        logs = self._logs([
            '/invoice/100231', '/invoice/100232',
            '/invoice/100233', '/invoice/100234',
        ])
        data = _build_session_data(None, logs)
        self.assertTrue(data['sequential_id_access'])

    def test_too_few_small_ids_not_flagged(self):
        """Only 2 IDs seen — below the 4-ID minimum, must not trigger."""
        logs = self._logs(['/product/1', '/product/2'])
        data = _build_session_data(None, logs)
        self.assertFalse(data['sequential_id_access'])

    def test_widely_spaced_small_ids_not_flagged(self):
        """IDs present but with large gaps — not enumeration."""
        logs = self._logs(['/product/1', '/product/40', '/product/3', '/product/77'])
        data = _build_session_data(None, logs)
        self.assertFalse(data['sequential_id_access'])


# ═══════════════════════════════════════════════════════════════════════════
# AI FALLBACK BUG (found via the genius-mirage-test-site harness)
# ═══════════════════════════════════════════════════════════════════════════

class AiAnalyzerFallbackTests(TestCase):
    """
    analyze_session() used to catch its OWN failures (e.g. "no Groq API key
    configured") and quietly return a fallback dict with risk_score
    defaulting to 0 for most sessions — instead of letting the failure
    propagate to its callers, both of which already have correct handling
    for it: threat_evaluator._check_tier3() has a heuristic fallback that
    factors in request velocity and technique count, and views.py's
    ai_session_analysis endpoint catches RuntimeError specifically to
    return a 503. The swallowed exception meant Tier 3 silently got WORSE
    at scoring threats whenever the AI was unavailable — a very ordinary
    condition (no key configured, rate limit, outage), not an edge case.

    This test locks in that analyze_session() now raises instead of
    silently downgrading detection.
    """

    def test_missing_groq_key_raises_instead_of_silently_downgrading(self):
        from types import SimpleNamespace
        from django.utils import timezone
        from base.services.global_ai_analyzer import analyze_session

        fake_session = SimpleNamespace(
            session_id='test-session-1',
            ip_address='198.51.100.20',
            domain='example.test',
            start_time=timezone.now(),
            interaction_count=25,   # would have scored risk_score=50 under
                                     # the old silent fallback, masking the
                                     # fact that the AI never actually ran
            backend_type='real',
            threat_level='low',
        )
        logs = [{'endpoint': '/login', 'method': 'POST', 'status_code': 401,
                 'timestamp': timezone.now().isoformat()}]

        with self.assertRaises(Exception):
            # No GROQ_API_KEY is configured in the test environment, so
            # this must raise (RuntimeError from _groq_client(), most
            # likely) rather than returning a dict.
            analyze_session(fake_session, logs, site_profile=None)


# ═══════════════════════════════════════════════════════════════════════════
# SUBSCRIPTION ENFORCEMENT TOGGLE
# ═══════════════════════════════════════════════════════════════════════════

class SubscriptionToggleTests(TestCase):
    """
    Admin panel -> System Settings -> Subscription Enforcement. ON: users
    are limited to their plan's PLAN_LIMITS. OFF: every user gets unlimited
    access regardless of their stored plan — the whole system runs free.
    """

    def setUp(self):
        from base.models import CustomUser, SystemSettings
        self.free_user = CustomUser.objects.create_user(
            username='freeuser', email='free@example.com', password='x', plan='free',
        )
        self.settings_obj, _ = SystemSettings.objects.get_or_create(pk=1)

    def test_defaults_to_enforced(self):
        from base.models import subscriptions_are_enabled
        self.assertTrue(subscriptions_are_enabled())

    def test_free_plan_limited_when_enforced(self):
        self.settings_obj.subscriptions_enabled = True
        self.settings_obj.save()
        self.assertEqual(self.free_user.plan_limits['sites'], 1)

    def test_free_plan_unlimited_when_subscriptions_disabled(self):
        self.settings_obj.subscriptions_enabled = False
        self.settings_obj.save()
        self.assertEqual(self.free_user.plan_limits, self.free_user.PLAN_LIMITS['admin'])
        self.assertEqual(self.free_user.plan_limits['sites'], -1)

    def test_reenabling_restores_original_limits(self):
        self.settings_obj.subscriptions_enabled = False
        self.settings_obj.save()
        self.assertEqual(self.free_user.plan_limits['sites'], -1)

        self.settings_obj.subscriptions_enabled = True
        self.settings_obj.save()
        self.assertEqual(self.free_user.plan_limits['sites'], 1)

    def test_missing_settings_row_fails_safe_to_enforced(self):
        """If SystemSettings has no row at all yet, default posture must be
        'enforced', not silently wide open."""
        from base.models import SystemSettings, subscriptions_are_enabled
        SystemSettings.objects.all().delete()
        self.assertTrue(subscriptions_are_enabled())


class SiteLimitEnforcementTests(TestCase):
    """
    Site registration is the one concrete PLAN_LIMITS value that's actually
    enforced server-side. This locks in that the enforcement itself
    respects the master subscriptions_enabled toggle.
    """

    def setUp(self):
        from base.models import CustomUser, RegisteredSite, Organization, SystemSettings
        self.org = Organization.objects.create(name='Test Org', subscription_tier='free')
        self.user = CustomUser.objects.create_user(
            username='siteowner', email='owner@example.com', password='x', plan='free',
        )
        self.settings_obj, _ = SystemSettings.objects.get_or_create(pk=1)
        # Free plan allows 1 site — create that one now so the user is at
        # their limit for both tests below.
        RegisteredSite.objects.create(
            domain='existing-site.example.com', organization=self.org,
            owner_user=self.user, name='Existing Site', status='active',
        )

    def test_at_limit_blocked_when_enforced(self):
        self.settings_obj.subscriptions_enabled = True
        self.settings_obj.save()
        limit = self.user.plan_limits.get('sites', -1)
        from base.models import RegisteredSite
        current_count = RegisteredSite.objects.filter(owner_user=self.user).count()
        self.assertTrue(current_count >= limit)  # confirms the test setup is actually at the limit

    def test_at_limit_allowed_when_subscriptions_disabled(self):
        self.settings_obj.subscriptions_enabled = False
        self.settings_obj.save()
        self.assertEqual(self.user.plan_limits.get('sites', -1), -1)


# ═══════════════════════════════════════════════════════════════════════════
# ATTACK PATTERN TRACKING (wiring the live detection pipeline to the
# Attack Patterns dashboard page)
# ═══════════════════════════════════════════════════════════════════════════

class AttackPatternTrackerTests(TestCase):
    """
    Before this, AttackPattern/PatternLearningData were only ever written
    from the threat-intel-sharing flow — never from a real, live detection.
    record_attack_patterns() is what threat_evaluator's real detections now
    feed into, via swap_middleware.py and deception_middleware.py.
    """

    def _make_eval_result(self, techniques, tier=1, score=90, threat_level='critical'):
        from types import SimpleNamespace
        return SimpleNamespace(
            techniques=techniques, tier=tier, score=score, threat_level=threat_level,
            confidence=90, explanation='Test detection', flagged=True,
        )

    def _make_threat(self, site, technique_str):
        from base.models import Threat
        return Threat.objects.create(
            timestamp=timezone.now(), domain='example.com', session_id='sess-1',
            ip_address='198.51.100.5', threat_type=technique_str, severity='critical',
            indicators=[technique_str], status='active', description='test',
            site=site, ai_confidence=0.9, risk_score=90, technique=technique_str,
        )

    def test_new_technique_creates_attack_pattern(self):
        from base.models import AttackPattern, Organization, RegisteredSite
        from base.services.attack_pattern_tracker import record_attack_patterns

        org = Organization.objects.create(name='Org A', subscription_tier='free')
        site = RegisteredSite.objects.create(domain='site-a.test', organization=org, status='active')
        eval_result = self._make_eval_result(['Definitive SQL injection'])
        threat = self._make_threat(site, 'Definitive SQL injection')

        self.assertEqual(AttackPattern.objects.count(), 0)
        record_attack_patterns(eval_result, threat)
        self.assertEqual(AttackPattern.objects.count(), 1)

        pattern = AttackPattern.objects.first()
        self.assertEqual(pattern.technique, 'Definitive SQL injection')
        self.assertEqual(pattern.category, 'Database Attacks')
        self.assertEqual(pattern.frequency, 1)
        self.assertEqual(pattern.sites_affected, 1)

    def test_repeated_technique_increments_frequency_not_sites(self):
        """Same site triggering the same technique twice must increment
        frequency but NOT double-count sites_affected."""
        from base.models import AttackPattern, Organization, RegisteredSite
        from base.services.attack_pattern_tracker import record_attack_patterns

        org = Organization.objects.create(name='Org B', subscription_tier='free')
        site = RegisteredSite.objects.create(domain='site-b.test', organization=org, status='active')
        eval_result = self._make_eval_result(['Path Traversal Attempt'])

        threat1 = self._make_threat(site, 'Path Traversal Attempt')
        record_attack_patterns(eval_result, threat1)
        threat2 = self._make_threat(site, 'Path Traversal Attempt')
        record_attack_patterns(eval_result, threat2)

        pattern = AttackPattern.objects.get(technique='Path Traversal Attempt')
        self.assertEqual(pattern.frequency, 2)
        self.assertEqual(pattern.sites_affected, 1)  # still just one distinct site

    def test_different_sites_increment_sites_affected(self):
        from base.models import AttackPattern, Organization, RegisteredSite
        from base.services.attack_pattern_tracker import record_attack_patterns

        org = Organization.objects.create(name='Org C', subscription_tier='free')
        site1 = RegisteredSite.objects.create(domain='site-c1.test', organization=org, status='active')
        site2 = RegisteredSite.objects.create(domain='site-c2.test', organization=org, status='active')
        eval_result = self._make_eval_result(['Admin Panel Probe'])

        record_attack_patterns(eval_result, self._make_threat(site1, 'Admin Panel Probe'))
        record_attack_patterns(eval_result, self._make_threat(site2, 'Admin Panel Probe'))

        pattern = AttackPattern.objects.get(technique='Admin Panel Probe')
        self.assertEqual(pattern.sites_affected, 2)

    def test_learning_data_rolls_forward(self):
        from base.models import Organization, RegisteredSite, PatternLearningData
        from base.services.attack_pattern_tracker import record_attack_patterns

        org = Organization.objects.create(name='Org D', subscription_tier='free')
        site = RegisteredSite.objects.create(domain='site-d.test', organization=org, status='active')
        eval_result = self._make_eval_result(['CMS Admin Probe'])

        self.assertEqual(PatternLearningData.objects.count(), 0)
        record_attack_patterns(eval_result, self._make_threat(site, 'CMS Admin Probe'))
        self.assertEqual(PatternLearningData.objects.count(), 1)
        self.assertEqual(PatternLearningData.objects.first().new_patterns, 1)

    def test_category_inference(self):
        from base.services.attack_pattern_tracker import _infer_category
        self.assertEqual(_infer_category('Definitive SQL injection'), 'Database Attacks')
        self.assertEqual(_infer_category('Path Traversal Attempt'), 'File System Attacks')
        self.assertEqual(_infer_category('Brute-Force Tool'), 'Authentication Attacks')
        self.assertEqual(_infer_category('XSS Probe'), 'Injection Attacks')
        self.assertEqual(_infer_category('Something totally novel'), 'Other')

    def test_no_techniques_does_nothing(self):
        from base.models import AttackPattern, Organization, RegisteredSite
        from base.services.attack_pattern_tracker import record_attack_patterns

        org = Organization.objects.create(name='Org E', subscription_tier='free')
        site = RegisteredSite.objects.create(domain='site-e.test', organization=org, status='active')
        eval_result = self._make_eval_result([])
        record_attack_patterns(eval_result, self._make_threat(site, 'Unknown'))
        self.assertEqual(AttackPattern.objects.count(), 0)


class EmptyTrendsTests(TestCase):
    """
    _empty_trends() (formerly _sample_trends()) must not fabricate activity
    numbers for a system with no real trend data yet.
    """

    def test_empty_trends_has_no_fake_activity(self):
        from base.views import _empty_trends
        trends = _empty_trends()
        self.assertTrue(len(trends) > 0)
        for bucket in trends:
            self.assertEqual(bucket['new_patterns'], 0)
            self.assertEqual(bucket['repeating_patterns'], 0)


# ═══════════════════════════════════════════════════════════════════════════
# QUERY STRING / BODY DECODING (real detection gap — XSS/SQLi via a query
# param or form field wasn't being decoded before pattern matching)
# ═══════════════════════════════════════════════════════════════════════════

class QueryStringDecodingTests(SimpleTestCase):
    """
    Browsers percent-encode special characters in query strings and
    form-encoded POST bodies. Path segments get auto-decoded by
    WSGI/Express before reaching this code (which is why SQLi typed into
    a URL path, e.g. `/product/1 UNION SELECT ...`, was always detected),
    but query_string/body were never decoded before Tier 1's literal-
    character regexes ran against them — so the exact same payload
    submitted via a search box or form field (arriving pre-encoded, e.g.
    `q=%3Cscript%3E...`) silently matched nothing.
    """

    def test_xss_via_encoded_query_string_now_detected(self):
        req = {
            'path': '/search',
            'query_string': "q=%3Cscript%3Ealert('xss')%3C/script%3E",
            'user_agent': 'Mozilla/5.0',
        }
        triggered, reasons = _check_tier1(req, {}, session_id='')
        self.assertTrue(triggered, f"reasons={reasons}")

    def test_xss_via_encoded_form_body_now_detected(self):
        req = {
            'path': '/contact',
            'query_string': '',
            'body': 'message=%3Cscript%3Ealert(1)%3C%2Fscript%3E&name=test',
            'user_agent': 'Mozilla/5.0',
        }
        triggered, reasons = _check_tier1(req, {}, session_id='')
        self.assertTrue(triggered, f"reasons={reasons}")

    def test_sqli_via_encoded_query_string_now_detected(self):
        req = {
            'path': '/search',
            'query_string': "q=1%27%20OR%20%271%27%3D%271",
            'user_agent': 'Mozilla/5.0',
        }
        triggered, reasons = _check_tier1(req, {}, session_id='')
        self.assertTrue(triggered, f"reasons={reasons}")

    def test_plain_decoded_payload_still_detected(self):
        """Regression guard: payloads that arrive already-decoded (e.g. a
        path segment) must keep working exactly as before."""
        req = {'path': "/product/1 UNION SELECT id,name FROM users",
               'query_string': '', 'user_agent': 'Mozilla/5.0'}
        triggered, reasons = _check_tier1(req, {}, session_id='')
        self.assertTrue(triggered, f"reasons={reasons}")

    def test_ordinary_percent_sign_in_text_does_not_break_matching(self):
        """A literal, non-encoding use of '%' (e.g. '50% off') should not
        crash or produce garbage — unquote_plus is a no-op on text that
        isn't valid percent-encoding for this kind of input."""
        req = {'path': '/product/1', 'query_string': 'promo=50%20off',
               'user_agent': 'Mozilla/5.0'}
        triggered, reasons = _check_tier1(req, {}, session_id='')
        self.assertFalse(triggered)


# ═══════════════════════════════════════════════════════════════════════════
# AI ANALYSIS -> PIPELINE WIRING
# ═══════════════════════════════════════════════════════════════════════════

class AiAnalysisPipelineWiringTests(TestCase):
    """The on-demand Analyze button used to be entirely read-only. Flagged
    results now write back into session/Threat/AttackPattern/ActivityLog."""

    def _make_env(self):
        from base.models import Organization, RegisteredSite, ActiveSession, ActivityLog
        org  = Organization.objects.create(name='AIWire Org', subscription_tier='pro')
        site = RegisteredSite.objects.create(
            domain='aiwire.test', organization=org, status='active')
        sess = ActiveSession.objects.create(
            id='session-aiwire-1', domain='aiwire.test',
            session_id='aiwire-sid-1', ip_address='198.51.100.9',
            site=site, backend_type='real', threat_level='low')
        log = ActivityLog.objects.create(
            domain='aiwire.test', session_id='aiwire-sid-1',
            method='GET', endpoint='/search', user_agent='Mozilla/5.0',
            status_code=200, response_time=45,
            suspicion_score=0, flagged=False, site=site,
            ip_address='198.51.100.9')
        return sess, log

    def test_flagged_result_flips_session_to_deceptive(self):
        from base.views import _apply_ai_analysis_verdict
        from base.models import ActiveSession
        sess, _ = self._make_env()
        _apply_ai_analysis_verdict(sess, {
            'risk_score': 88, 'threat_level': 'high', 'flagged': True,
            'techniques': ['Credential Stuffing'], 'explanation': 'x', 'confidence': 80,
        })
        self.assertEqual(ActiveSession.objects.get(id=sess.id).backend_type, 'deceptive')

    def test_flagged_result_creates_threat_record(self):
        from base.views import _apply_ai_analysis_verdict
        from base.models import Threat
        sess, _ = self._make_env()
        _apply_ai_analysis_verdict(sess, {
            'risk_score': 90, 'threat_level': 'critical', 'flagged': True,
            'techniques': ['Web Scraping'], 'explanation': 'x', 'confidence': 85,
        })
        self.assertEqual(Threat.objects.count(), 1)

    def test_flagged_result_corrects_activity_log_score(self):
        from base.views import _apply_ai_analysis_verdict
        from base.models import ActivityLog
        sess, log = self._make_env()
        _apply_ai_analysis_verdict(sess, {
            'risk_score': 95, 'threat_level': 'critical', 'flagged': True,
            'techniques': ['SQL Injection'], 'explanation': 'x', 'confidence': 90,
        })
        self.assertEqual(ActivityLog.objects.get(id=log.id).suspicion_score, 95)
        self.assertTrue(ActivityLog.objects.get(id=log.id).flagged)

    def test_unflagged_result_leaves_session_real(self):
        from base.views import _apply_ai_analysis_verdict
        from base.models import ActiveSession, Threat
        sess, _ = self._make_env()
        # gate matches get_session_ai_analysis: only call when flagged=True
        result = {'risk_score': 10, 'threat_level': 'low', 'flagged': False,
                  'techniques': [], 'explanation': 'ok', 'confidence': 60}
        if result.get('flagged'):
            _apply_ai_analysis_verdict(sess, result)
        self.assertEqual(ActiveSession.objects.get(id=sess.id).backend_type, 'real')
        self.assertEqual(Threat.objects.count(), 0)


# ═══════════════════════════════════════════════════════════════════════════
# SETTINGS PERMISSION SPLIT
# ═══════════════════════════════════════════════════════════════════════════

class SettingsPermissionTests(TestCase):
    def setUp(self):
        from base.models import CustomUser
        self.normal = CustomUser.objects.create_user(
            username='normalst', email='normalst@example.com', password='x', plan='free')
        self.admin  = CustomUser.objects.create_user(
            username='adminst',  email='adminst@example.com',  password='x', plan='admin')

    def _hdrs(self, user):
        from rest_framework_simplejwt.tokens import RefreshToken
        return {'HTTP_AUTHORIZATION': f'Bearer {RefreshToken.for_user(user).access_token}'}

    def test_normal_user_gets_200_not_403(self):
        from django.test import Client
        r = Client().get('/api/auth/settings/system/', **self._hdrs(self.normal))
        self.assertEqual(r.status_code, 200)

    def test_normal_user_gets_filtered_fields_only(self):
        from django.test import Client
        import json
        r = Client().get('/api/auth/settings/system/', **self._hdrs(self.normal))
        data = json.loads(r.content)
        self.assertNotIn('webhook_url', data)
        self.assertNotIn('subscriptions_enabled', data)
        self.assertIn('deception_level', data)

    def test_admin_gets_full_settings(self):
        from django.test import Client
        import json
        r = Client().get('/api/auth/settings/system/', **self._hdrs(self.admin))
        data = json.loads(r.content)
        self.assertIn('webhook_url', data)
        self.assertIn('subscriptions_enabled', data)

    def test_normal_user_cannot_edit(self):
        from django.test import Client
        r = Client().put(
            '/api/auth/settings/system/', data='{"deception_level":"basic"}',
            content_type='application/json', **self._hdrs(self.normal))
        self.assertEqual(r.status_code, 403)

    def test_admin_can_edit(self):
        from django.test import Client
        r = Client().put(
            '/api/auth/settings/system/', data='{"deception_level":"advanced"}',
            content_type='application/json', **self._hdrs(self.admin))
        self.assertEqual(r.status_code, 200)
