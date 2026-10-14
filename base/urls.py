from django.urls import path
from . import views

urlpatterns = [
    # ── Auth ─────────────────────────────────────────────────────────────────
    path('auth/register/', views.register),
    path('auth/login/',    views.login),
    path('auth/me/',                 views.me),
    path('auth/me/update/',          views.update_me),
    path('auth/me/change-password/', views.change_password),
    path('auth/logout/',   views.logout),

    # ── Sites ─────────────────────────────────────────────────────────────────
    path('auth/sites/',                          views.sites),
    path('auth/sites/<str:site_id>/',            views.site_detail),
    path('auth/sites/<str:site_id>/metrics/',    views.update_site_metrics),
    path('auth/sites/<str:site_id>/snippet/',    views.get_installation_snippet),
    path('auth/sites/<str:site_id>/verify/',     views.verify_snippet_installation),

    # ── Activity logs (summary before detail) ────────────────────────────────
    path('auth/activity-logs/summary/',          views.activity_logs_summary),
    path('auth/activity-logs/',                  views.activity_logs),
    path('auth/activity-logs/<str:log_id>/',     views.activity_log_detail),

    # ── Threats (summary before detail) ──────────────────────────────────────
    path('auth/threats/summary/',                views.threats_summary),
    path('auth/threats/',                        views.threats),
    path('auth/threats/<str:threat_id>/',        views.threat_detail),
    path('auth/threats/<str:threat_id>/status/', views.update_threat_status),

    # ── Active sessions (summary before detail) ───────────────────────────────
    path('auth/active-sessions/summary/',                   views.active_sessions_summary),
    path('auth/active-sessions/',                           views.active_sessions),
    path('auth/active-sessions/<str:session_id>/',          views.active_session_detail),
    path('auth/active-sessions/<str:session_id>/interact/', views.update_session_interaction),

    # ── Attack patterns ───────────────────────────────────────────────────────
    path('auth/attack-patterns/summary/',          views.attack_patterns_summary),
    path('auth/attack-patterns/trends/',           views.pattern_learning_trends),
    path('auth/attack-patterns/update-learning/',  views.update_pattern_learning),
    path('auth/attack-patterns/',                  views.attack_patterns),
    path('auth/attack-patterns/<str:pattern_id>/', views.attack_pattern_detail),

    # ── Settings ──────────────────────────────────────────────────────────────
    path('auth/settings/system/',      views.system_settings),
    path('auth/settings/system/test-ai/', views.test_ai_connection),
    path('auth/settings/preferences/', views.user_preferences),
    path('auth/settings/reset/',       views.reset_settings),
    path('auth/settings/audit-log/',   views.settings_audit_log),

    # ── Threat intelligence ───────────────────────────────────────────────────
    path('auth/threat-intel/stats/',                views.threat_intelligence_stats),
    path('auth/threat-intel/feed/',                 views.threat_intelligence_feed),
    path('auth/threat-intel/',                      views.threat_intelligence),
    path('auth/threat-intel/<str:intel_id>/',       views.threat_intelligence_detail),
    path('auth/threat-intel/<str:intel_id>/share/', views.share_threat_intelligence),

    # ── Analytics ─────────────────────────────────────────────────────────────
    path('auth/analytics/trends/',                views.get_analytics_trends),
    path('auth/analytics/attack-locations/',      views.get_attack_locations),
    path('auth/analytics/skill-distribution/',    views.get_skill_distribution),
    path('auth/analytics/summary/',               views.get_analytics_summary),
    path('auth/analytics/historical/',            views.get_historical_snapshots),
    path('auth/analytics/attack-patterns-stats/', views.get_attack_patterns_stats),
    path('auth/analytics/update/',                views.update_analytics_data),
    path('auth/analytics/update-location/',       views.update_attack_location),
    path('auth/analytics/update-skills/',         views.update_skill_distribution),

    # ── Attacker profiles ─────────────────────────────────────────────────────
    path('auth/attackers/summary/',                           views.attackers_summary),
    path('auth/attackers/',                                   views.attackers),
    path('auth/attackers/<str:attacker_id>/',                 views.attacker_detail),
    path('auth/attackers/<str:attacker_id>/behavior-logs/',   views.attacker_behavior_logs),
    path('auth/attackers/<str:attacker_id>/add-behavior/',    views.add_behavior_log),
    path('auth/attackers/<str:attacker_id>/update-analysis/', views.update_attacker_behavior_analysis),

    # ── Deception environments ────────────────────────────────────────────────
    path('auth/environments/summary/',                  views.environments_summary),
    path('auth/environments/',                          views.deception_environments),
    path('auth/environments/<str:env_id>/',             views.deception_environment_detail),
    path('auth/environments/<str:env_id>/interact/',    views.record_interaction),
    path('auth/environments/<str:env_id>/interactions/', views.environment_interactions),
    path('auth/environments/<str:env_id>/update-ai/',   views.update_environment_ai),

    # ── PUBLIC TRACKING ENDPOINT ──────────────────────────────────────────────
    # Called by the JS snippet on monitored sites. No authentication required.
    # Snippet sends a POST with JSON; view logs activity and returns JSON.
    # URL in snippet is built as: request.build_absolute_uri('/api/track/public/')
    path('track/public/', views.track_request_public, name='track_public'),

    # Authenticated internal track endpoint (for your own middleware / server-side use)
    path('track/', views.track_request, name='track_request'),

    # ── Site profiling & AI session analysis ──────────────────────────────────
    path('auth/sites/<str:site_id>/profile/',         views.get_site_profile),
    path('auth/sites/<str:site_id>/profile/trigger/', views.trigger_site_profile),
    path('auth/active-sessions/<str:session_id>/approve-swap/', views.approve_session_swap),
    path('auth/active-sessions/<str:session_id>/revoke-swap/',  views.revoke_session_swap),
    path('auth/active-sessions/<str:session_id>/ai-analysis/',  views.get_session_ai_analysis),
    path('auth/active-sessions/<str:session_id>/shell-url/',    views.get_shell_url),

    # Adaptive Deception Loop
    path('auth/deception-targets/',                               views.deception_targets),
    path('auth/deception-targets/<int:target_id>/',               views.deception_target_detail),
    path('auth/deception-targets/<int:target_id>/run-remediation/', views.run_remediation),
    path('auth/deception-targets/<int:target_id>/blueprints/',    views.list_blueprints),
    path('auth/blueprints/<str:blueprint_id>/',                   views.blueprint_detail),

    # ── Payments ────────────────────────────────────────────────────────────────
    path('payments/mpesa/stk/',                 views.mpesa_stk_push,       name='mpesa_stk'),
    path('payments/mpesa/callback/',            views.mpesa_callback,       name='mpesa_callback'),
    path('payments/mpesa/status/<str:checkout_id>/', views.mpesa_payment_status, name='mpesa_status'),
    path('payments/paypal/create/',             views.paypal_create_order,  name='paypal_create'),
    path('payments/paypal/capture/',            views.paypal_capture_order, name='paypal_capture'),
    path('payments/subscription/',              views.get_subscription,     name='subscription'),

    # ── Admin dashboard API ────────────────────────────────────────────────────
    path('admin-api/overview/',        views.admin_overview),
    path('admin-api/users/',           views.admin_users_list),
    path('admin-api/users/<int:user_id>/', views.admin_update_user),
    path('admin-api/payments/',        views.admin_payments_list),
    path('admin-api/sites/',           views.admin_sites_list),
    path('admin-api/notifications/',   views.admin_notifications),
]
# NOTE: This line is appended — it registers the noscript beacon endpoint.
# The client-side JS snippet plants a <noscript> tag that loads this URL.
# When JS is disabled, the browser fetches it automatically, silently flagging
# the session at Tier 1 before a single line of attack code runs.
from django.urls import path
from . import views as _v
from . import views_code_scan as _cs
_extra = [
    # ── Tier 1-3 evaluation endpoints ────────────────────────────────────
    path('track/noscript/',                         _v.noscript_beacon,              name='noscript_beacon'),
    path('track/eval-status/<str:session_id>/',     _v.get_evaluation_status,        name='eval_status'),
    path('auth/sites/<str:site_id>/snippet/v5/',    _v.get_installation_snippet_v5,  name='snippet_v5'),
    path('auth/sites/<str:site_id>/sdk-config/',    _v.get_sdk_config,               name='sdk_config'),
    # ── Swap layer endpoints ──────────────────────────────────────────────
    path('swap/session-status/',                    _v.session_status,               name='swap_session_status'),
    path('swap/decoy-response/',                    _v.decoy_response,               name='swap_decoy_response'),
    path('swap/process/',                           _v.swap_process,                 name='swap_process'),
    path('swap/schema-ingest/',                     views.proxy_schema_ingest,       name='proxy_schema_ingest'),
    path('swap/ai-decoy/',                          views.proxy_ai_decoy,            name='proxy_ai_decoy'),
    path('proxy/<str:site_id>/',                    _v.proxy_root,                   name='proxy_root'),
    path('proxy/<str:site_id>/<path:fwd_path>',     _v.proxy_path,                   name='proxy_path'),
    # ── Automated Pentester (NEW) — static code scan of an uploaded zip ───
    path('pentester/scan/',                          _cs.CodeScanUploadView.as_view(), name='code_scan_upload'),
    path('pentester/scan/<int:scan_id>/',            _cs.CodeScanDetailView.as_view(), name='code_scan_detail'),
    path('pentester/scans/',                         _cs.CodeScanListView.as_view(),   name='code_scan_list'),
    # ── Remediation (NEW) — AI-proposed fix per finding, diff-reviewed, never auto-applied ──
    path('pentester/scan/<int:scan_id>/findings/<int:finding_index>/remediate/',
                                                      _cs.RemediationGenerateView.as_view(), name='remediation_generate'),
    path('pentester/remediation/<int:suggestion_id>/approve/', _cs.RemediationApproveView.as_view(), name='remediation_approve'),
    path('pentester/remediation/<int:suggestion_id>/reject/',  _cs.RemediationRejectView.as_view(),  name='remediation_reject'),
    path('pentester/scan/<int:scan_id>/remediations/',  _cs.RemediationListView.as_view(),    name='remediation_list'),
    path('pentester/scan/<int:scan_id>/download/',      _cs.CodeScanDownloadView.as_view(),   name='code_scan_download'),
]

urlpatterns += _extra
