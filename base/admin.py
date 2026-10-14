from django.contrib import admin
from django import forms
from django.utils.html import format_html
from django.urls import reverse
from django.db.models import Count, Q
from django.utils import timezone
from datetime import timedelta
from .models import *

# ============================================================================
# Custom Admin Actions
# ============================================================================

def mark_active(modeladmin, request, queryset):
    queryset.update(status='active')
mark_active.short_description = "Mark selected items as Active"

def mark_inactive(modeladmin, request, queryset):
    queryset.update(is_active=False)
mark_inactive.short_description = "Mark selected sessions as Inactive"

def resolve_threats(modeladmin, request, queryset):
    queryset.update(status='resolved')
resolve_threats.short_description = "Mark selected threats as Resolved"

def terminate_sessions(modeladmin, request, queryset):
    queryset.update(is_active=False)
terminate_sessions.short_description = "Terminate selected sessions"

# ============================================================================
# Custom Filters
# ============================================================================

class ActiveSessionFilter(admin.SimpleListFilter):
    title = 'Session Status'
    parameter_name = 'session_status'
    
    def lookups(self, request, model_admin):
        return [
            ('active', 'Active (last 30 min)'),
            ('stale', 'Stale (>30 min)'),
            ('all', 'All Sessions'),
        ]
    
    def queryset(self, request, queryset):
        cutoff = timezone.now() - timedelta(minutes=30)
        if self.value() == 'active':
            return queryset.filter(is_active=True, last_activity__gte=cutoff)
        if self.value() == 'stale':
            return queryset.filter(Q(is_active=True, last_activity__lt=cutoff) | Q(is_active=False))
        return queryset


class ThreatSeverityFilter(admin.SimpleListFilter):
    title = 'Threat Severity'
    parameter_name = 'severity'
    
    def lookups(self, request, model_admin):
        return [
            ('critical', '⚠️ Critical'),
            ('high', '🔴 High'),
            ('medium', '🟠 Medium'),
            ('low', '🟢 Low'),
        ]
    
    def queryset(self, request, queryset):
        if self.value():
            return queryset.filter(severity=self.value())
        return queryset

# ============================================================================
# Inline Admins
# ============================================================================

class ActivityLogInline(admin.TabularInline):
    model = ActivityLog
    fields = ['timestamp', 'method', 'endpoint', 'ip_address', 'suspicion_score', 'flagged']
    readonly_fields = ['timestamp', 'method', 'endpoint', 'ip_address', 'suspicion_score', 'flagged']
    extra = 0
    max_num = 10
    can_delete = False
    show_change_link = True
    classes = ['collapse']
    
    def has_add_permission(self, request, obj=None):
        return False


class ThreatInline(admin.TabularInline):
    model = Threat
    fields = ['timestamp', 'threat_type', 'severity', 'status', 'risk_score']
    readonly_fields = ['timestamp', 'threat_type', 'severity', 'status', 'risk_score']
    extra = 0
    max_num = 10
    can_delete = False
    show_change_link = True
    classes = ['collapse']
    
    def has_add_permission(self, request, obj=None):
        return False


class ActiveSessionInline(admin.TabularInline):
    model = ActiveSession
    fields = ['session_id', 'ip_address', 'threat_level', 'interaction_count', 'last_activity']
    readonly_fields = ['session_id', 'ip_address', 'threat_level', 'interaction_count', 'last_activity']
    extra = 0
    max_num = 5
    can_delete = False
    show_change_link = True
    classes = ['collapse']
    
    def has_add_permission(self, request, obj=None):
        return False

# ============================================================================
# Main Admin Classes with Jazzmin Configuration
# ============================================================================

@admin.register(CustomUser)
class CustomUserAdmin(admin.ModelAdmin):
    list_display = ['email', 'full_name', 'company_name', 'plan', 'is_admin_user', 'date_joined', 'last_login']
    list_filter = ['plan', 'is_active', 'is_staff', 'date_joined']
    search_fields = ['email', 'full_name', 'company_name', 'username']
    ordering = ['-date_joined']
    readonly_fields = ['last_login', 'date_joined']
    
    fieldsets = (
        ('Account Information', {
            'fields': ('email', 'username', 'password')
        }),
        ('Personal Details', {
            'fields': ('full_name', 'company_name')
        }),
        ('Subscription', {
            'fields': ('plan',),
            'classes': ('collapse',)
        }),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
            'classes': ('collapse',)
        }),
        ('Important Dates', {
            'fields': ('last_login', 'date_joined'),
            'classes': ('collapse',)
        }),
    )
    
    def is_admin_user(self, obj):
        return obj.is_admin_user
    is_admin_user.boolean = True
    is_admin_user.short_description = 'Admin'


@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ['name', 'subscription_tier', 'api_key_short', 'is_active', 'created_at']
    list_filter = ['subscription_tier', 'is_active', 'created_at']
    search_fields = ['name', 'api_key']
    readonly_fields = ['api_key', 'created_at', 'updated_at']
    
    def api_key_short(self, obj):
        return f"{obj.api_key[:16]}..." if obj.api_key else '-'
    api_key_short.short_description = 'API Key'


@admin.register(RegisteredSite)
class RegisteredSiteAdmin(admin.ModelAdmin):
    list_display = ['domain', 'organization', 'owner', 'status', 'region', 'site_type', 
                    'sessions_monitored', 'threats_detected', 'last_activity', 'status_badge']
    list_filter = ['status', 'region', 'site_type', 'sensitivity_level', 'created_at']
    search_fields = ['domain', 'owner', 'name', 'organization__name']
    readonly_fields = ['id', 'registered_date', 'created_at', 'updated_at', 'last_activity']
    actions = [mark_active, mark_inactive]
    inlines = [ActivityLogInline, ThreatInline, ActiveSessionInline]
    
    fieldsets = (
        ('Site Information', {
            'fields': ('id', 'domain', 'name', 'owner', 'organization')
        }),
        ('Security Settings', {
            'fields': ('status', 'region', 'site_type', 'sensitivity_level', 'auto_engage_deception'),
            'classes': ('wide',)
        }),
        ('AI Configuration', {
            'fields': ('ai_analysis_frequency',),
            'classes': ('collapse',)
        }),
        ('Metrics', {
            'fields': ('sessions_monitored', 'threats_detected', 'active_deceptions', 
                      'registered_date', 'last_activity'),
            'classes': ('collapse',)
        }),
    )
    
    def status_badge(self, obj):
        colors = {
            'active': 'success',
            'monitoring': 'warning',
            'paused': 'danger',
        }
        color = colors.get(obj.status, 'secondary')
        return format_html(f'<span class="badge badge-{color}">{obj.status}</span>')
    status_badge.short_description = 'Status'
    
    def get_queryset(self, request):
        return super().get_queryset(request).select_related('organization', 'owner_user')
    
    def save_model(self, request, obj, form, change):
        if not obj.owner_user:
            obj.owner_user = request.user
        super().save_model(request, obj, form, change)


@admin.register(ActivityLog)
class ActivityLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'domain', 'method', 'endpoint_short', 'ip_address', 
                    'suspicion_score_progress', 'flagged_badge', 'site_link']
    list_filter = ['method', 'status_code', 'flagged', 'timestamp', 'site__domain']
    search_fields = ['domain', 'ip_address', 'session_id', 'endpoint']
    readonly_fields = ['id', 'timestamp', 'created_at']
    date_hierarchy = 'timestamp'
    list_select_related = ['site']
    
    fieldsets = (
        ('Request Details', {
            'fields': ('timestamp', 'domain', 'method', 'endpoint', 'session_id')
        }),
        ('Client Information', {
            'fields': ('ip_address', 'user_agent')
        }),
        ('Response Details', {
            'fields': ('status_code', 'response_time')
        }),
        ('Security Analysis', {
            'fields': ('suspicion_score', 'flagged', 'site'),
            'classes': ('wide',)
        }),
    )
    
    def endpoint_short(self, obj):
        return obj.endpoint[:50] + '...' if len(obj.endpoint) > 50 else obj.endpoint
    endpoint_short.short_description = 'Endpoint'
    
    def suspicion_score_progress(self, obj):
        color = 'danger' if obj.suspicion_score > 65 else 'warning' if obj.suspicion_score > 30 else 'success'
        return format_html(
            '<div class="progress" style="min-width: 80px;">'
            '<div class="progress-bar bg-{}" role="progressbar" style="width: {}%;" '
            'aria-valuenow="{}" aria-valuemin="0" aria-valuemax="100">{}</div>'
            '</div>',
            color, obj.suspicion_score, obj.suspicion_score, obj.suspicion_score
        )
    suspicion_score_progress.short_description = 'Suspicion'
    
    def flagged_badge(self, obj):
        if obj.flagged:
            return format_html('<span class="badge badge-danger">⚠️ Flagged</span>')
        return format_html('<span class="badge badge-success">✓ Clean</span>')
    flagged_badge.short_description = 'Flagged'
    
    def site_link(self, obj):
        if obj.site:
            url = reverse('admin:core_registratedsite_change', args=[obj.site.id])
            return format_html('<a href="{}">{}</a>', url, obj.site.domain)
        return '-'
    site_link.short_description = 'Site'
    
    def has_add_permission(self, request):
        return True  # Tracking endpoint creates these


@admin.register(Threat)
class ThreatAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'domain', 'threat_type_short', 'severity_badge', 
                    'status_badge', 'risk_score', 'ai_confidence', 'site_link']
    list_filter = [ThreatSeverityFilter, 'status', 'timestamp', 'site__domain']
    search_fields = ['domain', 'ip_address', 'session_id', 'threat_type', 'technique']
    readonly_fields = ['id', 'timestamp', 'created_at', 'updated_at']
    actions = [resolve_threats]
    date_hierarchy = 'timestamp'
    list_select_related = ['site']
    
    fieldsets = (
        ('Threat Information', {
            'fields': ('timestamp', 'domain', 'threat_type', 'description', 'technique')
        }),
        ('Severity & Status', {
            'fields': ('severity', 'status', 'risk_score', 'ai_confidence')
        }),
        ('Technical Details', {
            'fields': ('session_id', 'ip_address', 'indicators'),
            'classes': ('collapse',)
        }),
        ('Relationships', {
            'fields': ('site', 'activity_log'),
            'classes': ('collapse',)
        }),
    )
    
    def threat_type_short(self, obj):
        return obj.threat_type[:40] + '...' if len(obj.threat_type) > 40 else obj.threat_type
    threat_type_short.short_description = 'Threat Type'
    
    def severity_badge(self, obj):
        colors = {
            'critical': 'danger',
            'high': 'danger',
            'medium': 'warning',
            'low': 'info',
        }
        icons = {
            'critical': '💀',
            'high': '🔴',
            'medium': '🟠',
            'low': '🟢',
        }
        color = colors.get(obj.severity, 'secondary')
        icon = icons.get(obj.severity, '')
        return format_html(f'<span class="badge badge-{color}">{icon} {obj.severity.upper()}</span>')
    severity_badge.short_description = 'Severity'
    
    def status_badge(self, obj):
        colors = {
            'active': 'danger',
            'contained': 'warning',
            'resolved': 'success',
        }
        color = colors.get(obj.status, 'secondary')
        return format_html(f'<span class="badge badge-{color}">{obj.status}</span>')
    status_badge.short_description = 'Status'
    
    def site_link(self, obj):
        if obj.site:
            url = reverse('admin:core_registratedsite_change', args=[obj.site.id])
            return format_html('<a href="{}">{}</a>', url, obj.site.domain)
        return '-'
    site_link.short_description = 'Site'


@admin.register(ActiveSession)
class ActiveSessionAdmin(admin.ModelAdmin):
    list_display = ['session_id_short', 'domain', 'ip_address', 'threat_level_badge', 
                    'backend_type_badge', 'interaction_count', 'duration', 'last_activity_ago']
    list_filter = ['backend_type', 'threat_level', 'engagement_status', 'is_active', 
                   ActiveSessionFilter, 'site__domain']
    search_fields = ['session_id', 'domain', 'ip_address']
    readonly_fields = ['id', 'session_id', 'start_time', 'created_at', 'updated_at']
    actions = [terminate_sessions]
    list_select_related = ['site', 'threat']
    
    fieldsets = (
        ('Session Information', {
            'fields': ('session_id', 'domain', 'ip_address', 'site')
        }),
        ('Security Status', {
            'fields': ('backend_type', 'threat_level', 'engagement_status', 'is_active')
        }),
        ('Activity Metrics', {
            'fields': ('interaction_count', 'detected_techniques', 'start_time', 'last_activity'),
            'classes': ('wide',)
        }),
        ('Threat Link', {
            'fields': ('threat',),
            'classes': ('collapse',)
        }),
    )
    
    def session_id_short(self, obj):
        return obj.session_id[:16] + '...' if len(obj.session_id) > 16 else obj.session_id
    session_id_short.short_description = 'Session ID'
    
    def threat_level_badge(self, obj):
        colors = {
            'critical': 'danger',
            'high': 'danger',
            'medium': 'warning',
            'low': 'success',
        }
        color = colors.get(obj.threat_level, 'secondary')
        return format_html(f'<span class="badge badge-{color}">{obj.threat_level.upper()}</span>')
    threat_level_badge.short_description = 'Threat Level'
    
    def backend_type_badge(self, obj):
        color = 'danger' if obj.backend_type == 'deceptive' else 'success'
        icon = '🎭' if obj.backend_type == 'deceptive' else '✓'
        return format_html(f'<span class="badge badge-{color}">{icon} {obj.backend_type}</span>')
    backend_type_badge.short_description = 'Backend'
    
    def duration(self, obj):
        delta = timezone.now() - obj.start_time
        hours = delta.seconds // 3600
        minutes = (delta.seconds % 3600) // 60
        if hours > 0:
            return f"{hours}h {minutes}m"
        return f"{minutes}m"
    duration.short_description = 'Duration'
    
    def last_activity_ago(self, obj):
        delta = timezone.now() - obj.last_activity
        minutes = delta.seconds // 60
        if minutes < 1:
            return "Just now"
        elif minutes < 60:
            return f"{minutes}m ago"
        else:
            return f"{minutes//60}h ago"
    last_activity_ago.short_description = 'Last Activity'


@admin.register(AttackPattern)
class AttackPatternAdmin(admin.ModelAdmin):
    list_display = ['technique', 'category', 'severity_badge', 'frequency', 'detection_count', 
                    'sites_affected', 'last_seen_ago']
    list_filter = ['category', 'severity', 'last_seen']
    search_fields = ['technique', 'description', 'mitre_id']
    readonly_fields = ['id', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Attack Pattern', {
            'fields': ('technique', 'category', 'severity', 'description')
        }),
        ('Metrics', {
            'fields': ('frequency', 'detection_count', 'sites_affected', 'last_seen')
        }),
        ('Detection Details', {
            'fields': ('indicators', 'mitre_id'),
            'classes': ('collapse',)
        }),
    )
    
    def severity_badge(self, obj):
        colors = {
            'critical': 'danger',
            'high': 'danger',
            'medium': 'warning',
            'low': 'info',
        }
        color = colors.get(obj.severity, 'secondary')
        return format_html(f'<span class="badge badge-{color}">{obj.severity.upper()}</span>')
    severity_badge.short_description = 'Severity'
    
    def last_seen_ago(self, obj):
        delta = timezone.now() - obj.last_seen
        days = delta.days
        if days == 0:
            return "Today"
        elif days == 1:
            return "Yesterday"
        return f"{days} days ago"
    last_seen_ago.short_description = 'Last Seen'


@admin.register(AttackerProfile)
class AttackerProfileAdmin(admin.ModelAdmin):
    list_display = ['fingerprint_short', 'country', 'ip_address', 'skill_level_badge', 
                    'status_badge', 'threat_score_progress', 'total_interactions', 'last_activity_ago']
    list_filter = ['skill_level', 'status', 'country', 'first_seen']
    search_fields = ['fingerprint', 'ip_address', 'country', 'isp']
    readonly_fields = ['id', 'fingerprint', 'first_seen', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Attacker Identity', {
            'fields': ('fingerprint', 'ip_address', 'country', 'city', 'isp')
        }),
        ('Behavioral Metrics', {
            'fields': ('skill_level', 'status', 'threat_score', 'deception_susceptibility')
        }),
        ('Activity Stats', {
            'fields': ('total_interactions', 'total_sessions', 'time_in_environment', 
                      'first_seen', 'last_activity'),
            'classes': ('wide',)
        }),
        ('AI Analysis', {
            'fields': ('behavior_summary', 'preferred_targets', 'techniques', 'tags'),
            'classes': ('collapse',)
        }),
    )
    
    def fingerprint_short(self, obj):
        return obj.fingerprint[:20] + '...' if len(obj.fingerprint) > 20 else obj.fingerprint
    fingerprint_short.short_description = 'Fingerprint'
    
    def skill_level_badge(self, obj):
        colors = {'expert': 'danger', 'advanced': 'warning', 'intermediate': 'info', 'novice': 'success'}
        color = colors.get(obj.skill_level, 'secondary')
        return format_html(f'<span class="badge badge-{color}">{obj.skill_level}</span>')
    skill_level_badge.short_description = 'Skill'
    
    def status_badge(self, obj):
        colors = {'active': 'danger', 'trapped': 'warning', 'idle': 'secondary', 'evaded': 'info'}
        color = colors.get(obj.status, 'secondary')
        return format_html(f'<span class="badge badge-{color}">{obj.status}</span>')
    status_badge.short_description = 'Status'
    
    def threat_score_progress(self, obj):
        color = 'danger' if obj.threat_score > 65 else 'warning' if obj.threat_score > 30 else 'success'
        return format_html(
            '<div class="progress" style="min-width: 80px;">'
            '<div class="progress-bar bg-{}" role="progressbar" style="width: {}%;"'
            'aria-valuenow="{}" aria-valuemin="0" aria-valuemax="100">{}</div>'
            '</div>',
            color, obj.threat_score, obj.threat_score, obj.threat_score
        )
    threat_score_progress.short_description = 'Threat Score'
    
    def last_activity_ago(self, obj):
        delta = timezone.now() - obj.last_activity
        minutes = delta.seconds // 60
        if minutes < 1:
            return "Just now"
        elif minutes < 60:
            return f"{minutes}m ago"
        else:
            return f"{minutes//60}h ago"
    last_activity_ago.short_description = 'Last Active'


@admin.register(DeceptionEnvironment)
class DeceptionEnvironmentAdmin(admin.ModelAdmin):
    list_display = ['name', 'type', 'status_badge', 'attacker_count', 'total_interactions', 
                    'ai_adaptation_level_progress', 'last_triggered_ago']
    list_filter = ['type', 'status', 'deception_level', 'created_at']
    search_fields = ['name', 'description', 'network_segment']
    readonly_fields = ['id', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Environment Details', {
            'fields': ('name', 'type', 'status', 'description', 'site')
        }),
        ('Deception Configuration', {
            'fields': ('deception_level', 'response_delay_ms', 'error_rate', 'fake_data_volume')
        }),
        ('Metrics', {
            'fields': ('attacker_count', 'total_interactions', 'ai_adaptation_level', 'honeypots')
        }),
        ('Security', {
            'fields': ('network_segment', 'allowed_techniques', 'blocked_techniques'),
            'classes': ('collapse',)
        }),
    )
    
    def status_badge(self, obj):
        colors = {
            'active': 'success',
            'under_attack': 'danger',
            'compromised': 'danger',
            'idle': 'secondary',
            'maintenance': 'warning',
        }
        color = colors.get(obj.status, 'secondary')
        return format_html(f'<span class="badge badge-{color}">{obj.status.replace("_", " ").title()}</span>')
    status_badge.short_description = 'Status'
    
    def ai_adaptation_level_progress(self, obj):
        color = 'success' if obj.ai_adaptation_level > 70 else 'warning' if obj.ai_adaptation_level > 30 else 'secondary'
        return format_html(
            '<div class="progress" style="min-width: 80px;">'
            '<div class="progress-bar bg-{}" role="progressbar" style="width: {}%;"'
            'aria-valuenow="{}" aria-valuemin="0" aria-valuemax="100">{}</div>'
            '</div>',
            color, obj.ai_adaptation_level, obj.ai_adaptation_level, obj.ai_adaptation_level
        )
    ai_adaptation_level_progress.short_description = 'AI Adaptation'
    
    def last_triggered_ago(self, obj):
        delta = timezone.now() - obj.last_triggered
        minutes = delta.seconds // 60
        if minutes < 1:
            return "Just now"
        elif minutes < 60:
            return f"{minutes}m ago"
        else:
            return f"{minutes//60}h ago"
    last_triggered_ago.short_description = 'Last Triggered'


@admin.register(SystemSettings)
class SystemSettingsAdmin(admin.ModelAdmin):
    list_display = ['subscriptions_enabled_badge', 'suspicion_threshold_progress', 'auto_engagement_enabled_badge',
                    'learning_mode_badge', 'deception_level', 'session_timeout',
                    'updated_by', 'updated_at']
    readonly_fields = ['id', 'created_at', 'updated_at', 'updated_by']
    
    fieldsets = (
        ('Subscription Enforcement', {
            'fields': ('subscriptions_enabled',),
            'description': 'ON: users are limited to their plan\'s allowance (sites, '
                            'sessions, logs, etc — see each plan under Users). '
                            'OFF: every limit is lifted for every user immediately — '
                            'the whole system runs free for everyone, regardless of '
                            'what plan they\'re on.',
        }),
        ('Threat Detection', {
            'fields': ('suspicion_threshold',)
        }),
        ('Engagement & Learning', {
            'fields': ('auto_engagement_enabled', 'learning_mode', 'deception_level')
        }),
        ('Session Management', {
            'fields': ('session_timeout', 'max_concurrent_sessions')
        }),
        ('Data & Logging', {
            'fields': ('data_logging_enabled', 'alert_notifications', 'retention_days', 'max_log_size_mb')
        }),
        ('Integrations', {
            'fields': ('email_alerts', 'webhook_url'),
            'classes': ('collapse',)
        }),
        ('AI Integration (Groq)', {
            'fields': ('groq_api_key',),
            'description': 'Optional. Powers the AI threat-analysis tier. '
                            'Leave blank to fall back to the GROQ_API_KEY environment variable.'
        }),
    )

    def formfield_for_dbfield(self, db_field, request, **kwargs):
        if db_field.name == 'groq_api_key':
            kwargs['widget'] = forms.PasswordInput(render_value=True)
        return super().formfield_for_dbfield(db_field, request, **kwargs)

    def subscriptions_enabled_badge(self, obj):
        color = 'success' if obj.subscriptions_enabled else 'warning'
        text = 'ENFORCED' if obj.subscriptions_enabled else 'FREE FOR ALL'
        return format_html(f'<span class="badge badge-{color}">{text}</span>')
    subscriptions_enabled_badge.short_description = 'Subscriptions'
    
    def suspicion_threshold_progress(self, obj):
        color = 'danger' if obj.suspicion_threshold > 65 else 'warning' if obj.suspicion_threshold > 30 else 'success'
        return format_html(
            '<div class="progress" style="min-width: 80px;">'
            '<div class="progress-bar bg-{}" role="progressbar" style="width: {}%;"'
            'aria-valuenow="{}" aria-valuemin="0" aria-valuemax="100">{}</div>'
            '</div>',
            color, obj.suspicion_threshold, obj.suspicion_threshold, obj.suspicion_threshold
        )
    suspicion_threshold_progress.short_description = 'Threshold'
    
    def auto_engagement_enabled_badge(self, obj):
        color = 'success' if obj.auto_engagement_enabled else 'danger'
        text = 'ON' if obj.auto_engagement_enabled else 'OFF'
        return format_html(f'<span class="badge badge-{color}">{text}</span>')
    auto_engagement_enabled_badge.short_description = 'Auto Engagement'
    
    def learning_mode_badge(self, obj):
        color = 'success' if obj.learning_mode else 'danger'
        text = 'ON' if obj.learning_mode else 'OFF'
        return format_html(f'<span class="badge badge-{color}">{text}</span>')
    learning_mode_badge.short_description = 'Learning Mode'
    
    def save_model(self, request, obj, form, change):
        obj.updated_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(ThreatIntelligence)
class ThreatIntelligenceAdmin(admin.ModelAdmin):
    list_display = ['description_short', 'risk_score_progress', 'source', 'status_badge', 
                    'technique', 'is_shared_badge', 'timestamp']
    list_filter = ['source', 'status', 'risk_score', 'is_shared', 'timestamp']
    search_fields = ['description', 'technique', 'tool_signature', 'mitre_attack_id']
    readonly_fields = ['id', 'timestamp', 'created_at', 'updated_at']
    date_hierarchy = 'timestamp'
    
    fieldsets = (
        ('Threat Intelligence', {
            'fields': ('description', 'technique', 'risk_score', 'status', 'source')
        }),
        ('Technical Details', {
            'fields': ('payload', 'tool_signature', 'mitre_attack_id', 'indicators'),
            'classes': ('collapse',)
        }),
        ('Relationships', {
            'fields': ('affected_site', 'threat', 'is_shared', 'shared_at'),
            'classes': ('collapse',)
        }),
    )
    
    def description_short(self, obj):
        return obj.description[:60] + '...' if len(obj.description) > 60 else obj.description
    description_short.short_description = 'Description'
    
    def risk_score_progress(self, obj):
        color = 'danger' if obj.risk_score > 70 else 'warning' if obj.risk_score > 40 else 'success'
        return format_html(
            '<div class="progress" style="min-width: 80px;">'
            '<div class="progress-bar bg-{}" role="progressbar" style="width: {}%;"'
            'aria-valuenow="{}" aria-valuemin="0" aria-valuemax="100">{}</div>'
            '</div>',
            color, obj.risk_score, obj.risk_score, obj.risk_score
        )
    risk_score_progress.short_description = 'Risk Score'
    
    def status_badge(self, obj):
        colors = {
            'new': 'info',
            'analyzed': 'success',
            'mitigated': 'success',
            'false_positive': 'secondary',
        }
        color = colors.get(obj.status, 'secondary')
        return format_html(f'<span class="badge badge-{color}">{obj.status.replace("_", " ").title()}</span>')
    status_badge.short_description = 'Status'
    
    def is_shared_badge(self, obj):
        if obj.is_shared:
            return format_html('<span class="badge badge-success">✓ Shared</span>')
        return format_html('<span class="badge badge-secondary">Not Shared</span>')
    is_shared_badge.short_description = 'Shared'


@admin.register(GlobalThreatIntel)
class GlobalThreatIntelAdmin(admin.ModelAdmin):
    list_display = ['threat_type', 'severity_badge', 'detection_count', 'confidence_score_progress', 
                    'mitre_technique_id', 'last_seen']
    list_filter = ['threat_type', 'severity', 'mitigation_status', 'first_seen']
    search_fields = ['threat_hash', 'threat_type', 'mitre_technique_id', 'mitre_tactic']
    readonly_fields = ['id', 'first_seen', 'last_seen']
    
    def severity_badge(self, obj):
        colors = {
            'critical': 'danger',
            'high': 'danger',
            'medium': 'warning',
            'low': 'info',
        }
        color = colors.get(obj.severity, 'secondary')
        return format_html(f'<span class="badge badge-{color}">{obj.severity.upper()}</span>')
    severity_badge.short_description = 'Severity'
    
    def confidence_score_progress(self, obj):
        color = 'success' if obj.confidence_score > 70 else 'warning' if obj.confidence_score > 40 else 'secondary'
        return format_html(
            '<div class="progress" style="min-width: 80px;">'
            '<div class="progress-bar bg-{}" role="progressbar" style="width: {}%;"'
            'aria-valuenow="{}" aria-valuemin="0" aria-valuemax="100">{}</div>'
            '</div>',
            color, obj.confidence_score, obj.confidence_score, f"{obj.confidence_score:.0f}%"
        )
    confidence_score_progress.short_description = 'Confidence'


@admin.register(SiteProfile)
class SiteProfileAdmin(admin.ModelAdmin):
    list_display = ['site_link', 'status_badge', 'site_type', 'pages_crawled', 'updated_at']
    list_filter = ['status', 'site_type', 'created_at']
    search_fields = ['site__domain', 'site_purpose']
    readonly_fields = ['id', 'created_at', 'updated_at']
    
    fieldsets = (
        ('Site Profile', {
            'fields': ('site', 'status', 'site_type', 'site_purpose')
        }),
        ('Behavioral Analysis', {
            'fields': ('expected_paths', 'normal_actions', 'suspicious_signals', 'sensitive_areas'),
            'classes': ('wide',)
        }),
        ('Crawl Information', {
            'fields': ('pages_crawled', 'crawl_error', 'raw_ai_response'),
            'classes': ('collapse',)
        }),
    )
    
    def site_link(self, obj):
        url = reverse('admin:core_registratedsite_change', args=[obj.site.id])
        return format_html('<a href="{}">{}</a>', url, obj.site.domain)
    site_link.short_description = 'Site'
    
    def status_badge(self, obj):
        colors = {
            'ready': 'success',
            'profiling': 'warning',
            'pending': 'secondary',
            'failed': 'danger',
        }
        color = colors.get(obj.status, 'secondary')
        return format_html(f'<span class="badge badge-{color}">{obj.status}</span>')
    status_badge.short_description = 'Status'


@admin.register(Payment)
class PaymentAdmin(admin.ModelAdmin):
    list_display = ['user_email', 'plan', 'provider', 'amount', 'currency', 'status_badge', 'created_at']
    list_filter = ['plan', 'provider', 'status', 'created_at']
    search_fields = ['user__email', 'checkout_id']
    readonly_fields = ['id', 'created_at', 'updated_at', 'checkout_id']
    
    def user_email(self, obj):
        return obj.user.email
    user_email.short_description = 'User'
    
    def status_badge(self, obj):
        colors = {
            'completed': 'success',
            'pending': 'warning',
            'failed': 'danger',
        }
        color = colors.get(obj.status, 'secondary')
        return format_html(f'<span class="badge badge-{color}">{obj.status}</span>')
    status_badge.short_description = 'Status'


# Register remaining models with simpler admin
@admin.register(PatternLearningData)
class PatternLearningDataAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'new_patterns', 'repeating_patterns', 'total_patterns']
    list_filter = ['timestamp']
    date_hierarchy = 'timestamp'


@admin.register(AnalyticsData)
class AnalyticsDataAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'metric_type', 'value', 'site']
    list_filter = ['metric_type', 'timestamp']
    date_hierarchy = 'timestamp'


@admin.register(AttackLocation)
class AttackLocationAdmin(admin.ModelAdmin):
    list_display = ['country', 'country_code', 'attacks', 'last_seen']
    list_filter = ['country']


@admin.register(AttackerSkillDistribution)
class AttackerSkillDistributionAdmin(admin.ModelAdmin):
    list_display = ['skill_level', 'percentage', 'total_count', 'updated_at']


@admin.register(AnalyticsSnapshot)
class AnalyticsSnapshotAdmin(admin.ModelAdmin):
    list_display = ['date', 'total_attacks', 'total_attackers_trapped', 'peak_active_environments']
    list_filter = ['date']
    date_hierarchy = 'date'


@admin.register(AttackerBehaviorLog)
class AttackerBehaviorLogAdmin(admin.ModelAdmin):
    list_display = ['attacker', 'behavior_type', 'technique', 'success', 'deception_triggered', 'timestamp']
    list_filter = ['behavior_type', 'success', 'deception_triggered', 'timestamp']
    search_fields = ['technique', 'endpoint']


@admin.register(AttackerThreatIntel)
class AttackerThreatIntelAdmin(admin.ModelAdmin):
    list_display = ['attacker', 'threat_intel', 'confidence', 'created_at']


@admin.register(DeceptionInteraction)
class DeceptionInteractionAdmin(admin.ModelAdmin):
    list_display = ['environment', 'request_method', 'request_path_short', 'response_status', 
                    'was_deceptive', 'triggered_alert', 'timestamp']
    list_filter = ['request_method', 'response_status', 'was_deceptive', 'triggered_alert']
    search_fields = ['request_path', 'technique_detected']
    
    def request_path_short(self, obj):
        return obj.request_path[:50] + '...' if len(obj.request_path) > 50 else obj.request_path
    request_path_short.short_description = 'Path'


@admin.register(EnvironmentMetrics)
class EnvironmentMetricsAdmin(admin.ModelAdmin):
    list_display = ['environment', 'timestamp', 'attacker_count', 'interactions_per_minute', 
                    'deception_effectiveness', 'resource_usage']
    list_filter = ['timestamp']
    date_hierarchy = 'timestamp'


@admin.register(SessionTracker)
class SessionTrackerAdmin(admin.ModelAdmin):
    list_display = ['session_id_short', 'domain', 'ip_address', 'suspicion_score', 
                    'is_flagged', 'backend_type', 'created_at']
    list_filter = ['request_method', 'is_flagged', 'backend_type', 'created_at']
    search_fields = ['domain', 'ip_address', 'session_id', 'request_path']
    readonly_fields = ['id', 'created_at']
    
    def session_id_short(self, obj):
        return obj.session_id[:16] + '...' if obj.session_id and len(obj.session_id) > 16 else obj.session_id
    session_id_short.short_description = 'Session ID'


@admin.register(GlobalSessionTracker)
class GlobalSessionTrackerAdmin(admin.ModelAdmin):
    list_display = ['session_id_short', 'organization', 'global_threat_score_progress', 
                    'total_interactions_global', 'flagged_by_ai_badge', 'last_seen_global']
    list_filter = ['flagged_by_ai', 'organization', 'last_seen_global']
    search_fields = ['session_id']
    
    def session_id_short(self, obj):
        return obj.session_id[:20] + '...' if len(obj.session_id) > 20 else obj.session_id
    session_id_short.short_description = 'Session ID'
    
    def global_threat_score_progress(self, obj):
        color = 'danger' if obj.global_threat_score > 65 else 'warning' if obj.global_threat_score > 30 else 'success'
        return format_html(
            '<div class="progress" style="min-width: 80px;">'
            '<div class="progress-bar bg-{}" role="progressbar" style="width: {}%;"'
            'aria-valuenow="{}" aria-valuemin="0" aria-valuemax="100">{}</div>'
            '</div>',
            color, obj.global_threat_score, obj.global_threat_score, f"{obj.global_threat_score:.0f}"
        )
    global_threat_score_progress.short_description = 'Threat Score'
    
    def flagged_by_ai_badge(self, obj):
        if obj.flagged_by_ai:
            return format_html('<span class="badge badge-danger">⚠️ Flagged</span>')
        return format_html('<span class="badge badge-success">✓ Clean</span>')
    flagged_by_ai_badge.short_description = 'Flagged'


@admin.register(UserPreferences)
class UserPreferencesAdmin(admin.ModelAdmin):
    list_display = ['user', 'theme', 'auto_refresh_interval', 'email_notifications', 'desktop_notifications']
    list_filter = ['theme', 'email_notifications', 'desktop_notifications', 'threat_alerts']


@admin.register(SettingsAuditLog)
class SettingsAuditLogAdmin(admin.ModelAdmin):
    list_display = ['user', 'action', 'setting_key', 'old_value_short', 'new_value_short', 'timestamp']
    list_filter = ['action', 'setting_key', 'timestamp']
    search_fields = ['user__email', 'setting_key', 'old_value', 'new_value']
    readonly_fields = ['id', 'timestamp']
    
    def old_value_short(self, obj):
        return obj.old_value[:50] + '...' if obj.old_value and len(obj.old_value) > 50 else obj.old_value
    old_value_short.short_description = 'Old Value'
    
    def new_value_short(self, obj):
        return obj.new_value[:50] + '...' if obj.new_value and len(obj.new_value) > 50 else obj.new_value
    new_value_short.short_description = 'New Value'


@admin.register(ThreatIntelligenceShare)
class ThreatIntelligenceShareAdmin(admin.ModelAdmin):
    list_display = ['threat_intel', 'shared_to', 'shared_by', 'shared_at']
    list_filter = ['shared_at']
    search_fields = ['shared_to', 'shared_by__email']


# ============================================================================
# Jazzmin Configuration (Optional - add to settings.py)
# ============================================================================
"""
# Add to your settings.py for Jazzmin customization:

JAZZMIN_SETTINGS = {
    "site_title": "Genius Mirage Admin",
    "site_header": "Genius Mirage",
    "site_brand": "Genius Mirage",
    "site_logo": None,
    "welcome_sign": "Welcome to Genius Mirage Security Platform",
    "copyright": "Genius Mirage",
    "search_model": ["core.RegisteredSite", "core.Threat", "core.AttackerProfile"],
    "order_with_respect_to": [
        "core",
        "core.CustomUser",
        "core.Organization",
        "core.RegisteredSite",
        "core.ActiveSession",
        "core.Threat",
        "core.ActivityLog",
    ],
    "icons": {
        "auth.User": "fas fa-user",
        "core.CustomUser": "fas fa-user-shield",
        "core.Organization": "fas fa-building",
        "core.RegisteredSite": "fas fa-globe",
        "core.ActivityLog": "fas fa-history",
        "core.Threat": "fas fa-exclamation-triangle",
        "core.ActiveSession": "fas fa-users",
        "core.AttackPattern": "fas fa-bug",
        "core.AttackerProfile": "fas fa-user-secret",
        "core.DeceptionEnvironment": "fas fa-robot",
        "core.ThreatIntelligence": "fas fa-brain",
    },
}
"""