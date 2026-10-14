from django.contrib.auth.models import AbstractUser
from django.db import models
from django.utils import timezone
import hashlib
import secrets
import time

# ===== CUSTOM USER MODEL =====
class CustomUser(AbstractUser):
    email        = models.EmailField(unique=True)
    company_name = models.CharField(max_length=255, blank=True)
    full_name    = models.CharField(max_length=255, blank=True)

    # Subscription tier — 'admin' users bypass all limits
    PLAN_CHOICES = [
        ('free',       'Free'),
        ('pro',        'Pro'),
        ('enterprise', 'Enterprise'),
        ('admin',      'Admin'),       # unlimited — bypasses all restrictions
    ]
    plan = models.CharField(max_length=20, choices=PLAN_CHOICES, default='free')

    # Plan limits (admin gets -1 = unlimited)
    PLAN_LIMITS = {
        'free':       {'sites': 1,  'sessions': 100,  'logs': 500},
        'pro':        {'sites': 10, 'sessions': 5000, 'logs': 50000},
        'enterprise': {'sites': 50, 'sessions': -1,   'logs': -1},
        'admin':      {'sites': -1, 'sessions': -1,   'logs': -1},
    }

    USERNAME_FIELD  = 'email'
    REQUIRED_FIELDS = ['username']

    @property
    def is_admin_user(self):
        return self.plan == 'admin' or self.is_superuser or self.is_staff

    @property
    def plan_limits(self):
        if not subscriptions_are_enabled():
            # Master switch is off — the whole system is free for everyone,
            # so nobody is limited regardless of what plan they're on.
            return self.PLAN_LIMITS['admin']
        return self.PLAN_LIMITS.get(self.plan, self.PLAN_LIMITS['free'])

    def __str__(self):
        return self.email

    class Meta:
        db_table = 'auth_user'


# ===== ORGANIZATION (Multi-tenant) =====
class Organization(models.Model):
    """Top-level organization for multi-tenant support"""
    name = models.CharField(max_length=200)
    subscription_tier = models.CharField(max_length=50, choices=[
        ('free', 'Free'),
        ('pro', 'Professional'),
        ('enterprise', 'Enterprise'),
        ('global', 'Global')
    ], default='free')
    api_key = models.CharField(max_length=255, unique=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    
    # Global settings
    ai_model_preference = models.CharField(max_length=100, default='llama-3.3-70b-versatile')
    max_sessions_per_site = models.IntegerField(default=1000)
    data_retention_days = models.IntegerField(default=90)
    
    def save(self, *args, **kwargs):
        if not self.api_key:
            # Cryptographically secure, unpredictable API key — NOT derived from
            # guessable inputs (name/timestamp). 256 bits of entropy, url-safe.
            self.api_key = f"gm_{secrets.token_urlsafe(32)}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.name} ({self.subscription_tier})"
    
    class Meta:
        indexes = [
            models.Index(fields=['api_key']),
            models.Index(fields=['subscription_tier']),
        ]


# ===== REGISTERED SITE =====
class RegisteredSite(models.Model):
    """Enhanced for global multi-site support"""
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('monitoring', 'Monitoring'),
        ('paused', 'Paused'),
    ]
    
    REGION_CHOICES = [
        ('US-EAST', 'US East'),
        ('US-WEST', 'US West'),
        ('EU-WEST', 'EU West'),
        ('AP-SOUTH', 'Asia Pacific'),
        ('AF-SOUTH', 'Africa South'),
        ('ME', 'Middle East'),
        ('SA', 'South America')
    ]
    
    SITE_TYPE_CHOICES = [
        ('banking', 'Banking'),
        ('ecommerce', 'E-Commerce'),
        ('healthcare', 'Healthcare'),
        ('government', 'Government'),
        ('technology', 'Technology'),
        ('custom', 'Custom')
    ]
    
    id = models.CharField(max_length=50, primary_key=True, editable=False)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='sites', null=True, blank=True)
    name = models.CharField(max_length=200, null=True, blank=True)
    domain = models.CharField(max_length=255)
    owner = models.CharField(max_length=255, blank=True)
    owner_user = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='sites', null=True, blank=True)
    
    region = models.CharField(max_length=50, choices=REGION_CHOICES, default='US-EAST')
    site_type = models.CharField(max_length=50, choices=SITE_TYPE_CHOICES, default='custom')
    
    sensitivity_level = models.IntegerField(default=65, help_text="0-100, lower = more aggressive detection")
    auto_engage_deception = models.BooleanField(default=True)
    ai_analysis_frequency = models.CharField(max_length=20, choices=[
        ('realtime', 'Real-time'),
        ('minute', 'Every Minute'),
        ('hour', 'Every Hour'),
        ('batch', 'Batch Processing')
    ], default='realtime')
    
    sessions_monitored = models.IntegerField(default=0)
    threats_detected = models.IntegerField(default=0)
    active_deceptions = models.IntegerField(default=0)
    registered_date = models.DateTimeField(default=timezone.now)
    last_activity = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='monitoring')
    
    def save(self, *args, **kwargs):
        if not self.id:
            self.id = f"site-{int(time.time() * 1000)}-{secrets.token_hex(3)}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return self.domain
    
    class Meta:
        unique_together = [['organization', 'domain']]
        ordering = ['-registered_date']
        indexes = [
            models.Index(fields=['organization', 'status']),
            models.Index(fields=['region', 'status']),
            models.Index(fields=['domain']),
        ]


# ===== ACTIVITY LOG =====
class ActivityLog(models.Model):
    METHOD_CHOICES = [
        ('GET', 'GET'),
        ('POST', 'POST'),
        ('PUT', 'PUT'),
        ('DELETE', 'DELETE'),
        ('PATCH', 'PATCH'),
    ]
    
    id = models.CharField(max_length=50, primary_key=True, editable=False)
    timestamp = models.DateTimeField(default=timezone.now)
    domain = models.CharField(max_length=255)
    session_id = models.CharField(max_length=100, db_index=True)
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField()
    endpoint = models.CharField(max_length=500)
    method = models.CharField(max_length=10, choices=METHOD_CHOICES)
    status_code = models.IntegerField()
    response_time = models.IntegerField(help_text="Response time in milliseconds")
    suspicion_score = models.IntegerField(default=0)
    flagged = models.BooleanField(default=False)
    site = models.ForeignKey(RegisteredSite, on_delete=models.CASCADE, related_name='activity_logs', null=True, blank=True)
    active_session = models.ForeignKey('ActiveSession', on_delete=models.SET_NULL, null=True, blank=True, related_name='activity_logs')
    # Three-tier evaluation fields
    noscript_triggered = models.BooleanField(default=False, help_text='True when no-JS beacon fired')
    eval_tier          = models.IntegerField(default=0, help_text='Which tier (1/2/3) produced the score')
    eval_reasons       = models.JSONField(default=list, help_text='Reason strings from evaluator')
    created_at = models.DateTimeField(auto_now_add=True)
    
    def save(self, *args, **kwargs):
        if not self.id:
            self.id = f"log-{int(time.time() * 1000)}-{secrets.token_hex(3)}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.method} {self.endpoint} - {self.status_code}"
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['domain']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['session_id']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['flagged']),
            models.Index(fields=['eval_tier']),
        ]


# ===== THREAT =====
class Threat(models.Model):
    SEVERITY_CHOICES = [
        ('critical', 'Critical'),
        ('high', 'High'),
        ('medium', 'Medium'),
        ('low', 'Low'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('contained', 'Contained'),
        ('resolved', 'Resolved'),
    ]
    
    id = models.CharField(max_length=50, primary_key=True, editable=False)
    timestamp = models.DateTimeField(default=timezone.now)
    domain = models.CharField(max_length=255)
    session_id = models.CharField(max_length=100, db_index=True)
    ip_address = models.GenericIPAddressField()
    threat_type = models.CharField(max_length=255)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES)
    indicators = models.JSONField(default=list)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    description = models.TextField()
    site = models.ForeignKey(RegisteredSite, on_delete=models.CASCADE, related_name='threats', null=True, blank=True)
    activity_log = models.ForeignKey(ActivityLog, on_delete=models.SET_NULL, null=True, blank=True, related_name='threats')
    ai_confidence = models.FloatField(default=0)
    risk_score = models.IntegerField(default=0)
    technique = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        if not self.id:
            self.id = f"threat-{int(time.time() * 1000)}-{secrets.token_hex(3)}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.threat_type} - {self.severity}"
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['domain']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['session_id']),
            models.Index(fields=['severity']),
            models.Index(fields=['status']),
            models.Index(fields=['timestamp']),
        ]


# ===== ACTIVE SESSION =====
class ActiveSession(models.Model):
    BACKEND_TYPE_CHOICES = [
        ('real', 'Real'),
        ('deceptive', 'Deceptive'),
    ]
    
    THREAT_LEVEL_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    ENGAGEMENT_STATUS_CHOICES = [
        ('learning', 'Learning'),
        ('deceiving', 'Deceiving'),
        ('analyzing', 'Analyzing'),
    ]
    
    id = models.CharField(max_length=50, primary_key=True, editable=False)
    domain = models.CharField(max_length=255)
    session_id = models.CharField(max_length=100, unique=True, db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    start_time = models.DateTimeField(default=timezone.now)
    last_activity = models.DateTimeField(default=timezone.now, db_index=True)  # manual update — NOT auto_now
    backend_type = models.CharField(max_length=20, choices=BACKEND_TYPE_CHOICES, default='real')
    threat_level = models.CharField(max_length=20, choices=THREAT_LEVEL_CHOICES, default='low')
    interaction_count = models.IntegerField(default=0)
    engagement_status = models.CharField(max_length=20, choices=ENGAGEMENT_STATUS_CHOICES, default='analyzing')
    detected_techniques = models.JSONField(default=list)
    site = models.ForeignKey(RegisteredSite, on_delete=models.CASCADE, related_name='active_sessions', null=True, blank=True)
    threat = models.OneToOneField(Threat, on_delete=models.SET_NULL, null=True, blank=True, related_name='active_session')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)
    swap_approved = models.BooleanField(
        default=False,
        help_text="Operator-approved swap to deceptive backend. When False, "
                  "the session is flagged/detected but still served real responses "
                  "until a dashboard user reviews the AI analysis and approves the swap.",
    )

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = f"session-{int(time.time() * 1000)}-{secrets.token_hex(3)}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.session_id} - {self.backend_type}"
    
    class Meta:
        ordering = ['-last_activity']
        indexes = [
            models.Index(fields=['session_id']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['backend_type']),
            models.Index(fields=['threat_level']),
            models.Index(fields=['engagement_status']),
            models.Index(fields=['is_active']),
            models.Index(fields=['last_activity']),
        ]


# ===== ATTACK PATTERN =====
class AttackPattern(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    CATEGORY_CHOICES = [
        ('Database Attacks', 'Database Attacks'),
        ('Authentication Attacks', 'Authentication Attacks'),
        ('File System Attacks', 'File System Attacks'),
        ('Injection Attacks', 'Injection Attacks'),
        ('API Attacks', 'API Attacks'),
        ('Network Attacks', 'Network Attacks'),
        ('Social Engineering', 'Social Engineering'),
        ('Malware', 'Malware'),
        ('Other', 'Other'),
    ]
    
    id = models.CharField(max_length=50, primary_key=True, editable=False)
    technique = models.CharField(max_length=255, unique=True)
    category = models.CharField(max_length=100, choices=CATEGORY_CHOICES)
    frequency = models.IntegerField(default=0)
    last_seen = models.DateTimeField(default=timezone.now)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    description = models.TextField()
    indicators = models.JSONField(default=list)
    mitre_id = models.CharField(max_length=50, blank=True, null=True)
    detection_count = models.IntegerField(default=0)
    sites_affected = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        if not self.id:
            self.id = f"pattern-{int(time.time() * 1000)}-{secrets.token_hex(3)}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.technique} - {self.severity}"
    
    class Meta:
        ordering = ['-frequency', '-last_seen']
        indexes = [
            models.Index(fields=['technique']),
            models.Index(fields=['category']),
            models.Index(fields=['severity']),
            models.Index(fields=['last_seen']),
            models.Index(fields=['frequency']),
        ]


# ===== PATTERN LEARNING DATA =====
class PatternLearningData(models.Model):
    timestamp = models.DateTimeField(default=timezone.now)
    new_patterns = models.IntegerField(default=0)
    repeating_patterns = models.IntegerField(default=0)
    total_patterns = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
        ]
    
    def __str__(self):
        return f"{self.timestamp.strftime('%Y-%m-%d %H:%M')} - New: {self.new_patterns}"


# ===== SYSTEM SETTINGS =====
class SystemSettings(models.Model):
    DECEPTION_LEVEL_CHOICES = [
        ('basic', 'Basic - Simple responses'),
        ('intermediate', 'Intermediate - Realistic data'),
        ('advanced', 'Advanced - Full environment simulation'),
    ]

    # Master switch for the whole subscription/plan-limit system. When True
    # (default), each user's `plan` and `PLAN_LIMITS` are enforced normally.
    # When False, every feature and limit is unlocked for every user
    # regardless of their plan — see CustomUser.plan_limits /
    # subscriptions_enabled() in this module for how this gets consumed.
    subscriptions_enabled = models.BooleanField(
        default=True,
        help_text="ON: users are restricted to their plan's limits (sites, "
                  "sessions, logs, etc). OFF: every feature is unlocked for "
                  "everyone, regardless of plan — the whole system runs free.",
    )

    suspicion_threshold = models.IntegerField(default=65)
    auto_engagement_enabled = models.BooleanField(default=True)
    learning_mode = models.BooleanField(default=True)
    deception_level = models.CharField(max_length=20, choices=DECEPTION_LEVEL_CHOICES, default='advanced')
    session_timeout = models.IntegerField(default=30)
    max_concurrent_sessions = models.IntegerField(default=100)
    data_logging_enabled = models.BooleanField(default=True)
    alert_notifications = models.BooleanField(default=True)
    retention_days = models.IntegerField(default=30)
    max_log_size_mb = models.IntegerField(default=100)
    email_alerts = models.BooleanField(default=False)
    webhook_url = models.URLField(blank=True, null=True)
    groq_api_key = models.CharField(
        max_length=200, blank=True, default='',
        help_text="Optional. Powers the AI threat-analysis tier. If left blank, "
                  "the GROQ_API_KEY environment variable is used instead."
    )
    # ── AI provider/model selection (NEW) ───────────────────────────────────
    AI_PROVIDER_CHOICES = [
        ('groq', 'Groq'),
        ('openai', 'OpenAI'),
    ]
    ai_provider = models.CharField(
        max_length=20, choices=AI_PROVIDER_CHOICES, default='groq',
        help_text="Which provider powers the AI threat-analysis tier (Tier 3)."
    )
    ai_model = models.CharField(
        max_length=100, blank=True, default='llama-3.3-70b-versatile',
        help_text="Model name for the selected provider, e.g. 'llama-3.3-70b-versatile' for Groq "
                  "or 'gpt-4o-mini' for OpenAI. Leave blank to use the provider's built-in default."
    )
    openai_api_key = models.CharField(
        max_length=200, blank=True, default='',
        help_text="Required only when ai_provider is 'openai'. Falls back to the OPENAI_API_KEY "
                  "environment variable if left blank."
    )
    updated_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name_plural = "System Settings"
    
    def __str__(self):
        return f"System Settings (Updated: {self.updated_at.strftime('%Y-%m-%d %H:%M')})"


def subscriptions_are_enabled() -> bool:
    """
    Single source of truth for whether the subscription/plan-limit system
    is currently enforced. Controlled from the admin panel (System Settings
    -> Subscription Enforcement). Used by CustomUser.plan_limits and
    available for any other feature check that should respect the same
    master switch.

    Fails safe: if SystemSettings can't be read for any reason, defaults to
    True (enforced) rather than silently unlocking every feature.
    """
    try:
        settings_obj = SystemSettings.objects.filter(pk=1).first()
        if settings_obj is None:
            return True  # no row yet == field default == enforced
        return settings_obj.subscriptions_enabled
    except Exception:
        return True


# ===== USER PREFERENCES =====
class UserPreferences(models.Model):
    user = models.OneToOneField(CustomUser, on_delete=models.CASCADE, related_name='preferences')
    email_notifications = models.BooleanField(default=True)
    desktop_notifications = models.BooleanField(default=True)
    threat_alerts = models.BooleanField(default=True)
    default_dashboard_view = models.CharField(max_length=50, default='overview')
    auto_refresh_interval = models.IntegerField(default=30)
    theme = models.CharField(max_length=20, default='dark')
    compact_view = models.BooleanField(default=False)
    updated_at = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    def __str__(self):
        return f"Preferences for {self.user.email}"


# ===== SETTINGS AUDIT LOG =====
class SettingsAuditLog(models.Model):
    ACTION_CHOICES = [
        ('create', 'Create'),
        ('update', 'Update'),
        ('delete', 'Delete'),
        ('reset', 'Reset to Defaults'),
    ]
    
    user = models.ForeignKey(CustomUser, on_delete=models.CASCADE)
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    setting_key = models.CharField(max_length=100)
    old_value = models.TextField(blank=True, null=True)
    new_value = models.TextField(blank=True, null=True)
    ip_address = models.GenericIPAddressField()
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.user.email} - {self.action} - {self.setting_key} at {self.timestamp}"


# ===== THREAT INTELLIGENCE =====
class ThreatIntelligence(models.Model):
    STATUS_CHOICES = [
        ('new', 'New'),
        ('analyzed', 'Analyzed'),
        ('mitigated', 'Mitigated'),
        ('false_positive', 'False Positive'),
    ]
    
    SOURCE_CHOICES = [
        ('internal_scan', 'Internal Scan'),
        ('honeypot', 'Honeypot'),
        ('deceptive_backend', 'Deceptive Backend'),
        ('threat_intel_feed', 'Threat Intel Feed'),
        ('community_sharing', 'Community Sharing'),
    ]
    
    id = models.CharField(max_length=50, primary_key=True, editable=False)
    timestamp = models.DateTimeField(default=timezone.now)
    description = models.TextField()
    risk_score = models.IntegerField(default=0)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='new')
    source = models.CharField(max_length=50, choices=SOURCE_CHOICES)
    payload = models.TextField(blank=True, null=True)
    tool_signature = models.CharField(max_length=255, blank=True, null=True)
    technique = models.CharField(max_length=255, blank=True, null=True)
    mitre_attack_id = models.CharField(max_length=50, blank=True, null=True)
    indicators = models.JSONField(default=list)
    affected_site = models.ForeignKey(RegisteredSite, on_delete=models.SET_NULL, null=True, blank=True, related_name='threat_intel')
    threat = models.ForeignKey(Threat, on_delete=models.SET_NULL, null=True, blank=True, related_name='intel')
    is_shared = models.BooleanField(default=False)
    shared_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        if not self.id:
            self.id = f"tif-{int(time.time() * 1000)}-{secrets.token_hex(3)}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.description[:50]} - {self.risk_score}%"
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp']),
            models.Index(fields=['risk_score']),
            models.Index(fields=['status']),
            models.Index(fields=['source']),
            models.Index(fields=['technique']),
        ]


# ===== THREAT INTELLIGENCE SHARE =====
class ThreatIntelligenceShare(models.Model):
    threat_intel = models.ForeignKey(ThreatIntelligence, on_delete=models.CASCADE, related_name='shares')
    shared_to = models.CharField(max_length=255)
    shared_at = models.DateTimeField(auto_now_add=True)
    shared_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True)
    
    def __str__(self):
        return f"Shared {self.threat_intel.id} to {self.shared_to}"


# ===== ANALYTICS DATA =====
class AnalyticsData(models.Model):
    METRIC_TYPES = [
        ('attacks_detected', 'Attacks Detected'),
        ('attackers_trapped', 'Attackers Trapped'),
        ('environments_active', 'Environments Active'),
        ('avg_response_time', 'Average Response Time'),
        ('avg_deception_time', 'Average Deception Time'),
    ]
    
    timestamp = models.DateTimeField(default=timezone.now, db_index=True)
    metric_type = models.CharField(max_length=50, choices=METRIC_TYPES)
    value = models.FloatField(default=0)
    site = models.ForeignKey(RegisteredSite, on_delete=models.CASCADE, related_name='analytics', null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['timestamp', 'metric_type']),
            models.Index(fields=['site', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.metric_type}: {self.value} at {self.timestamp}"


# ===== ATTACK LOCATION =====
class AttackLocation(models.Model):
    country = models.CharField(max_length=100)
    country_code = models.CharField(max_length=2)
    attacks = models.IntegerField(default=0)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    last_seen = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-attacks']
        unique_together = ['country', 'country_code']
    
    def __str__(self):
        return f"{self.country}: {self.attacks} attacks"


# ===== ATTACKER SKILL DISTRIBUTION =====
class AttackerSkillDistribution(models.Model):
    SKILL_LEVELS = [
        ('novice', 'Novice'),
        ('intermediate', 'Intermediate'),
        ('advanced', 'Advanced'),
        ('expert', 'Expert'),
    ]
    
    skill_level = models.CharField(max_length=20, choices=SKILL_LEVELS)
    percentage = models.FloatField(default=0)
    total_count = models.IntegerField(default=0)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-percentage']
    
    def __str__(self):
        return f"{self.skill_level}: {self.percentage}%"


# ===== ANALYTICS SNAPSHOT =====
class AnalyticsSnapshot(models.Model):
    date = models.DateField(unique=True, db_index=True)
    total_attacks = models.IntegerField(default=0)
    total_attackers_trapped = models.IntegerField(default=0)
    avg_response_time = models.FloatField(default=0)
    avg_deception_time = models.FloatField(default=0)
    peak_active_environments = models.IntegerField(default=0)
    unique_attackers = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-date']
    
    def __str__(self):
        return f"Snapshot for {self.date}: {self.total_attacks} attacks"


# ===== ATTACKER PROFILE =====
class AttackerProfile(models.Model):
    SKILL_LEVEL_CHOICES = [
        ('novice', 'Novice'),
        ('intermediate', 'Intermediate'),
        ('advanced', 'Advanced'),
        ('expert', 'Expert'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('idle', 'Idle'),
        ('trapped', 'Trapped'),
        ('evaded', 'Evaded'),
    ]
    
    id = models.CharField(max_length=50, primary_key=True, editable=False)
    fingerprint = models.CharField(max_length=255, unique=True, db_index=True)
    country = models.CharField(max_length=100)
    country_code = models.CharField(max_length=2, blank=True)
    city = models.CharField(max_length=100, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    asn = models.CharField(max_length=100, blank=True)
    isp = models.CharField(max_length=255, blank=True)
    
    skill_level = models.CharField(max_length=20, choices=SKILL_LEVEL_CHOICES, default='novice')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    time_in_environment = models.IntegerField(default=0)
    total_interactions = models.IntegerField(default=0)
    avg_response_time = models.FloatField(default=0)
    techniques = models.JSONField(default=list)
    
    current_session = models.ForeignKey(ActiveSession, on_delete=models.SET_NULL, null=True, blank=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_activity = models.DateTimeField(auto_now=True)
    total_sessions = models.IntegerField(default=0)
    
    behavior_summary = models.TextField(blank=True)
    threat_score = models.IntegerField(default=0)
    deception_susceptibility = models.FloatField(default=0)
    preferred_targets = models.JSONField(default=list)
    
    notes = models.TextField(blank=True)
    tags = models.JSONField(default=list)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        if not self.id:
            self.id = f"att-{int(time.time() * 1000)}-{secrets.token_hex(3)}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.id} - {self.country} ({self.skill_level})"
    
    class Meta:
        ordering = ['-threat_score', '-last_activity']
        indexes = [
            models.Index(fields=['fingerprint']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['country']),
            models.Index(fields=['skill_level']),
            models.Index(fields=['status']),
            models.Index(fields=['threat_score']),
            models.Index(fields=['last_activity']),
        ]


# ===== ATTACKER BEHAVIOR LOG =====
class AttackerBehaviorLog(models.Model):
    BEHAVIOR_TYPES = [
        ('probe', 'Probe'),
        ('attack', 'Attack'),
        ('lateral_movement', 'Lateral Movement'),
        ('data_exfiltration', 'Data Exfiltration'),
        ('privilege_escalation', 'Privilege Escalation'),
        ('persistence', 'Persistence'),
        ('evasion', 'Evasion'),
    ]
    
    attacker = models.ForeignKey(AttackerProfile, on_delete=models.CASCADE, related_name='behavior_logs')
    behavior_type = models.CharField(max_length=50, choices=BEHAVIOR_TYPES)
    description = models.TextField()
    technique = models.CharField(max_length=255, blank=True)
    endpoint = models.CharField(max_length=500)
    payload = models.TextField(blank=True)
    response_time = models.IntegerField(default=0)
    success = models.BooleanField(default=False)
    deception_triggered = models.BooleanField(default=False)
    timestamp = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['attacker', 'timestamp']),
            models.Index(fields=['behavior_type']),
            models.Index(fields=['technique']),
        ]
    
    def __str__(self):
        return f"{self.attacker.id} - {self.behavior_type} at {self.timestamp}"


# ===== ATTACKER THREAT INTEL =====
class AttackerThreatIntel(models.Model):
    attacker = models.ForeignKey(AttackerProfile, on_delete=models.CASCADE, related_name='threat_intel')
    threat_intel = models.ForeignKey(ThreatIntelligence, on_delete=models.CASCADE, related_name='attackers')
    confidence = models.FloatField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        unique_together = ['attacker', 'threat_intel']
    
    def __str__(self):
        return f"{self.attacker.id} -> {self.threat_intel.id} ({self.confidence}%)"


# ===== DECEPTION ENVIRONMENT =====
class DeceptionEnvironment(models.Model):
    TYPE_CHOICES = [
        ('admin_panel', 'Admin Panel'),
        ('database', 'Database'),
        ('api', 'API Server'),
        ('file_server', 'File Server'),
        ('email_server', 'Email Server'),
        ('iot_device', 'IoT Device'),
        ('cloud_console', 'Cloud Console'),
        ('crm_system', 'CRM System'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('under_attack', 'Under Attack'),
        ('compromised', 'Compromised'),
        ('idle', 'Idle'),
        ('maintenance', 'Maintenance'),
    ]
    
    id = models.CharField(max_length=50, primary_key=True, editable=False)
    name = models.CharField(max_length=255)
    type = models.CharField(max_length=50, choices=TYPE_CHOICES)
    status = models.CharField(max_length=50, choices=STATUS_CHOICES, default='idle')
    description = models.TextField()
    
    attacker_count = models.IntegerField(default=0)
    total_interactions = models.IntegerField(default=0)
    ai_adaptation_level = models.IntegerField(default=0)
    honeypots = models.IntegerField(default=1)
    
    deception_level = models.CharField(max_length=50, choices=SystemSettings.DECEPTION_LEVEL_CHOICES, default='intermediate')
    response_delay_ms = models.IntegerField(default=100)
    error_rate = models.FloatField(default=0.05)
    
    fake_data_volume = models.CharField(max_length=20, choices=[
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
    ], default='medium')
    
    behavioral_patterns = models.JSONField(default=dict)
    allowed_techniques = models.JSONField(default=list)
    blocked_techniques = models.JSONField(default=list)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_triggered = models.DateTimeField(default=timezone.now)
    
    site = models.ForeignKey(RegisteredSite, on_delete=models.CASCADE, related_name='environments', null=True, blank=True)
    active_session = models.ForeignKey(ActiveSession, on_delete=models.SET_NULL, null=True, blank=True, related_name='environment')
    
    network_segment = models.CharField(max_length=100, blank=True)
    access_controls = models.JSONField(default=dict)
    
    def save(self, *args, **kwargs):
        if not self.id:
            self.id = f"env-{int(time.time() * 1000)}-{secrets.token_hex(3)}"
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.name} ({self.get_type_display()}) - {self.status}"
    
    class Meta:
        ordering = ['-last_triggered']
        indexes = [
            models.Index(fields=['name']),
            models.Index(fields=['type']),
            models.Index(fields=['status']),
            models.Index(fields=['last_triggered']),
            models.Index(fields=['site']),
        ]


# ===== DECEPTION INTERACTION =====
class DeceptionInteraction(models.Model):
    environment = models.ForeignKey(DeceptionEnvironment, on_delete=models.CASCADE, related_name='interactions')
    attacker = models.ForeignKey(AttackerProfile, on_delete=models.CASCADE, related_name='deception_interactions')
    request_path = models.CharField(max_length=500)
    request_method = models.CharField(max_length=10)
    request_headers = models.JSONField(default=dict)
    request_body = models.TextField(blank=True)
    response_status = models.IntegerField(default=200)
    response_body = models.TextField(blank=True)
    response_time_ms = models.IntegerField(default=0)
    was_deceptive = models.BooleanField(default=True)
    triggered_alert = models.BooleanField(default=False)
    technique_detected = models.CharField(max_length=255, blank=True)
    timestamp = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['environment', 'timestamp']),
            models.Index(fields=['attacker', 'timestamp']),
            models.Index(fields=['was_deceptive']),
        ]
    
    def __str__(self):
        return f"{self.environment.name} - {self.request_method} {self.request_path} - {self.timestamp}"


# ===== ENVIRONMENT METRICS =====
class EnvironmentMetrics(models.Model):
    environment = models.ForeignKey(DeceptionEnvironment, on_delete=models.CASCADE, related_name='metrics')
    timestamp = models.DateTimeField(default=timezone.now)
    attacker_count = models.IntegerField(default=0)
    interactions_per_minute = models.FloatField(default=0)
    avg_response_time_ms = models.FloatField(default=0)
    deception_effectiveness = models.FloatField(default=0)
    resource_usage = models.FloatField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        unique_together = ['environment', 'timestamp']
    
    def __str__(self):
        return f"{self.environment.name} - {self.timestamp}"


# ===== SESSION TRACKER =====
class SessionTracker(models.Model):
    id = models.CharField(max_length=50, primary_key=True, editable=False)
    request_id = models.CharField(max_length=100, unique=True)
    domain = models.CharField(max_length=255, db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.TextField()
    request_path = models.CharField(max_length=500)
    request_method = models.CharField(max_length=10)
    request_headers = models.JSONField(default=dict)
    request_body = models.TextField(blank=True)
    response_status = models.IntegerField()
    response_time_ms = models.IntegerField()
    suspicion_score = models.IntegerField(default=0)
    is_flagged = models.BooleanField(default=False)
    backend_type = models.CharField(max_length=20, default='real')
    session_id = models.CharField(max_length=100, null=True, blank=True, db_index=True)
    site = models.ForeignKey(RegisteredSite, on_delete=models.CASCADE, null=True, blank=True, related_name='session_trackers')
    created_at = models.DateTimeField(auto_now_add=True)
    
    def save(self, *args, **kwargs):
        if not self.id:
            self.id = f"st-{int(time.time() * 1000)}-{secrets.token_hex(3)}"
            if not self.session_id:
                session_key = f"{self.ip_address}:{self.domain}:{self.user_agent[:100]}"
                self.session_id = hashlib.md5(session_key.encode()).hexdigest()[:32]
        super().save(*args, **kwargs)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['domain', 'session_id']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['session_id']),
            models.Index(fields=['created_at']),
        ]


# ===== GLOBAL THREAT INTELLIGENCE =====
class GlobalThreatIntel(models.Model):
    threat_hash = models.CharField(max_length=255, unique=True)
    threat_type = models.CharField(max_length=100)
    severity = models.CharField(max_length=20)
    indicators = models.JSONField(default=list)
    affected_regions = models.JSONField(default=list)
    affected_industries = models.JSONField(default=list)
    detection_count = models.IntegerField(default=1)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    confidence_score = models.FloatField(default=0)
    mitigation_status = models.CharField(max_length=50, default='active')
    mitre_technique_id = models.CharField(max_length=50, null=True, blank=True)
    mitre_tactic = models.CharField(max_length=100, null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['threat_hash']),
            models.Index(fields=['last_seen', 'confidence_score']),
            models.Index(fields=['threat_type', 'severity']),
        ]
    
    def __str__(self):
        return f"{self.threat_type} - {self.severity} (Count: {self.detection_count})"


# ===== GLOBAL SESSION TRACKER =====
class GlobalSessionTracker(models.Model):
    session_id = models.CharField(max_length=255, db_index=True)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE)
    sites_visited = models.JSONField(default=list)
    global_threat_score = models.FloatField(default=0)
    first_seen_global = models.DateTimeField(auto_now_add=True)
    last_seen_global = models.DateTimeField(auto_now=True)
    total_interactions_global = models.IntegerField(default=0)
    flagged_by_ai = models.BooleanField(default=False)
    ai_analysis_cache = models.JSONField(default=dict, null=True, blank=True)
    
    class Meta:
        indexes = [
            models.Index(fields=['session_id', 'organization']),
            models.Index(fields=['global_threat_score']),
            models.Index(fields=['flagged_by_ai', 'last_seen_global']),
        ]
    
    def __str__(self):
        return f"{self.session_id[:20]}... - Score: {self.global_threat_score}"

# ═══════════════════════════════════════════════════════════════════════════════
# SITE PROFILE  — AI-generated understanding of what a registered site does
# ═══════════════════════════════════════════════════════════════════════════════

class SiteProfile(models.Model):
    """
    Stores the AI-generated behavioural profile for a registered site.
    Created automatically when a site is registered (or on demand).
    Used by the session analyser to detect anomalous behaviour.
    """
    STATUS_CHOICES = [
        ('pending',    'Pending'),
        ('profiling',  'Profiling'),
        ('ready',      'Ready'),
        ('failed',     'Failed'),
    ]

    site            = models.OneToOneField(RegisteredSite, on_delete=models.CASCADE,
                                           related_name='profile')
    status          = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    # What the AI discovered about the site
    site_purpose    = models.TextField(blank=True,
                                       help_text="What the site is for, in plain English")
    site_type       = models.CharField(max_length=100, blank=True,
                                       help_text="e.g. e-commerce, banking, blog, SaaS dashboard")
    expected_paths  = models.JSONField(default=list,
                                       help_text="URL paths that are normal for this site")
    normal_actions  = models.JSONField(default=list,
                                       help_text="What a normal user would do on this site")
    suspicious_signals = models.JSONField(default=list,
                                          help_text="Specific things that would be suspicious for THIS site")
    sensitive_areas = models.JSONField(default=list,
                                       help_text="Paths/actions that should never be accessed by a regular visitor")

    # Raw AI response stored so we can re-use it without re-calling Groq
    raw_ai_response = models.TextField(blank=True)

    # Metadata
    pages_crawled   = models.IntegerField(default=0)
    crawl_error     = models.TextField(blank=True)
    created_at      = models.DateTimeField(auto_now_add=True)
    updated_at      = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Profile for {self.site.domain} [{self.status}]"

    class Meta:
        ordering = ['-updated_at']


# ═══════════════════════════════════════════════════════════════════════════════
# PAYMENT
# ═══════════════════════════════════════════════════════════════════════════════

class Payment(models.Model):
    PROVIDER_CHOICES = [('mpesa', 'M-Pesa'), ('paypal', 'PayPal')]
    STATUS_CHOICES   = [('pending', 'Pending'), ('completed', 'Completed'), ('failed', 'Failed')]

    user        = models.ForeignKey(CustomUser, on_delete=models.CASCADE, related_name='payments')
    plan        = models.CharField(max_length=20)
    provider    = models.CharField(max_length=20, choices=PROVIDER_CHOICES)
    amount      = models.DecimalField(max_digits=10, decimal_places=2)
    currency    = models.CharField(max_length=10, default='USD')
    checkout_id = models.CharField(max_length=255, unique=True)
    status      = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at  = models.DateTimeField(auto_now_add=True)
    updated_at  = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.email} — {self.plan} via {self.provider} [{self.status}]"

    class Meta:
        ordering = ['-created_at']


# ═══════════════════════════════════════════════════════════════════════════════
# ADAPTIVE DECEPTION LOOP — DB MODELS
# ═══════════════════════════════════════════════════════════════════════════════

class DeceptionTarget(models.Model):
    """
    Tracks which RegisteredSites have opted into the Adaptive Deception Loop
    features — schema mirroring, AI-powered decoy generation, and log-based
    remediation analysis.

    The `allow_automated_remediation_analysis` boolean is the explicit consent
    gate: no background AI analysis of logs or traffic patterns runs unless
    the site owner turns this on.  It surfaces in the dashboard as a prominent
    toggle with a clear consent disclaimer.
    """
    STATUS_CHOICES = [
        ('active',   'Active'),
        ('paused',   'Paused'),
        ('learning', 'Learning (passive only)'),
    ]

    site = models.OneToOneField(
        'RegisteredSite',
        on_delete=models.CASCADE,
        related_name='deception_target',
    )

    # ── Consent gates ────────────────────────────────────────────────────────
    allow_automated_remediation_analysis = models.BooleanField(
        default=False,
        help_text=(
            "Explicitly authorises the background remediation engine to analyse "
            "this site's historical telemetry logs using the Groq AI and generate "
            "defensive code blueprints.  No AI processing of this site's logs "
            "occurs unless this is True."
        ),
    )
    allow_schema_mirroring = models.BooleanField(
        default=True,
        help_text=(
            "Allow the proxy to passively extract structural JSON footprints from "
            "clean traffic for use in AI-powered decoy generation.  No raw payload "
            "data is stored — only structural metadata (key names and value types)."
        ),
    )

    # ── State ────────────────────────────────────────────────────────────────
    status        = models.CharField(max_length=20, choices=STATUS_CHOICES, default='learning')
    schema_map    = models.JSONField(
        default=dict,
        help_text="Structural blueprint extracted from clean traffic: {endpoint: {field: type}}.",
    )
    last_analysis = models.DateTimeField(null=True, blank=True)
    created_at    = models.DateTimeField(auto_now_add=True)
    updated_at    = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"DeceptionTarget({self.site.domain}) consent={self.allow_automated_remediation_analysis}"

    class Meta:
        ordering = ['-created_at']


class StrategicDefenseBlueprint(models.Model):
    """
    A single AI-generated defensive patch blueprint produced by the
    RemediationEngine after analysing a site's telemetry logs.

    Each blueprint contains:
      - The log signatures that triggered the analysis.
      - The posture weaknesses the AI identified.
      - Deployable Django/Python code snippets to close the gaps.

    Blueprints are read-only once generated (immutable audit trail).
    They are never automatically deployed — a human operator reviews and
    applies them manually.
    """
    STATUS_CHOICES = [
        ('pending_review', 'Pending Review'),
        ('accepted',       'Accepted'),
        ('rejected',       'Rejected'),
        ('applied',        'Applied'),
    ]

    target      = models.ForeignKey(
        DeceptionTarget,
        on_delete=models.CASCADE,
        related_name='blueprints',
    )
    triggered_by = models.JSONField(
        default=list,
        help_text="The log signature array / anomaly sequences that triggered this analysis.",
    )
    weakness_summary = models.TextField(
        help_text="Plain-English description of the posture gaps the AI identified.",
    )
    patch_code   = models.TextField(
        help_text="Deployable Django/Python code snippets. Read-only — apply manually.",
    )
    model_used   = models.CharField(max_length=80, default='llama3-70b-8192')
    groq_tokens_used = models.IntegerField(default=0)
    status       = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending_review')
    operator_notes = models.TextField(blank=True)
    created_at   = models.DateTimeField(auto_now_add=True)

    def save(self, *args, **kwargs):
        if not self.id:
            self.id = f"sbp-{int(time.time() * 1000)}-{secrets.token_hex(3)}"
        super().save(*args, **kwargs)

    id = models.CharField(max_length=60, primary_key=True, editable=False)

    def __str__(self):
        return f"Blueprint({self.id}) for {self.target.site.domain} [{self.status}]"

    class Meta:
        ordering = ['-created_at']


class SchemaEndpointBlueprint(models.Model):
    """
    One endpoint's structural JSON footprint extracted from clean traffic.
    Used by the AI decoy generator to produce realistic fake responses
    that match the structure of real API responses.

    Only stores structural metadata — key names and Python type names.
    No actual values from real requests are ever persisted here.
    """
    target    = models.ForeignKey(
        DeceptionTarget,
        on_delete=models.CASCADE,
        related_name='endpoint_blueprints',
    )
    path      = models.CharField(max_length=512)
    method    = models.CharField(max_length=10, default='GET')
    # { "field_name": "str" | "int" | "float" | "bool" | "list" | "dict" }
    structure = models.JSONField(default=dict)
    sample_count = models.IntegerField(default=0, help_text="Number of clean requests that shaped this blueprint.")
    last_seen = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.method} {self.path} (seen {self.sample_count}x)"

    class Meta:
        unique_together = [['target', 'path', 'method']]
        ordering = ['-last_seen']


class CodeScan(models.Model):
    """
    NEW — "Automated Pentester" feature.

    A user-initiated static scan of a codebase zip they uploaded. The scan
    only reads the extracted source (see services/code_scanner.py) — it
    never executes anything from it and never touches any live system.
    Requires explicit consent (user_consented=True) before a scan is
    allowed to run; enforced in the view, not just here.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]

    site = models.ForeignKey(
        'RegisteredSite', on_delete=models.CASCADE, related_name='code_scans',
        null=True, blank=True,
    )
    uploaded_by = models.ForeignKey(
        CustomUser, on_delete=models.SET_NULL, null=True, blank=True, related_name='code_scans',
    )
    original_filename = models.CharField(max_length=255)
    file_size_bytes = models.BigIntegerField(default=0)

    # Explicit, required consent — the view refuses to run a scan without
    # this set True by the uploader at upload time. Owning your own code
    # is not assumed; the user has to affirmatively say so.
    user_consented = models.BooleanField(default=False)
    consent_statement = models.TextField(
        blank=True,
        help_text="The exact consent text the user agreed to at upload time (kept for audit purposes).",
    )

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    result_json = models.JSONField(default=dict, blank=True)
    error_message = models.TextField(blank=True)

    # Where the extracted source tree was persisted after a successful scan
    # (see code_scanner.scan_zip's persist_to param) — needed so remediation
    # can read the actual full file content for a finding, not just its
    # one-line snippet. Blank if the scan failed or predates this field.
    source_path = models.CharField(max_length=500, blank=True, default='')

    created_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"CodeScan({self.original_filename}, {self.status})"

    class Meta:
        ordering = ['-created_at']


class RemediationSuggestion(models.Model):
    """
    NEW — AI-generated fix for one specific finding from a CodeScan, shown
    to the user as a diff for review. Nothing is written to the persisted
    source tree until the user explicitly approves (see
    views_code_scan.py's RemediationApproveView) — generating a suggestion
    never modifies anything by itself.
    """
    STATUS_CHOICES = [
        ('pending', 'Pending Review'),
        ('approved', 'Approved & Applied'),
        ('rejected', 'Rejected'),
        ('failed', 'Generation Failed'),
    ]

    scan = models.ForeignKey(CodeScan, on_delete=models.CASCADE, related_name='remediations')
    requested_by = models.ForeignKey(CustomUser, on_delete=models.SET_NULL, null=True, blank=True)

    # Identifies which finding this is for (matches a Finding in the scan's
    # result_json — see code_scanner.Finding).
    rule_id = models.CharField(max_length=50)
    file = models.CharField(max_length=500)
    line = models.IntegerField()
    finding_title = models.CharField(max_length=300, blank=True)

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')

    original_content = models.TextField(blank=True)
    proposed_content = models.TextField(blank=True)
    diff_text = models.TextField(blank=True)
    explanation = models.TextField(blank=True)
    error_message = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    decided_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"RemediationSuggestion({self.file}:{self.line}, {self.rule_id}, {self.status})"

    class Meta:
        ordering = ['-created_at']
