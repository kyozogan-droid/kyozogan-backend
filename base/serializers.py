from rest_framework import serializers
from django.contrib.auth.password_validation import validate_password
from .models import *  # Import CustomUser directly

class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, validators=[validate_password])
    confirmPassword = serializers.CharField(write_only=True)

    class Meta:
        model = CustomUser  # Use CustomUser instead of get_user_model()
        fields = ('email', 'full_name', 'company_name', 'password', 'confirmPassword')

    def validate(self, attrs):
        if attrs['password'] != attrs['confirmPassword']:
            raise serializers.ValidationError({'password': 'Passwords do not match.'})
        return attrs

    def create(self, validated_data):
        validated_data.pop('confirmPassword')
        # Create username from email if not provided
        if 'username' not in validated_data or not validated_data.get('username'):
            validated_data['username'] = validated_data['email']
        
        user = CustomUser.objects.create_user(**validated_data)
        return user

class UserSerializer(serializers.ModelSerializer):
    is_admin_user = serializers.BooleanField(read_only=True)
    plan_limits   = serializers.DictField(read_only=True)

    class Meta:
        model  = CustomUser
        fields = ('id', 'email', 'full_name', 'company_name', 'plan', 'is_admin_user', 'plan_limits')



class RegisteredSiteSerializer(serializers.ModelSerializer):
    registered_date = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    last_activity = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta:
        model = RegisteredSite
        fields = ['id', 'domain', 'owner', 'owner_user', 'registered_date', 
                  'status', 'sessions_monitored', 'threats_detected', 'last_activity']
        read_only_fields = ['id', 'registered_date', 'sessions_monitored', 
                           'threats_detected', 'last_activity', 'owner_user']

class SiteCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = RegisteredSite
        fields = ['domain', 'owner', 'status']
    
    def create(self, validated_data):
        validated_data['owner_user'] = self.context['request'].user
        return super().create(validated_data)


# Add to your existing serializers.py

class ActivityLogSerializer(serializers.ModelSerializer):
    timestamp = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    domain_display = serializers.CharField(source='domain', read_only=True)
    
    class Meta:
        model = ActivityLog
        fields = ['id', 'timestamp', 'domain', 'domain_display', 'session_id', 'ip_address', 'user_agent',
                 'endpoint', 'method', 'status_code', 'response_time', 'suspicion_score', 
                 'flagged', 'site']
        read_only_fields = ['id', 'timestamp', 'created_at']

class ActivityLogCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActivityLog
        fields = ['domain', 'session_id', 'ip_address', 'user_agent', 'endpoint', 
                 'method', 'status_code', 'response_time', 'suspicion_score', 'flagged', 'site']
    
    def validate_suspicion_score(self, value):
        if value < 0 or value > 100:
            raise serializers.ValidationError("Suspicion score must be between 0 and 100")
        return value


# Add to your existing serializers.py

class ThreatSerializer(serializers.ModelSerializer):
    timestamp = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta:
        model = Threat
        fields = ['id', 'timestamp', 'domain', 'session_id', 'ip_address', 'threat_type',
                 'severity', 'indicators', 'status', 'description', 'site', 'activity_log']
        read_only_fields = ['id', 'timestamp', 'created_at', 'updated_at']

class ThreatCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Threat
        fields = ['domain', 'session_id', 'ip_address', 'threat_type', 'severity',
                 'indicators', 'status', 'description', 'site', 'activity_log']
    
    def validate_severity(self, value):
        if value not in ['critical', 'high', 'medium', 'low']:
            raise serializers.ValidationError("Invalid severity level")
        return value
    
    def validate_status(self, value):
        if value not in ['active', 'contained', 'resolved']:
            raise serializers.ValidationError("Invalid status")
        return value
    
    def validate_indicators(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("Indicators must be a list")
        return value



# Add to your existing serializers.py

class ActiveSessionSerializer(serializers.ModelSerializer):
    start_time = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    last_activity = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    duration_minutes = serializers.SerializerMethodField()
    
    class Meta:
        model = ActiveSession
        fields = ['id', 'domain', 'session_id', 'ip_address', 'start_time', 'last_activity',
                 'backend_type', 'threat_level', 'interaction_count', 'engagement_status',
                 'detected_techniques', 'site', 'threat', 'is_active', 'swap_approved', 'duration_minutes']
        read_only_fields = ['id', 'start_time', 'last_activity', 'created_at', 'updated_at']
    
    def get_duration_minutes(self, obj):
        from django.utils import timezone
        duration = timezone.now() - obj.start_time
        return int(duration.total_seconds() / 60)

class ActiveSessionCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActiveSession
        fields = ['domain', 'session_id', 'ip_address', 'backend_type', 'threat_level',
                 'interaction_count', 'engagement_status', 'detected_techniques', 'site', 'threat']
    
    def validate_detected_techniques(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("Detected techniques must be a list")
        return value
    
    def validate_session_id(self, value):
        # Check if session already exists
        if ActiveSession.objects.filter(session_id=value, is_active=True).exists():
            raise serializers.ValidationError("Active session with this ID already exists")
        return value


# Add to your existing serializers.py

class AttackPatternSerializer(serializers.ModelSerializer):
    last_seen = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta:
        model = AttackPattern
        fields = ['id', 'technique', 'category', 'frequency', 'last_seen', 'severity',
                 'description', 'indicators', 'mitre_id', 'detection_count', 'sites_affected']
        read_only_fields = ['id', 'created_at', 'updated_at']

class AttackPatternCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackPattern
        fields = ['technique', 'category', 'severity', 'description', 'indicators', 'mitre_id']
    
    def validate_indicators(self, value):
        if not isinstance(value, list):
            raise serializers.ValidationError("Indicators must be a list")
        return value

class PatternLearningDataSerializer(serializers.ModelSerializer):
    timestamp = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta:
        model = PatternLearningData
        fields = ['timestamp', 'new_patterns', 'repeating_patterns', 'total_patterns']

# Add to your existing serializers.py

class SystemSettingsSerializer(serializers.ModelSerializer):
    groq_api_key_set = serializers.SerializerMethodField()
    openai_api_key_set = serializers.SerializerMethodField()

    class Meta:
        model = SystemSettings
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at', 'updated_by']
        extra_kwargs = {
            'groq_api_key': {'write_only': True, 'required': False, 'allow_blank': True},
            'openai_api_key': {'write_only': True, 'required': False, 'allow_blank': True},
        }

    def get_groq_api_key_set(self, obj):
        # Lets the UI show "a key is configured" without ever exposing the
        # actual key value back over the API.
        return bool(obj.groq_api_key)

    def get_openai_api_key_set(self, obj):
        return bool(obj.openai_api_key)

    def validate_suspicion_threshold(self, value):
        if value < 0 or value > 100:
            raise serializers.ValidationError("Suspicion threshold must be between 0 and 100")
        return value
    
    def validate_session_timeout(self, value):
        if value < 1 or value > 1440:
            raise serializers.ValidationError("Session timeout must be between 1 and 1440 minutes")
        return value
    
    def validate_max_concurrent_sessions(self, value):
        if value < 1 or value > 10000:
            raise serializers.ValidationError("Max concurrent sessions must be between 1 and 10000")
        return value

class UserPreferencesSerializer(serializers.ModelSerializer):
    class Meta:
        model = UserPreferences
        fields = '__all__'
        read_only_fields = ['id', 'user', 'created_at', 'updated_at']

class SettingsAuditLogSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source='user.email', read_only=True)
    timestamp = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta:
        model = SettingsAuditLog
        fields = ['id', 'user_email', 'action', 'setting_key', 'old_value', 
                 'new_value', 'ip_address', 'timestamp']



# Add to your existing serializers.py

class ThreatIntelligenceSerializer(serializers.ModelSerializer):
    timestamp = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    affected_site_domain = serializers.CharField(source='affected_site.domain', read_only=True, allow_null=True)
    
    class Meta:
        model = ThreatIntelligence
        fields = ['id', 'timestamp', 'description', 'risk_score', 'status', 'source',
                 'payload', 'tool_signature', 'technique', 'mitre_attack_id', 'indicators',
                 'affected_site', 'affected_site_domain', 'threat', 'is_shared', 
                 'shared_at', 'created_at', 'updated_at']
        read_only_fields = ['id', 'created_at', 'updated_at']

class ThreatIntelligenceCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ThreatIntelligence
        fields = ['description', 'risk_score', 'source', 'payload', 'tool_signature',
                 'technique', 'mitre_attack_id', 'indicators', 'affected_site', 'threat']
    
    def validate_risk_score(self, value):
        if value < 0 or value > 100:
            raise serializers.ValidationError("Risk score must be between 0 and 100")
        return value


# Add to your existing serializers.py

class AnalyticsDataSerializer(serializers.ModelSerializer):
    timestamp = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta:
        model = AnalyticsData
        fields = ['id', 'timestamp', 'metric_type', 'value', 'site']
        read_only_fields = ['id', 'created_at']

class AttackLocationSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackLocation
        fields = ['id', 'country', 'country_code', 'attacks', 'latitude', 'longitude', 'last_seen']
        read_only_fields = ['id', 'last_seen', 'created_at']

class AttackerSkillDistributionSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackerSkillDistribution
        fields = ['id', 'skill_level', 'percentage', 'total_count', 'updated_at']
        read_only_fields = ['id', 'updated_at']

class AnalyticsSnapshotSerializer(serializers.ModelSerializer):
    date = serializers.DateField(format="%Y-%m-%d", read_only=True)
    
    class Meta:
        model = AnalyticsSnapshot
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


# Add to your existing serializers.py

class AttackerProfileSerializer(serializers.ModelSerializer):
    first_seen = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    last_activity = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta:
        model = AttackerProfile
        fields = '__all__'
        read_only_fields = ['id', 'first_seen', 'created_at', 'updated_at']

class AttackerBehaviorLogSerializer(serializers.ModelSerializer):
    timestamp = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta:
        model = AttackerBehaviorLog
        fields = '__all__'
        read_only_fields = ['id', 'created_at']

class AttackerCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = AttackerProfile
        fields = ['fingerprint', 'ip_address', 'country', 'country_code', 'city', 
                 'latitude', 'longitude', 'asn', 'isp']
    
    def validate_fingerprint(self, value):
        if AttackerProfile.objects.filter(fingerprint=value).exists():
            raise serializers.ValidationError("Attacker with this fingerprint already exists")
        return value



# Add to your existing serializers.py

class DeceptionEnvironmentSerializer(serializers.ModelSerializer):
    last_triggered = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    created_at = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    type_display = serializers.CharField(source='get_type_display', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = DeceptionEnvironment
        fields = '__all__'
        read_only_fields = ['id', 'created_at', 'updated_at']

class DeceptionEnvironmentCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = DeceptionEnvironment
        fields = ['name', 'type', 'description', 'deception_level', 'response_delay_ms', 
                 'error_rate', 'fake_data_volume', 'network_segment']
    
    def validate_error_rate(self, value):
        if value < 0 or value > 1:
            raise serializers.ValidationError("Error rate must be between 0 and 1")
        return value

class DeceptionInteractionSerializer(serializers.ModelSerializer):
    timestamp = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta:
        model = DeceptionInteraction
        fields = '__all__'
        read_only_fields = ['id', 'created_at']

class EnvironmentMetricsSerializer(serializers.ModelSerializer):
    timestamp = serializers.DateTimeField(format="%Y-%m-%d %H:%M:%S", read_only=True)
    
    class Meta:
        model = EnvironmentMetrics
        fields = '__all__'
        read_only_fields = ['id', 'created_at']


class OrganizationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Organization
        fields = ['id', 'name', 'subscription_tier', 'api_key', 'is_active', 
                  'ai_model_preference', 'max_sessions_per_site', 'data_retention_days',
                  'created_at', 'updated_at']
        read_only_fields = ['id', 'api_key', 'created_at', 'updated_at']

class GlobalThreatIntelSerializer(serializers.ModelSerializer):
    class Meta:
        model = GlobalThreatIntel
        fields = '__all__'
        read_only_fields = ['id', 'first_seen', 'last_seen']

class GlobalSessionTrackerSerializer(serializers.ModelSerializer):
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    
    class Meta:
        model = GlobalSessionTracker
        fields = '__all__'
        read_only_fields = ['id', 'first_seen_global', 'last_seen_global']


class DeceptionTargetSerializer(serializers.ModelSerializer):
    site_domain = serializers.CharField(source='site.domain', read_only=True)
    blueprint_count = serializers.SerializerMethodField()

    class Meta:
        model = DeceptionTarget
        fields = [
            'id', 'site', 'site_domain',
            'allow_automated_remediation_analysis', 'allow_schema_mirroring',
            'status', 'schema_map', 'last_analysis', 'blueprint_count',
            'created_at', 'updated_at',
        ]
        read_only_fields = ['id', 'schema_map', 'last_analysis', 'created_at', 'updated_at']

    def get_blueprint_count(self, obj):
        return obj.blueprints.count()


class StrategicDefenseBlueprintSerializer(serializers.ModelSerializer):
    site_domain = serializers.CharField(source='target.site.domain', read_only=True)

    class Meta:
        model = StrategicDefenseBlueprint
        fields = [
            'id', 'target', 'site_domain', 'triggered_by', 'weakness_summary',
            'patch_code', 'model_used', 'groq_tokens_used', 'status',
            'operator_notes', 'created_at',
        ]
        read_only_fields = [
            'id', 'triggered_by', 'weakness_summary', 'patch_code',
            'model_used', 'groq_tokens_used', 'created_at',
        ]
