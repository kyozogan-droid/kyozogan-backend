import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('base', '0007_systemsettings_ai_provider'),
    ]

    operations = [
        migrations.AddField(
            model_name='codescan',
            name='source_path',
            field=models.CharField(blank=True, default='', max_length=500),
        ),
        migrations.CreateModel(
            name='RemediationSuggestion',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('rule_id', models.CharField(max_length=50)),
                ('file', models.CharField(max_length=500)),
                ('line', models.IntegerField()),
                ('finding_title', models.CharField(blank=True, max_length=300)),
                ('status', models.CharField(choices=[('pending', 'Pending Review'), ('approved', 'Approved & Applied'), ('rejected', 'Rejected'), ('failed', 'Generation Failed')], default='pending', max_length=20)),
                ('original_content', models.TextField(blank=True)),
                ('proposed_content', models.TextField(blank=True)),
                ('diff_text', models.TextField(blank=True)),
                ('explanation', models.TextField(blank=True)),
                ('error_message', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('decided_at', models.DateTimeField(blank=True, null=True)),
                ('requested_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to=settings.AUTH_USER_MODEL)),
                ('scan', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='remediations', to='base.codescan')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
