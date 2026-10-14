from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('base', '0005_deceptiontarget_strategicdefenseblueprint_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='CodeScan',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('original_filename', models.CharField(max_length=255)),
                ('file_size_bytes', models.BigIntegerField(default=0)),
                ('user_consented', models.BooleanField(default=False)),
                ('consent_statement', models.TextField(blank=True, help_text='The exact consent text the user agreed to at upload time (kept for audit purposes).')),
                ('status', models.CharField(choices=[('pending', 'Pending'), ('running', 'Running'), ('completed', 'Completed'), ('failed', 'Failed')], default='pending', max_length=20)),
                ('result_json', models.JSONField(blank=True, default=dict)),
                ('error_message', models.TextField(blank=True)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('completed_at', models.DateTimeField(blank=True, null=True)),
                ('site', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.CASCADE, related_name='code_scans', to='base.registeredsite')),
                ('uploaded_by', models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='code_scans', to=settings.AUTH_USER_MODEL)),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]
