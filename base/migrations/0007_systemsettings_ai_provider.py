from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('base', '0006_codescan'),
    ]

    operations = [
        migrations.AddField(
            model_name='systemsettings',
            name='ai_provider',
            field=models.CharField(
                choices=[('groq', 'Groq'), ('openai', 'OpenAI')],
                default='groq', max_length=20,
                help_text='Which provider powers the AI threat-analysis tier (Tier 3).',
            ),
        ),
        migrations.AddField(
            model_name='systemsettings',
            name='ai_model',
            field=models.CharField(
                blank=True, default='llama-3.3-70b-versatile', max_length=100,
                help_text="Model name for the selected provider, e.g. 'llama-3.3-70b-versatile' for Groq "
                          "or 'gpt-4o-mini' for OpenAI. Leave blank to use the provider's built-in default.",
            ),
        ),
        migrations.AddField(
            model_name='systemsettings',
            name='openai_api_key',
            field=models.CharField(
                blank=True, default='', max_length=200,
                help_text="Required only when ai_provider is 'openai'. Falls back to the OPENAI_API_KEY "
                          "environment variable if left blank.",
            ),
        ),
    ]
