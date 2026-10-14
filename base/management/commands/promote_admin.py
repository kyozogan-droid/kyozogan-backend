"""
python manage.py promote_admin <email>

Grants admin access (plan='admin', is_staff=True, is_superuser=True) to an
existing user account by email. Use this to give your own registered
account access to admin-gated pages/endpoints (System Settings, Settings
audit log, resetting system settings) — `seed_admin` only creates/upgrades
a separate, hardcoded admin@geniusmirage.io account, which isn't the same
as the account you signed up with.
"""
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model

User = get_user_model()


class Command(BaseCommand):
    help = "Grant admin access to an existing user account by email"

    def add_arguments(self, parser):
        parser.add_argument('email', type=str)

    def handle(self, *args, **options):
        email = options['email']
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise CommandError(
                f"No user found with email '{email}'. Check the exact "
                f"email you registered with (case-sensitive on some setups)."
            )

        user.plan = 'admin'
        user.is_staff = True
        user.is_superuser = True
        user.save()

        self.stdout.write(self.style.SUCCESS(
            f"✅ {email} now has admin access (plan='admin', is_staff=True, "
            f"is_superuser=True). Log out and back in for the change to "
            f"take effect if you were already signed in."
        ))
