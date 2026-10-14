"""
python manage.py seed_admin

Creates the default admin account if it doesn't already exist.
Credentials:
  Email:    admin@geniusmirage.io
  Password: GeniusMirage@Admin2024!
"""
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model

User = get_user_model()

ADMIN_EMAIL    = 'admin@geniusmirage.io'
ADMIN_PASSWORD = 'GeniusMirage@Admin2024!'
ADMIN_NAME     = 'Platform Admin'


class Command(BaseCommand):
    help = 'Seed the default admin account'

    def handle(self, *args, **options):
        user, created = User.objects.get_or_create(
            email=ADMIN_EMAIL,
            defaults={
                'username':     ADMIN_EMAIL,
                'full_name':    ADMIN_NAME,
                'company_name': 'Genius Mirage',
                'is_staff':     True,
                'is_superuser': True,
                'plan':         'admin',
            },
        )
        if created:
            user.set_password(ADMIN_PASSWORD)
            user.save()
            self.stdout.write(self.style.SUCCESS(
                f'\n✅ Admin account created\n'
                f'   Email:    {ADMIN_EMAIL}\n'
                f'   Password: {ADMIN_PASSWORD}\n'
            ))
        else:
            # Ensure existing account has admin privileges
            updated = False
            if user.plan != 'admin':
                user.plan = 'admin'
                updated = True
            if not user.is_superuser:
                user.is_superuser = True
                updated = True
            if not user.is_staff:
                user.is_staff = True
                updated = True
            if updated:
                user.save()
                self.stdout.write(self.style.SUCCESS(f'✅ Existing account {ADMIN_EMAIL} upgraded to admin'))
            else:
                self.stdout.write(self.style.WARNING(f'⚠  Admin account already exists: {ADMIN_EMAIL}'))
