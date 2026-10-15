from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from django.db import IntegrityError
import os

User = get_user_model()

class Command(BaseCommand):
    help = 'Creates a superuser if none exists'

    def handle(self, *args, **options):
        # Get credentials from environment variables or use defaults
        email = os.environ.get('DJANGO_SUPERUSER_EMAIL', 'geniussalvtore5@gmail.com')
        password = os.environ.get('DJANGO_SUPERUSER_PASSWORD', '#Sin9ularity')
        username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'SuperGenius')

        # Check if superuser exists
        if not User.objects.filter(is_superuser=True).exists():
            try:
                user = User.objects.create_superuser(
                    username=username,
                    email=email,
                    password=password
                )
                # The post_save signal on User already created a Profile
                # with the default role='member' — explicitly promote it
                # to 'superadmin' so the SuperAdmin dashboard is what this
                # account sees on login. (_get_role() in serializers.py
                # also treats any is_superuser=True account as
                # 'superadmin' regardless of this field, as a second line
                # of defense — but keeping the stored role accurate too
                # matters for anywhere the Profile row itself is read
                # directly, e.g. the Django admin.)
                if hasattr(user, 'profile'):
                    user.profile.role = 'superadmin'
                    user.profile.email_verified = True
                    user.profile.save(update_fields=['role', 'email_verified'])

                self.stdout.write(
                    self.style.SUCCESS(f'Superuser created successfully!')
                )
                self.stdout.write(
                    self.style.SUCCESS(f'Username: {username}')
                )
            except IntegrityError:
                self.stdout.write(
                    self.style.WARNING('Superuser already exists!')
                )
        else:
            # Superuser(s) already exist — make sure their Profile role
            # is consistent too, in case one was created before this
            # command started setting it (or via `createsuperuser` directly).
            for su in User.objects.filter(is_superuser=True):
                if hasattr(su, 'profile') and su.profile.role != 'superadmin':
                    su.profile.role = 'superadmin'
                    su.profile.save(update_fields=['role'])
            self.stdout.write(
                self.style.WARNING('Superuser already exists, skipping creation.')
            )