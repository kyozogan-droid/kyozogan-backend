"""
base/permissions.py
====================
Custom DRF permission classes.

Why this exists: DRF's built-in `IsAdminUser` only checks Django's
`is_staff` flag. This app has its own, broader notion of "admin" —
`CustomUser.is_admin_user`, which is True for `plan == 'admin'` OR
`is_superuser` OR `is_staff` (see models.py) — and it's already used
consistently by hand in several views (e.g. the subscription endpoint).
`system_settings` was the one place still using DRF's narrower
`IsAdminUser` instead, which meant a normal user — even the person who
owns and set up their own Genius Mirage deployment — would get a 403 on
the Settings page unless they also happened to have Django's `is_staff`
flag specifically set, which a normal signup never sets. `IsAppAdminUser`
below makes every "admin-gated" endpoint use the same rule.
"""

from rest_framework.permissions import BasePermission


class IsAppAdminUser(BasePermission):
    """Matches CustomUser.is_admin_user: plan == 'admin' OR is_superuser
    OR is_staff — the app's actual admin concept, not just Django's
    built-in is_staff flag."""

    def has_permission(self, request, view):
        user = request.user
        return bool(
            user
            and user.is_authenticated
            and getattr(user, 'is_admin_user', False)
        )
