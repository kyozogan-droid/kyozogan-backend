"""
ASGI configuration for geniusmirage.

Handles both:
  - Standard HTTP requests via Django's ASGI application.
  - WebSocket connections for the Adaptive Deception Loop (honeypot shell
    and operator monitoring), routed via Django Channels.

Install dependencies:
    pip install channels channels-redis

Set CHANNEL_LAYERS in settings.py (in-memory for dev, Redis for production):
    CHANNEL_LAYERS = {
        "default": {
            "BACKEND": "channels_redis.core.RedisChannelLayer",
            "CONFIG":  {"hosts": [("127.0.0.1", 6379)]},
        }
    }
    # Or for single-instance dev (no Redis required):
    CHANNEL_LAYERS = {
        "default": {"BACKEND": "channels.layers.InMemoryChannelLayer"}
    }
"""

import os

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "geniusmirage.settings")

try:
    from channels.auth import AuthMiddlewareStack
    from channels.routing import ProtocolTypeRouter, URLRouter
    from channels.security.websocket import AllowedHostsOriginValidator
    from django.core.asgi import get_asgi_application

    # Import WebSocket URL patterns from the deception channel module.
    # Wrapped in try/except so the ASGI app still starts even if channels
    # isn't installed yet (graceful degradation for initial deployment).
    try:
        from base.services.deception_channel import build_websocket_urlpatterns
        ws_patterns = build_websocket_urlpatterns()
    except Exception as _ws_err:
        import logging
        logging.getLogger("geniusmirage.asgi").warning(
            "WebSocket patterns unavailable: %s", _ws_err
        )
        ws_patterns = []

    application = ProtocolTypeRouter({
        "http": get_asgi_application(),
        "websocket": AllowedHostsOriginValidator(
            AuthMiddlewareStack(URLRouter(ws_patterns))
        ),
    })

except ImportError:
    # channels not installed — fall back to pure HTTP ASGI
    from django.core.asgi import get_asgi_application
    application = get_asgi_application()
