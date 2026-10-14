"""
backend/base/services/deception_channel.py
============================================
Operator monitoring channel — real-time wiretap of honeypot interactions.

Every WebShellHoneypotConsumer emits telemetry events to a per-session
channel group named `monitor_{session_id}`.  This consumer subscribes to
that group and relays everything to the operator's dashboard WebSocket in
real time.

Operator capabilities:
  - Watch all attacker commands (red) and AI responses (green) scroll live.
  - Inject custom steering text into the AI's ongoing context.
  - Request an immediate session teardown.

URL pattern (routing.py):
    re_path(r'^ws/deception/monitor/(?P<session_id>[^/]+)/$',
            OperatorMonitorConsumer.as_asgi()),

Access: requires a valid JWT in the WebSocket subprotocol header or cookie.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger("genius_mirage.deception_channel")


# ─── Graceful import guard ────────────────────────────────────────────────────

try:
    from channels.generic.websocket import AsyncJsonWebsocketConsumer
    _CHANNELS_AVAILABLE = True
except ImportError:
    _CHANNELS_AVAILABLE = False
    class AsyncJsonWebsocketConsumer:  # type: ignore
        pass


class OperatorMonitorConsumer(AsyncJsonWebsocketConsumer):
    """
    Operator-facing WebSocket consumer.  Authenticates the operator, then
    subscribes to the per-session telemetry group to receive real-time events
    from the honeypot shell consumer.
    """

    _session_id: str
    _monitoring_group: str
    _paused: bool   # True while human_intervention_override is active

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def connect(self):
        self._session_id = self.scope["url_route"]["kwargs"]["session_id"]
        self._monitoring_group = f"monitor_{self._session_id}"
        self._paused = False

        # Authenticate operator — must be an admin user
        authenticated = await self._authenticate()
        if not authenticated:
            logger.warning("[Monitor] Unauthenticated connection attempt — rejecting")
            await self.close(code=4401)
            return

        await self.accept()

        # Subscribe to the per-session telemetry group
        try:
            from channels.layers import get_channel_layer
            layer = get_channel_layer()
            if layer:
                await layer.group_add(self._monitoring_group, self.channel_name)
        except Exception as exc:
            logger.warning("[Monitor] Could not join group: %s", exc)

        # Confirm connection to the dashboard
        await self.send_json({
            "type":       "monitor_connected",
            "session_id": self._session_id,
            "ts":         time.time(),
            "message":    f"Monitoring session {self._session_id}. All interactions will appear here.",
        })
        logger.info("[Monitor] Operator connected to session %s", self._session_id)

    async def disconnect(self, code):
        try:
            from channels.layers import get_channel_layer
            layer = get_channel_layer()
            if layer:
                await layer.group_discard(self._monitoring_group, self.channel_name)
        except Exception:
            pass
        logger.info("[Monitor] Operator disconnected from session %s", self._session_id)

    # ── Receive operator commands ──────────────────────────────────────────

    async def receive_json(self, content: dict, **kwargs):
        """
        Handle messages from the operator dashboard.

        Supported message types:
          { "action": "inject",    "instruction": "..." }   → steer the AI
          { "action": "terminate" }                         → tear down session
          { "action": "pause" }                             → pause automated Groq routing
          { "action": "resume" }                            → resume automated Groq routing
        """
        action = content.get("action", "")

        if action == "inject":
            await self._handle_inject(content.get("instruction", ""))

        elif action == "terminate":
            await self._handle_terminate()

        elif action == "pause":
            self._paused = True
            await self.send_json({
                "type":    "monitor_status",
                "paused":  True,
                "message": "Automated Groq routing paused. Waiting for your instructions.",
            })
            # Signal the shell consumer to pause too
            await self._signal_shell_consumer("operator_pause", {})

        elif action == "resume":
            self._paused = False
            await self.send_json({
                "type":    "monitor_status",
                "paused":  False,
                "message": "Automated routing resumed.",
            })
            await self._signal_shell_consumer("operator_resume", {})

        else:
            await self.send_json({"type": "error", "message": f"Unknown action: {action}"})

    # ── Incoming telemetry from the shell consumer ─────────────────────────

    async def telemetry_event(self, event: dict):
        """
        Called by the channel layer when a telemetry event arrives from the
        honeypot shell consumer.  Relay to the operator's browser with
        display metadata (colour hints, direction, timestamp).
        """
        event_type = event.get("event_type", "")
        data       = event.get("data", "")
        ts         = event.get("ts", time.time())

        # Map event types to display direction for the frontend terminal
        direction = "inbound"  if event_type == "attacker_input" else "outbound"
        colour    = "red"      if event_type == "attacker_input" else "green"

        await self.send_json({
            "type":      "telemetry",
            "event_type": event_type,
            "direction": direction,
            "colour":    colour,
            "data":      data,
            "ts":        ts,
            "session_id": event.get("session_id", self._session_id),
        })

    # ── Operator action handlers ───────────────────────────────────────────

    async def _handle_inject(self, instruction: str):
        """Inject a steering hint into the live AI context via the channel layer."""
        if not instruction.strip():
            return
        logger.info("[Monitor] Operator injecting instruction for %s: %s",
                    self._session_id, instruction[:100])
        await self._signal_shell_consumer("operator_inject", {"instruction": instruction})
        await self.send_json({
            "type":        "injection_sent",
            "instruction": instruction,
            "ts":          time.time(),
        })

    async def _handle_terminate(self):
        """Send a teardown command to the shell consumer."""
        logger.info("[Monitor] Operator terminating session %s", self._session_id)
        await self._signal_shell_consumer("operator_terminate", {})
        await self.send_json({
            "type":    "termination_sent",
            "message": "Session teardown command dispatched.",
            "ts":      time.time(),
        })

    # ── Helpers ───────────────────────────────────────────────────────────

    async def _authenticate(self) -> bool:
        """Validate operator identity from the JWT in the query string or cookie."""
        try:
            from channels.db import database_sync_to_async
            from django.contrib.auth.models import AnonymousUser
            user = self.scope.get("user")
            if not user or isinstance(user, AnonymousUser):
                # Try query-string JWT fallback
                qs = dict(
                    (k.decode(), v.decode())
                    for k, v in (pair.split(b"=", 1) for pair in
                                 self.scope.get("query_string", b"").split(b"&")
                                 if b"=" in pair)
                )
                token = qs.get("token", "")
                if token:
                    from rest_framework_simplejwt.tokens import AccessToken
                    from rest_framework_simplejwt.exceptions import InvalidToken
                    try:
                        tok = AccessToken(token)
                        from base.models import CustomUser
                        user_id = tok["user_id"]

                        @database_sync_to_async
                        def get_user():
                            return CustomUser.objects.get(pk=user_id)

                        user = await get_user()
                    except Exception:
                        return False

            if user and hasattr(user, "is_admin_user") and user.is_admin_user:
                return True
            return False
        except Exception as exc:
            logger.warning("[Monitor] Auth error: %s", exc)
            return False

    async def _signal_shell_consumer(self, event_type: str, payload: dict):
        """Send a control event to all WebShellHoneypotConsumers in this group."""
        try:
            from channels.layers import get_channel_layer
            layer = get_channel_layer()
            if layer:
                await layer.group_send(self._monitoring_group, {
                    "type": event_type.replace("_", "."),
                    **payload,
                })
        except Exception as exc:
            logger.debug("[Monitor] Signal error: %s", exc)


# ─── ASGI routing helper ──────────────────────────────────────────────────────

def build_websocket_urlpatterns():
    """
    Returns the URL patterns for both consumers.
    Call this from asgi.py or a dedicated routing.py:

        from base.services.deception_channel import build_websocket_urlpatterns
        application = ProtocolTypeRouter({
            "http":      get_asgi_application(),
            "websocket": URLRouter(build_websocket_urlpatterns()),
        })
    """
    try:
        from django.urls import re_path
        from base.services.web_terminal_emulator import WebShellHoneypotConsumer
        return [
            re_path(
                r"^ws/deception/shell/(?P<session_id>[^/]+)/(?P<token>[a-f0-9]+)/$",
                WebShellHoneypotConsumer.as_asgi(),
            ),
            re_path(
                r"^ws/deception/monitor/(?P<session_id>[^/]+)/$",
                OperatorMonitorConsumer.as_asgi(),
            ),
        ]
    except Exception as exc:
        logger.error("[DeceptionChannel] Could not build URL patterns: %s", exc)
        return []
