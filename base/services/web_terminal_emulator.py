"""
backend/base/services/web_terminal_emulator.py
================================================
AI-powered web shell honeypot — served via Django Channels WebSocket.

Architecture
------------
When the behavioral detector has already flagged a session as malicious and
that session navigates to the hidden honeypot path, a WebSocket connection
is upgraded.  Every command the attacker types is:
  1. Captured in a per-connection in-memory buffer (no DB writes on the hot path).
  2. Appended to the AI's conversation context.
  3. Streamed to FAST_STREAM_EMULATOR which responds as a convincingly imperfect
     legacy Linux shell.
  4. Mirrored token-by-token to the operator monitoring channel (deception_channel.py).
  5. Persisted to ActivityLog asynchronously after the exchange, not during it.

The AI persona is a realistic but deliberately flawed server — it produces plausible
outputs while never yielding real system data.  Attackers spend time here instead
of pivoting; all commands are logged for threat intelligence.

Access control
--------------
The WebSocket URL includes a per-session HMAC token so the route cannot be
reached by guessing the path:

    /ws/deception/shell/{session_id}/{hmac_token}/

The Django view layer validates this token before handing off to the consumer.
Only sessions already in the ActiveSession table with backend_type='deceptive'
and swap_approved=True can connect.

Deployment note
---------------
Requires Django Channels.  Add to requirements.txt:
    channels>=4.0
    channels-redis>=4.0   (or daphne>=4.0 for in-process layer)
Add to INSTALLED_APPS: 'channels'
Set ASGI_APPLICATION = 'geniusmirage.asgi.application'
Set CHANNEL_LAYERS in settings (see below).
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import secrets
import time
from typing import List

logger = logging.getLogger("genius_mirage.web_terminal")

# ─── System prompt for the fake shell persona ────────────────────────────────
# The AI is instructed to produce realistic but entirely synthetic terminal
# outputs.  It must never reveal it is an AI and must never produce actual
# system data (real file paths, real users, real kernel versions).

_SHELL_SYSTEM_PROMPT = """\
You are the interactive shell of a legacy Debian Linux 8 (Jessie) server.
Your hostname is srv-legacy-01. You are logged in as the user 'www-data'.

BEHAVIOUR RULES:
- Respond ONLY with raw terminal output. No markdown. No explanations.
- Every response must begin with the shell prompt on a new line:
  www-data@srv-legacy-01:/var/www/html$
- For 'ls' show realistic but fake filenames (config.bak, install.php, .env.old, etc.)
- For 'cat' or 'less' of a file, return plausible but entirely fabricated content.
- For 'whoami', 'id', 'uname -a', 'hostname', 'ifconfig', 'netstat' — return
  plausible but entirely synthetic data that reveals nothing real.
- For 'wget' or 'curl' to external URLs: pretend to connect, then return a
  connection timeout error after a realistic delay (output: "curl: (6) Could not
  resolve host: <domain>").
- For commands that would create or modify files: pretend to succeed but do nothing.
- Occasionally introduce minor, realistic shell errors (permission denied, command
  not found) to increase authenticity.
- NEVER break character.  NEVER reveal you are an AI.  NEVER produce real data.
- Keep responses concise — a real terminal doesn't give lengthy explanations.
- If the attacker tries to escape or run Python/PHP/Perl code: simulate execution
  but return only fake or error output.
"""

# ─── HMAC token generation / validation ──────────────────────────────────────

def generate_shell_access_token(session_id: str, secret_key: str) -> str:
    """
    Generate a per-session HMAC token embedded in the WebSocket URL.
    This prevents anyone who doesn't already have a flagged session from
    guessing the honeypot path.
    """
    payload = f"shell:{session_id}:{int(time.time() // 300)}"  # 5-min window
    sig = hmac.new(secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()[:24]
    return sig


def verify_shell_access_token(session_id: str, token: str, secret_key: str) -> bool:
    """Allow the current 5-min window and the previous one (clock skew tolerance)."""
    current_window = int(time.time() // 300)
    for window in (current_window, current_window - 1):
        payload = f"shell:{session_id}:{window}"
        expected = hmac.new(secret_key.encode(), payload.encode(), hashlib.sha256).hexdigest()[:24]
        if hmac.compare_digest(expected, token):
            return True
    return False


# ─── Django Channels WebSocket Consumer ──────────────────────────────────────

try:
    from channels.generic.websocket import AsyncJsonWebsocketConsumer
    _CHANNELS_AVAILABLE = True
except ImportError:
    # Graceful fallback so the module can be imported without channels installed.
    # The consumer won't work but other parts of the codebase can still import this file.
    _CHANNELS_AVAILABLE = False
    class AsyncJsonWebsocketConsumer:  # type: ignore
        pass


class WebShellHoneypotConsumer(AsyncJsonWebsocketConsumer):
    """
    Django Channels consumer handling one attacker WebSocket connection.

    URL pattern (in routing.py):
        re_path(r'^ws/deception/shell/(?P<session_id>[^/]+)/(?P<token>[a-f0-9]+)/$',
                WebShellHoneypotConsumer.as_asgi()),
    """

    # In-memory conversation history for this connection
    _context: List[dict]
    _session_id: str
    _monitoring_group: str

    # ── Lifecycle ──────────────────────────────────────────────────────────

    async def connect(self):
        from django.conf import settings
        from base.config.deception_client import ActiveGroqModels, stream_completion

        session_id = self.scope["url_route"]["kwargs"]["session_id"]
        token      = self.scope["url_route"]["kwargs"]["token"]

        # 1. Validate the HMAC token
        secret = getattr(settings, "SECRET_KEY", "")
        if not verify_shell_access_token(session_id, token, secret):
            logger.warning("[WebShell] Invalid token for session %s — rejecting", session_id)
            await self.close(code=4403)
            return

        # 2. Confirm session is flagged and swap-approved
        valid = await self._validate_session(session_id)
        if not valid:
            logger.warning("[WebShell] Session %s not flagged/approved — rejecting", session_id)
            await self.close(code=4403)
            return

        self._session_id = session_id
        self._monitoring_group = f"monitor_{session_id}"
        self._context = [{"role": "system", "content": _SHELL_SYSTEM_PROMPT}]

        # 3. Accept connection and join the operator monitoring group
        await self.accept()
        try:
            from channels.layers import get_channel_layer
            layer = get_channel_layer()
            if layer:
                await layer.group_add(self._monitoring_group, self.channel_name)
        except Exception:
            pass

        # 4. Send the opening banner (no AI call needed for this)
        banner = (
            "Debian GNU/Linux 8 (jessie)\r\n"
            "Last login: Wed Jan 15 03:21:44 2025 from 10.0.0.1\r\n"
            "www-data@srv-legacy-01:/var/www/html$ "
        )
        await self.send(text_data=banner)
        logger.info("[WebShell] Session %s connected — honeypot active", session_id)

    async def disconnect(self, code):
        try:
            from channels.layers import get_channel_layer
            layer = get_channel_layer()
            if layer and hasattr(self, "_monitoring_group"):
                await layer.group_discard(self._monitoring_group, self.channel_name)
        except Exception:
            pass
        logger.info("[WebShell] Session %s disconnected (code=%s)", getattr(self, "_session_id", "?"), code)

    # ── Receive attacker input ─────────────────────────────────────────────

    async def receive(self, text_data: str = "", bytes_data: bytes = None):
        command = (text_data or "").strip()
        if not command:
            return

        # Mirror raw command to operator monitoring channel
        await self._emit_to_monitor("attacker_input", command)
        logger.info("[WebShell] [%s] CMD: %s", self._session_id, command[:200])

        # Append to conversation context
        self._context.append({"role": "user", "content": command})

        # Stream AI response back to attacker
        response_chunks = []
        try:
            from base.config.deception_client import ActiveGroqModels, stream_completion
            async for chunk in stream_completion(
                ActiveGroqModels.FAST_STREAM_EMULATOR,
                self._context,
                temperature=0.6,
                max_tokens=256,
            ):
                await self.send(text_data=chunk)
                response_chunks.append(chunk)
                # Mirror each chunk to the operator feed
                await self._emit_to_monitor("groq_output_chunk", chunk)

        except Exception as exc:
            fallback = "\r\nsh: command not found\r\nwww-data@srv-legacy-01:/var/www/html$ "
            await self.send(text_data=fallback)
            response_chunks.append(fallback)
            logger.warning("[WebShell] Groq error for %s: %s", self._session_id, exc)

        # Append AI response to context for multi-turn continuity
        full_response = "".join(response_chunks)
        self._context.append({"role": "assistant", "content": full_response})

        # Trim context to last 20 turns to stay within token limits
        if len(self._context) > 41:  # system + 20 pairs
            self._context = [self._context[0]] + self._context[-40:]

        # Persist to ActivityLog asynchronously — after response is already sent
        asyncio.create_task(self._persist_interaction(command, full_response))

    # ── Operator monitor message handler ──────────────────────────────────

    async def operator_inject(self, event: dict):
        """
        Receive an operator instruction from the monitoring dashboard and
        inject it as a hidden system note into the AI context.  The attacker
        never sees this; the AI's next response will be steered by it.
        """
        instruction = event.get("instruction", "")
        if not instruction:
            return
        # Inject as a system-level note (invisible to attacker)
        steering = f"[OPERATOR NOTE — invisible to attacker, steer your next response accordingly]: {instruction}"
        self._context.append({"role": "system", "content": steering})
        logger.info("[WebShell] Operator injected steering for session %s", self._session_id)

    async def operator_terminate(self, event: dict):
        """Operator requested immediate session teardown."""
        await self.send(text_data="\r\nConnection reset by peer.\r\n")
        await self.close(code=4200)
        logger.info("[WebShell] Session %s terminated by operator", self._session_id)

    # ── Helpers ───────────────────────────────────────────────────────────

    @staticmethod
    async def _validate_session(session_id: str) -> bool:
        """Async DB check — session must exist and be operator-approved."""
        from channels.db import database_sync_to_async

        @database_sync_to_async
        def _check():
            try:
                from base.models import ActiveSession
                s = ActiveSession.objects.get(session_id=session_id)
                return s.backend_type == "deceptive" and s.swap_approved
            except Exception:
                return False

        return await _check()

    async def _emit_to_monitor(self, event_type: str, data: str):
        """Send a telemetry event to the operator monitoring group."""
        try:
            from channels.layers import get_channel_layer
            layer = get_channel_layer()
            if layer and hasattr(self, "_monitoring_group"):
                await layer.group_send(self._monitoring_group, {
                    "type":       "telemetry.event",
                    "event_type": event_type,
                    "session_id": self._session_id,
                    "data":       data,
                    "ts":         time.time(),
                })
        except Exception:
            pass

    @staticmethod
    async def _persist_interaction(command: str, response: str):
        """Write the command/response pair to ActivityLog — fire-and-forget."""
        from channels.db import database_sync_to_async

        @database_sync_to_async
        def _write():
            try:
                pass  # ActivityLog creation would go here with the session FK
                # Kept minimal so the import chain works before full wiring.
            except Exception as exc:
                logger.debug("[WebShell] Persist failed: %s", exc)

        await _write()


# ─── Django URL/routing helpers ───────────────────────────────────────────────

def get_shell_websocket_url(session_id: str) -> str | None:
    """
    Return the WebSocket URL for the honeypot shell for a given session.
    Returns None if the session isn't eligible.
    Called by the frontend API to get the ws:// URL to hand to the attacker.
    """
    try:
        from django.conf import settings
        from base.models import ActiveSession
        sess = ActiveSession.objects.get(session_id=session_id)
        if not (sess.backend_type == "deceptive" and sess.swap_approved):
            return None
        token = generate_shell_access_token(session_id, settings.SECRET_KEY)
        return f"/ws/deception/shell/{session_id}/{token}/"
    except Exception:
        return None
