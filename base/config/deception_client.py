"""
backend/base/config/deception_client.py
========================================
Central Groq API client for the Adaptive Deception Loop.

Two routing tiers, both using the Groq free API:
  FAST_STREAM_EMULATOR   — llama3-8b-8192  (low-latency, real-time streaming)
  HEAVY_ANALYTICS_BRAIN  — llama3-70b-8192 (deep log analysis, schema synthesis)

Includes an in-process sliding-window rate limiter that prevents concurrent
request spikes from burning through free-tier token quotas.  Every call goes
through _groq_request() which enforces the window before dispatching.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import os
import time
from enum import Enum
from typing import AsyncIterator, Dict, Optional

import groq as _groq

logger = logging.getLogger("genius_mirage.deception_client")


# ─── Model Registry ──────────────────────────────────────────────────────────

class ActiveGroqModels(Enum):
    # Fast path: real-time interactive web-shell emulation, per-token streaming.
    FAST_STREAM_EMULATOR  = "llama3-8b-8192"
    # Heavy path: log array analysis, schema synthesis, remediation blueprints.
    HEAVY_ANALYTICS_BRAIN = "llama3-70b-8192"


# ─── Sliding-Window Rate Limiter ─────────────────────────────────────────────

class _SlidingWindowLimiter:
    """
    Thread- and coroutine-safe sliding-window rate limiter.

    Maintains a deque of request timestamps per model bucket.  Before every
    Groq call, _acquire() checks whether the rolling window already contains
    `max_requests` entries; if so, it sleeps until the oldest entry falls
    outside the window.

    Default limits are deliberately conservative to protect free-tier quotas:
      - Fast model : 20 req / 60 s  (Groq free: ~30 rpm for 8 B models)
      - Heavy model: 10 req / 60 s  (Groq free: ~15 rpm for 70 B models)

    Both limits can be overridden via the environment:
      GM_RATE_FAST_MAX_REQ, GM_RATE_FAST_WINDOW_S
      GM_RATE_HEAVY_MAX_REQ, GM_RATE_HEAVY_WINDOW_S
    """

    def __init__(self):
        self._windows: Dict[str, collections.deque] = {}
        self._locks: Dict[str, asyncio.Lock] = {}
        self._config = {
            ActiveGroqModels.FAST_STREAM_EMULATOR.value: {
                "max_requests": int(os.environ.get("GM_RATE_FAST_MAX_REQ", 20)),
                "window_s":     float(os.environ.get("GM_RATE_FAST_WINDOW_S", 60)),
            },
            ActiveGroqModels.HEAVY_ANALYTICS_BRAIN.value: {
                "max_requests": int(os.environ.get("GM_RATE_HEAVY_MAX_REQ", 10)),
                "window_s":     float(os.environ.get("GM_RATE_HEAVY_WINDOW_S", 60)),
            },
        }

    def _ensure_model(self, model: str):
        if model not in self._windows:
            self._windows[model] = collections.deque()
        if model not in self._locks:
            self._locks[model] = asyncio.Lock()

    async def acquire(self, model: str) -> None:
        self._ensure_model(model)
        cfg = self._config.get(model, {"max_requests": 15, "window_s": 60})
        max_req  = cfg["max_requests"]
        window_s = cfg["window_s"]

        async with self._locks[model]:
            dq = self._windows[model]
            while True:
                now = time.monotonic()
                # Evict entries that have fallen outside the window
                while dq and now - dq[0] > window_s:
                    dq.popleft()
                if len(dq) < max_req:
                    dq.append(now)
                    return
                # Window is full — wait until the oldest entry expires
                wait_for = window_s - (now - dq[0]) + 0.05
                logger.debug("[RateLimit] %s at capacity — sleeping %.2fs", model, wait_for)
                await asyncio.sleep(wait_for)


_limiter = _SlidingWindowLimiter()


# ─── Groq Client Wrapper ─────────────────────────────────────────────────────

def _resolve_groq_key() -> str:
    """Read the Groq API key from SystemSettings (admin panel) or env var."""
    try:
        from django.conf import settings as _dj
        if getattr(_dj, "GROQ_API_KEY", ""):
            return _dj.GROQ_API_KEY
    except Exception:
        pass
    try:
        from base.models import SystemSettings
        obj = SystemSettings.objects.filter(pk=1).first()
        if obj and obj.groq_api_key:
            return obj.groq_api_key
    except Exception:
        pass
    key = os.environ.get("GROQ_API_KEY", "")
    if not key:
        raise RuntimeError(
            "No Groq API key configured. Set one in System Settings → AI Integration "
            "or via the GROQ_API_KEY environment variable."
        )
    return key


def _sync_client() -> "_groq.Groq":
    return _groq.Groq(api_key=_resolve_groq_key())


def _async_client() -> "_groq.AsyncGroq":
    return _groq.AsyncGroq(api_key=_resolve_groq_key())


async def stream_completion(
    model: ActiveGroqModels,
    messages: list,
    temperature: float = 0.7,
    max_tokens: int = 512,
) -> AsyncIterator[str]:
    """
    Async generator — yields text chunks from a streaming Groq completion.

    Usage:
        async for chunk in stream_completion(ActiveGroqModels.FAST_STREAM_EMULATOR, msgs):
            websocket.send(chunk)

    The sliding-window limiter is checked before the request is dispatched.
    """
    model_id = model.value
    await _limiter.acquire(model_id)
    client = _async_client()
    try:
        stream = await client.chat.completions.create(
            model=model_id,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=True,
        )
        async for chunk in stream:
            delta = chunk.choices[0].delta.content
            if delta:
                yield delta
    except _groq.RateLimitError as exc:
        logger.warning("[Groq] Rate limit hit for %s: %s", model_id, exc)
        yield "\n[System: rate limit — retry in a moment]\n"
    except Exception as exc:
        logger.error("[Groq] Streaming error for %s: %s", model_id, exc)
        raise


async def complete(
    model: ActiveGroqModels,
    messages: list,
    temperature: float = 0.4,
    max_tokens: int = 2048,
) -> str:
    """
    Non-streaming async completion — returns the full text at once.
    Used by the heavy analytics path where the caller wants the full result
    before processing (log analysis, schema synthesis, patch generation).
    """
    model_id = model.value
    await _limiter.acquire(model_id)
    client = _async_client()
    try:
        resp = await client.chat.completions.create(
            model=model_id,
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stream=False,
        )
        return resp.choices[0].message.content or ""
    except _groq.RateLimitError as exc:
        logger.warning("[Groq] Rate limit hit for %s: %s", model_id, exc)
        raise
    except Exception as exc:
        logger.error("[Groq] Completion error for %s: %s", model_id, exc)
        raise


def complete_sync(
    model: ActiveGroqModels,
    messages: list,
    temperature: float = 0.4,
    max_tokens: int = 2048,
) -> str:
    """
    Synchronous wrapper for use in Django management commands, Celery tasks,
    or anywhere asyncio.run() is acceptable.
    """
    return asyncio.run(complete(model, messages, temperature, max_tokens))
