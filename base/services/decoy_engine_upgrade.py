"""
backend/base/services/decoy_engine_upgrade.py
===============================================
Shadow Copy Dynamic Schema Mirroring — upgrade patch for decoy_engine.py.

Two new capabilities:
  1. passive_schema_ingest(path, method, body_dict, target)
     Called by the universal proxy on every CLEAN (non-flagged) request that
     returns JSON.  Extracts only structural metadata (key name → Python type
     name) from the response body and upserts it into SchemaEndpointBlueprint.
     No real values are ever written; only shapes.

  2. generate_ai_decoy_response(path, method, schema_structure, target, site_profile)
     Called by generate_decoy_response() when a malicious session hits an
     endpoint for which we have a blueprint.  Sends the structural schema to
     HEAVY_ANALYTICS_BRAIN and streams back a realistic, entirely synthetic
     JSON body that fits the shape.  Attackers / fuzzers get endlessly looping
     fake data that looks real but is completely fabricated.

These functions are async-native to avoid blocking the proxy's request
handling loop.  They are designed to be called with asyncio.create_task()
so the core decoy-response path is never slowed down by DB writes or
AI round-trips.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from typing import Any, Dict, Optional

logger = logging.getLogger("genius_mirage.decoy_engine_upgrade")


# ─── Structural extraction ────────────────────────────────────────────────────

def _extract_structure(obj: Any, depth: int = 0) -> Dict[str, str]:
    """
    Recursively extract a JSON object's structure as {key: type_name}.
    Stops at depth 3 to avoid unbounded recursion on deeply nested responses.

    Example:
        {"id": 42, "user": {"name": "Alice", "active": true}, "tags": ["x"]}
      → {"id": "int", "user.name": "str", "user.active": "bool", "tags": "list"}
    """
    result = {}
    if depth > 3 or not isinstance(obj, dict):
        return result
    for k, v in obj.items():
        if not isinstance(k, str):
            continue
        if isinstance(v, dict):
            sub = _extract_structure(v, depth + 1)
            for sk, sv in sub.items():
                result[f"{k}.{sk}"] = sv
        elif isinstance(v, list):
            result[k] = "list"
        elif isinstance(v, bool):
            result[k] = "bool"
        elif isinstance(v, int):
            result[k] = "int"
        elif isinstance(v, float):
            result[k] = "float"
        else:
            result[k] = "str"
    return result


def passive_schema_ingest_sync(path: str, method: str, body: str, site_id: str) -> None:
    """
    Synchronous entry point called from the proxy's response-processing path.
    Extracts structural metadata from a clean JSON response and upserts it into
    SchemaEndpointBlueprint.  Called as fire-and-forget via threading.

    Only operates if the site has allow_schema_mirroring=True.
    """
    try:
        from base.models import DeceptionTarget, SchemaEndpointBlueprint, RegisteredSite
        site = RegisteredSite.objects.get(id=site_id)
        target = DeceptionTarget.objects.filter(site=site, allow_schema_mirroring=True).first()
        if not target:
            return

        try:
            parsed = json.loads(body) if isinstance(body, str) else body
        except (json.JSONDecodeError, TypeError):
            return

        if not isinstance(parsed, dict):
            return

        structure = _extract_structure(parsed)
        if not structure:
            return

        obj, created = SchemaEndpointBlueprint.objects.get_or_create(
            target=target,
            path=path[:512],
            method=method.upper(),
            defaults={"structure": structure, "sample_count": 1},
        )
        if not created:
            # Merge new keys; keep existing ones (schema should be additive)
            merged = {**obj.structure, **structure}
            obj.structure    = merged
            obj.sample_count = obj.sample_count + 1
            obj.save(update_fields=["structure", "sample_count", "last_seen"])

        logger.debug("[Schema] Upserted %s %s (%d keys)", method, path, len(structure))

    except Exception as exc:
        logger.debug("[Schema] Ingest error: %s", exc)


# ─── AI decoy generation ─────────────────────────────────────────────────────

_AI_DECOY_PROMPT = """\
You are a data synthesis engine for a cybersecurity deception platform.
You are given the structural schema of a real API endpoint response.
Generate a SINGLE realistic but entirely SYNTHETIC JSON object that fits the schema.

Rules:
- Every field must have a plausible-looking but completely fake value.
- Integer IDs should be realistic-looking 6-digit numbers.
- Strings should look like real data (names, emails, slugs) but be entirely fictitious.
- Do NOT include any personally identifiable information.
- Return ONLY the raw JSON object — no markdown, no explanation, no code fences.
- The output must be valid JSON.
"""


async def generate_ai_decoy_response(
    path: str,
    method: str,
    structure: Dict[str, str],
    fallback_body: str = "{}",
) -> str:
    """
    Call HEAVY_ANALYTICS_BRAIN to synthesize a realistic fake JSON response.
    Returns valid JSON string.  Falls back to fallback_body on any error.
    """
    if not structure:
        return fallback_body

    schema_desc = json.dumps(structure, indent=2)
    messages = [
        {"role": "system", "content": _AI_DECOY_PROMPT},
        {"role": "user",   "content": f"Endpoint: {method} {path}\nSchema:\n{schema_desc}"},
    ]

    try:
        from base.config.deception_client import ActiveGroqModels, complete
        raw = await complete(
            ActiveGroqModels.HEAVY_ANALYTICS_BRAIN,
            messages,
            temperature=0.8,
            max_tokens=512,
        )
        # Validate it's actually JSON before returning
        json.loads(raw)
        return raw
    except json.JSONDecodeError:
        logger.warning("[DecoyGen] AI returned non-JSON for %s %s — using fallback", method, path)
        return fallback_body
    except Exception as exc:
        logger.warning("[DecoyGen] AI error for %s %s: %s", method, path, exc)
        return fallback_body


async def get_ai_decoy_for_session(
    path: str,
    method: str,
    site_id: str,
) -> Optional[str]:
    """
    Lookup the schema blueprint for this endpoint on this site, then
    ask the AI to generate a matching fake response body.
    Returns None if no blueprint exists (fall through to static decoy).
    """
    try:
        from channels.db import database_sync_to_async
        from base.models import SchemaEndpointBlueprint, RegisteredSite, DeceptionTarget

        @database_sync_to_async
        def _lookup():
            try:
                site   = RegisteredSite.objects.get(id=site_id)
                target = DeceptionTarget.objects.get(site=site)
                bp     = SchemaEndpointBlueprint.objects.get(
                    target=target, path=path, method=method.upper()
                )
                return bp.structure
            except Exception:
                return None

        structure = await _lookup()
        if structure is None:
            return None

        return await generate_ai_decoy_response(path, method, structure)

    except Exception as exc:
        logger.debug("[DecoyGen] Lookup error: %s", exc)
        return None
