"""
backend/base/services/remediation_engine.py
============================================
Background AI-powered log analysis and defensive patch generation.

Pipeline:
  1. A site owner enables `allow_automated_remediation_analysis` on their
     DeceptionTarget (the consent gate).
  2. run_remediation_for_target(target_id) is called — from a management
     command, Celery beat, or on-demand via the dashboard.
  3. The engine collects the site's recent ActivityLog records and optionally
     any uploaded log files (Cowrie, nginx, etc.).
  4. The HEAVY_ANALYTICS_BRAIN analyses the log array and returns a
     structured Defensive Blueprint containing:
       - Identified attack signatures and posture weaknesses
       - Deployable Django/Python code snippets to remediate each weakness
  5. A StrategicDefenseBlueprint record is saved (status='pending_review').
     Nothing is automatically deployed — a human operator reviews and applies.

Supports both async (await run_remediation_for_target()) and sync
(run_remediation_for_target_sync()) entry points.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
from typing import Dict, List, Optional

logger = logging.getLogger("genius_mirage.remediation_engine")


# ─── AI Prompt Templates ─────────────────────────────────────────────────────

_LOG_ANALYSIS_SYSTEM = """\
You are a senior application security analyst for an enterprise cybersecurity platform.
You will receive an array of HTTP request/activity log entries from a web application.
Your task is to:
  1. Identify attack techniques present in the log array (SQLi, XSS, SSTI, Path Traversal,
     Command Injection, Credential Stuffing, IDOR, etc.). Be precise — distinguish
     command injection (;whoami, `id`, $(cmd)) from SQL injection (UNION SELECT).
  2. Identify security posture weaknesses in the application that these logs reveal.
  3. Generate practical, deployable Django/Python defensive code snippets to remediate
     each weakness.

CRITICAL RULES for code generation:
- All generated code must be DEFENSIVE only — input validation, output encoding,
  rate limiting, parameterised queries, etc.
- Never generate offensive or test payloads.
- Code snippets must be safe to copy into a production Django app.
- Replace any potentially destructive action with a safe diagnostic echo.

Return your analysis as valid JSON in exactly this structure:
{
  "weakness_summary": "Plain English summary of what you found",
  "attack_signatures": ["list of identified technique names"],
  "posture_gaps": [
    {
      "gap": "Description of the vulnerability",
      "evidence": "Which log entries demonstrated this",
      "patch_snippet": "# Django/Python code to fix this\\n..."
    }
  ],
  "consolidated_patch": "# Complete combined remediation snippet\\n..."
}
Return ONLY the JSON object. No markdown. No explanation outside the JSON.
"""


# ─── Log Formatters ──────────────────────────────────────────────────────────

def _format_activity_logs(logs: list) -> str:
    """Format ActivityLog queryset values into a condensed log array string."""
    lines = []
    for entry in logs[:200]:  # Cap at 200 entries for token safety
        ts     = str(entry.get("timestamp", ""))[:19]
        method = entry.get("method", "GET")
        ep     = entry.get("endpoint", "/")[:100]
        ua     = str(entry.get("user_agent", ""))[:60]
        score  = entry.get("suspicion_score", 0)
        flagged = "FLAGGED" if entry.get("flagged") else "clean"
        lines.append(f"[{ts}] {method} {ep} | UA: {ua} | score={score} | {flagged}")
    return "\n".join(lines)


def _format_cowrie_logs(raw: str) -> str:
    """
    Extract relevant fields from Cowrie JSON log lines.
    Cowrie is a common SSH honeypot — this engine can ingest its output.
    """
    relevant = []
    for line in raw.splitlines()[:200]:
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
            event = record.get("eventid", "")
            src   = record.get("src_ip", "")
            ts    = str(record.get("timestamp", ""))[:19]
            if "command" in event:
                cmd = record.get("input", "")
                relevant.append(f"[{ts}] SSH_CMD src={src} cmd={cmd!r}")
            elif "login" in event:
                user = record.get("username", "")
                pwd  = record.get("password", "")[:4] + "***"
                relevant.append(f"[{ts}] SSH_LOGIN src={src} user={user!r} pass={pwd}")
            elif "download" in event:
                url = record.get("url", "")
                relevant.append(f"[{ts}] SSH_DOWNLOAD src={src} url={url}")
        except json.JSONDecodeError:
            # Plain-text log line — include as-is
            if len(line) < 300:
                relevant.append(line)
    return "\n".join(relevant)


# ─── Core Engine ─────────────────────────────────────────────────────────────

async def run_remediation_for_target(
    target_id: int,
    uploaded_log_content: Optional[str] = None,
) -> Optional[str]:
    """
    Main async entry point.  Returns the blueprint ID if successful, else None.

    Args:
        target_id:             DeceptionTarget PK.
        uploaded_log_content:  Optional raw string content from an uploaded
                               external log file (Cowrie, nginx, etc.).
    """
    from channels.db import database_sync_to_async

    # ── 1. Load target and check consent ─────────────────────────────────
    @database_sync_to_async
    def _load_target():
        from base.models import DeceptionTarget
        try:
            return DeceptionTarget.objects.select_related("site").get(pk=target_id)
        except DeceptionTarget.DoesNotExist:
            return None

    target = await _load_target()
    if target is None:
        logger.error("[Remediation] Target %s not found", target_id)
        return None

    if not target.allow_automated_remediation_analysis:
        logger.warning("[Remediation] Consent not granted for target %s — aborting", target_id)
        return None

    logger.info("[Remediation] Starting analysis for %s", target.site.domain)

    # ── 2. Collect activity logs ──────────────────────────────────────────
    @database_sync_to_async
    def _fetch_logs():
        from base.models import ActivityLog
        return list(
            ActivityLog.objects.filter(site=target.site)
            .order_by("-timestamp")[:200]
            .values("timestamp", "method", "endpoint", "user_agent",
                    "suspicion_score", "flagged", "status_code")
        )

    logs = await _fetch_logs()
    log_text = _format_activity_logs(logs)

    # ── 3. Process any uploaded external log file ─────────────────────────
    external_log_text = ""
    if uploaded_log_content:
        # Try Cowrie JSON format first, fall back to plain text
        if uploaded_log_content.lstrip().startswith("{"):
            external_log_text = _format_cowrie_logs(uploaded_log_content)
        else:
            external_log_text = uploaded_log_content[:8000]

    # ── 4. Build the combined log payload ────────────────────────────────
    combined = f"=== Application Telemetry Logs ===\n{log_text}"
    if external_log_text:
        combined += f"\n\n=== External Honeypot Logs ===\n{external_log_text}"

    if not log_text.strip() and not external_log_text.strip():
        logger.info("[Remediation] No log data available for %s — skipping", target.site.domain)
        return None

    # ── 5. AI analysis ────────────────────────────────────────────────────
    messages = [
        {"role": "system", "content": _LOG_ANALYSIS_SYSTEM},
        {"role": "user",   "content": f"Site: {target.site.domain}\n\nLOG DATA:\n{combined[:12000]}"},
    ]

    try:
        from base.config.deception_client import ActiveGroqModels, complete
        raw_response = await complete(
            ActiveGroqModels.HEAVY_ANALYTICS_BRAIN,
            messages,
            temperature=0.3,
            max_tokens=3000,
        )
    except Exception as exc:
        logger.error("[Remediation] Groq call failed for %s: %s", target.site.domain, exc)
        return None

    # ── 6. Parse AI response ──────────────────────────────────────────────
    try:
        # Strip markdown code fences if the model added them despite instructions
        cleaned = re.sub(r"```(?:json)?\n?", "", raw_response).strip().rstrip("`")
        analysis = json.loads(cleaned)
    except json.JSONDecodeError:
        logger.error("[Remediation] Non-JSON response for %s:\n%s", target.site.domain, raw_response[:500])
        return None

    weakness_summary = analysis.get("weakness_summary", "No summary provided.")
    attack_sigs      = analysis.get("attack_signatures", [])
    posture_gaps     = analysis.get("posture_gaps", [])
    consolidated     = analysis.get("consolidated_patch", "")

    # ── 7. Build patch code string ────────────────────────────────────────
    patch_sections = []
    for gap in posture_gaps:
        snippet = gap.get("patch_snippet", "")
        if snippet:
            title = gap.get("gap", "Unnamed gap")
            patch_sections.append(f"# === {title} ===\n{snippet}")
    if consolidated:
        patch_sections.append(f"# === Consolidated Remediation ===\n{consolidated}")
    patch_code = "\n\n".join(patch_sections) or "# No actionable patches generated."

    # ── 8. Save blueprint ─────────────────────────────────────────────────
    @database_sync_to_async
    def _save_blueprint():
        from base.models import StrategicDefenseBlueprint, DeceptionTarget as DT
        from django.utils import timezone
        bp = StrategicDefenseBlueprint.objects.create(
            target           = target,
            triggered_by     = attack_sigs,
            weakness_summary = weakness_summary,
            patch_code       = patch_code,
            model_used       = ActiveGroqModels.HEAVY_ANALYTICS_BRAIN.value,
        )
        target.last_analysis = timezone.now()
        target.save(update_fields=["last_analysis"])
        return bp.id

    from base.config.deception_client import ActiveGroqModels
    blueprint_id = await _save_blueprint()
    logger.info("[Remediation] Blueprint %s created for %s", blueprint_id, target.site.domain)
    return blueprint_id


def run_remediation_for_target_sync(
    target_id: int,
    uploaded_log_content: Optional[str] = None,
) -> Optional[str]:
    """Synchronous wrapper for Django management commands or Celery tasks."""
    return asyncio.run(run_remediation_for_target(target_id, uploaded_log_content))
