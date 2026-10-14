"""
services/code_remediation.py  (NEW)
=================================================================
Generates a fix for one specific Automated Pentester finding, as a diff
for the user to review — never applied automatically. This is a distinct
feature from services/remediation_engine.py, which analyzes live attack
logs against a DeceptionTarget and proposes a defensive blueprint; this
module instead edits a specific file from a CodeScan to close one static
finding, and is scoped to exactly that.

Pipeline
--------
1. Read the finding's full original file content from the scan's
   persisted source tree (CodeScan.source_path) — not just its one-line
   snippet, which isn't enough context to produce a safe fix.
2. Ask the currently-configured AI provider (Groq or OpenAI — whichever
   System Settings → AI Integration has active; see
   global_ai_analyzer._groq_client/_current_model, reused here so
   switching providers in the admin panel also changes what generates
   fixes) for the smallest possible change that closes the specific
   finding, with an explicit instruction to touch nothing else and keep
   the file importable/syntactically valid.
3. Compute a unified diff between the original and proposed content.
4. Return everything for human review. Nothing is written to disk here —
   see views_code_scan.py's RemediationApproveView for the only place
   that actually writes a file, and only on explicit approval.

Safety notes
------------
- The model is told to return strict JSON so the response can't smuggle
  prose/markdown fences into the file content.
- The proposed content is validated before being offered for approval:
  for .py files, it must at least parse as valid Python (ast.parse) — a
  fix that doesn't parse is rejected outright rather than shown as if it
  were safe to approve.
- A heuristic size-sanity check rejects a "fix" that deletes most of the
  file (a classic failure mode: the model rewrites everything instead of
  making a minimal change) rather than silently proposing something that
  would wipe out unrelated code.
"""

from __future__ import annotations

import ast
import difflib
import json
import logging
import os

logger = logging.getLogger(__name__)

MAX_FILE_BYTES_FOR_REMEDIATION = 200_000  # skip absurdly large files rather than blow the context window


class RemediationError(Exception):
    pass


def _read_source_file(scan_source_path: str, rel_file: str) -> str:
    full_path = os.path.normpath(os.path.join(scan_source_path, rel_file))
    # Guard against the finding's file path escaping the scan's own source dir
    if not full_path.startswith(os.path.abspath(scan_source_path) + os.sep):
        raise RemediationError("Invalid file path for this scan.")
    if not os.path.isfile(full_path):
        raise RemediationError(f"Source file not found: {rel_file} (was this scan's source cleaned up?)")
    if os.path.getsize(full_path) > MAX_FILE_BYTES_FOR_REMEDIATION:
        raise RemediationError(f"{rel_file} is too large to remediate automatically ({os.path.getsize(full_path):,} bytes).")
    with open(full_path, 'r', encoding='utf-8', errors='ignore') as fh:
        return fh.read()


def _write_source_file(scan_source_path: str, rel_file: str, content: str) -> None:
    full_path = os.path.normpath(os.path.join(scan_source_path, rel_file))
    if not full_path.startswith(os.path.abspath(scan_source_path) + os.sep):
        raise RemediationError("Invalid file path for this scan.")
    with open(full_path, 'w', encoding='utf-8') as fh:
        fh.write(content)


def _build_diff(original: str, proposed: str, rel_file: str) -> str:
    return ''.join(difflib.unified_diff(
        original.splitlines(keepends=True),
        proposed.splitlines(keepends=True),
        fromfile=f'a/{rel_file}', tofile=f'b/{rel_file}',
    ))


def _sanity_check(original: str, proposed: str, rel_file: str) -> str | None:
    """Returns an error message if the proposed fix looks unsafe to offer, else None."""
    if not proposed.strip():
        return "The proposed fix is empty — refusing to offer a change that would wipe the file."

    orig_lines = len(original.splitlines())
    new_lines = len(proposed.splitlines())
    if orig_lines > 5 and new_lines < orig_lines * 0.4:
        return (
            f"The proposed fix removes most of the file ({orig_lines} lines → {new_lines} lines), "
            "which looks like a rewrite rather than a targeted fix — refusing to offer it as safe to approve."
        )

    if rel_file.endswith('.py'):
        try:
            ast.parse(proposed)
        except SyntaxError as exc:
            return f"The proposed fix doesn't parse as valid Python ({exc}) — refusing to offer a change that would break the file."

    return None


def generate_fix(scan, finding: dict, requested_by=None) -> dict:
    """
    scan: a CodeScan instance (must have source_path set).
    finding: one finding dict from scan.result_json['findings'], i.e. has
        'rule_id', 'file', 'line', 'title', 'description', 'recommendation', 'snippet'.
    Returns a dict ready to save onto a RemediationSuggestion:
        {status, original_content, proposed_content, diff_text, explanation, error_message}
    Raises RemediationError for problems that should surface as a 4xx to the caller
    (missing source, file too large, etc.) — AI/parsing failures are instead
    returned with status='failed' so the attempt is still recorded.
    """
    if not scan.source_path:
        raise RemediationError("This scan's source was not persisted (scan may predate the remediation feature, or failed) — re-run the scan to enable remediation.")

    rel_file = finding['file']
    original = _read_source_file(scan.source_path, rel_file)

    from .global_ai_analyzer import _groq_client, _current_model
    try:
        client = _groq_client()
    except RuntimeError as exc:  # raised by _groq_client() when no API key is configured
        return {
            'status': 'failed', 'original_content': original, 'proposed_content': '',
            'diff_text': '', 'explanation': '', 'error_message': str(exc),
        }

    system_prompt = (
        "You are a careful security engineer fixing exactly one reported vulnerability in a file. "
        "Rules, all mandatory:\n"
        "1. Make the SMALLEST possible change that closes the specific vulnerability described. "
        "Never rewrite, reformat, reorganize, or 'improve' unrelated code, comments, or whitespace.\n"
        "2. The file must remain fully functional — same function/class names, same public behavior "
        "for everything not related to the vulnerability, same imports unless the fix genuinely requires a new one.\n"
        "3. Output strict JSON only, no markdown fences, no prose outside the JSON, matching exactly:\n"
        '   {"fixed_code": "<the COMPLETE file content after the fix, as a single string>", '
        '"explanation": "<2-4 sentences on exactly what you changed and why it closes the vulnerability>"}\n'
        "4. fixed_code must be the ENTIRE file, not a snippet or diff — every line of the original that "
        "isn't part of the fix must appear in fixed_code unchanged."
    )
    user_prompt = (
        f"Vulnerability: {finding.get('title', finding['rule_id'])}\n"
        f"Rule: {finding['rule_id']}\n"
        f"File: {rel_file}\n"
        f"Reported at line: {finding.get('line')}\n"
        f"Description: {finding.get('description', '')}\n"
        f"Recommended fix approach: {finding.get('recommendation', '')}\n\n"
        f"Full current file content:\n```\n{original}\n```"
    )

    try:
        completion = client.chat.completions.create(
            model=_current_model(),
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=0.1,
            max_tokens=8000,
            timeout=60,
        )
        raw = (completion.choices[0].message.content or '').strip()
        # Strip accidental markdown fences even though the prompt forbids them —
        # models sometimes add them anyway.
        if raw.startswith('```'):
            raw = raw.strip('`')
            if raw.lower().startswith('json'):
                raw = raw[4:]
        parsed = json.loads(raw)
        proposed = parsed['fixed_code']
        explanation = parsed.get('explanation', '').strip()
    except Exception as exc:
        logger.warning("Remediation generation failed for %s:%s (%s): %s", rel_file, finding.get('line'), finding['rule_id'], exc)
        return {
            'status': 'failed', 'original_content': original, 'proposed_content': '',
            'diff_text': '', 'explanation': '', 'error_message': f'AI did not return a usable fix: {exc}',
        }

    sanity_error = _sanity_check(original, proposed, rel_file)
    if sanity_error:
        return {
            'status': 'failed', 'original_content': original, 'proposed_content': proposed,
            'diff_text': _build_diff(original, proposed, rel_file), 'explanation': explanation,
            'error_message': sanity_error,
        }

    if proposed == original:
        return {
            'status': 'failed', 'original_content': original, 'proposed_content': proposed,
            'diff_text': '', 'explanation': explanation,
            'error_message': 'The AI returned the file unchanged — it may not have been able to identify a safe fix for this finding.',
        }

    return {
        'status': 'pending', 'original_content': original, 'proposed_content': proposed,
        'diff_text': _build_diff(original, proposed, rel_file), 'explanation': explanation,
        'error_message': '',
    }


def apply_suggestion(scan, suggestion) -> None:
    """Writes proposed_content to the persisted source tree. Called ONLY on
    explicit user approval (views_code_scan.py's RemediationApproveView) —
    never from generate_fix()."""
    _write_source_file(scan.source_path, suggestion.file, suggestion.proposed_content)
