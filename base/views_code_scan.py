"""
base/views_code_scan.py  (NEW — "Automated Pentester" feature)
=================================================================
Lets a user upload a zip of their own codebase and get back a static
security report — the automated equivalent of the manual code review
process, using services/code_scanner.py.

Consent gate: a scan will not run unless the request explicitly
includes `user_consented: true` AND a `consent_statement` naming the
codebase the user is attesting they own or are authorized to test.
This is intentionally NOT a checkbox that defaults to checked — the
serializer requires the field.

Everything else (auth, ownership check against the site, synchronous
scan for now — see note below) mirrors the patterns already used
elsewhere in this app.
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile

from django.conf import settings
from django.http import FileResponse
from django.utils import timezone
from rest_framework import status
from rest_framework.parsers import MultiPartParser
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import CodeScan, RegisteredSite, RemediationSuggestion
from .services.code_scanner import scan_zip
from .services.code_remediation import generate_fix, apply_suggestion, RemediationError

logger = logging.getLogger(__name__)

REQUIRED_CONSENT_TEXT_MIN_LENGTH = 10  # just enough to stop an empty/whitespace "consent"
MAX_UPLOAD_BYTES = 100 * 1024 * 1024   # 100 MB — matches typical source-only zip sizes; raise if needed

# Where persisted scan source trees live, so remediation can read full file
# content later. Separate from Django's MEDIA_ROOT on purpose — this is
# working storage for an internal feature, not user-facing media.
CODESCAN_STORAGE_ROOT = os.path.join(settings.BASE_DIR, 'codescan_storage')


class CodeScanUploadView(APIView):
    """
    POST /api/pentester/scan/

    multipart/form-data:
        file               — the zip to scan (required)
        site_id            — RegisteredSite this scan is associated with (required)
        user_consented     — must be the literal boolean true (required)
        consent_statement  — free text, e.g. "I own/am authorized to test this codebase" (required)

    Runs synchronously and returns the full report in the response. For
    very large codebases you may want to move `scan_zip()` onto a task
    queue (Celery, etc.) and have this endpoint just enqueue + return a
    scan id — the CodeScan model already supports that (status field),
    this view just doesn't do it yet to keep the first version simple.
    """
    permission_classes = [IsAuthenticated]
    parser_classes = [MultiPartParser]

    def post(self, request):
        uploaded_file = request.FILES.get('file')
        site_id = request.data.get('site_id', '')
        user_consented = request.data.get('user_consented')
        consent_statement = (request.data.get('consent_statement') or '').strip()

        if not uploaded_file:
            return Response({"error": "No file uploaded."}, status=status.HTTP_400_BAD_REQUEST)

        if uploaded_file.size == 0:
            return Response(
                {"error": "The uploaded file is 0 bytes — it didn't actually arrive with any content. "
                          "Re-select the file and try again (this usually means the browser/file picker "
                          "didn't attach the file data, not that the scan failed)."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if not uploaded_file.name.lower().endswith('.zip'):
            return Response({"error": "Only .zip archives are accepted."}, status=status.HTTP_400_BAD_REQUEST)

        if uploaded_file.size > MAX_UPLOAD_BYTES:
            return Response(
                {"error": f"File exceeds the {MAX_UPLOAD_BYTES // (1024*1024)}MB upload limit."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        # ── Hard consent gate — this is not optional, and it's checked for
        # the actual boolean/string true, not just "truthy" ──────────────
        consented = str(user_consented).strip().lower() in ('true', '1')
        if not consented or len(consent_statement) < REQUIRED_CONSENT_TEXT_MIN_LENGTH:
            return Response(
                {
                    "error": (
                        "Scanning requires explicit consent. Set user_consented=true and provide a "
                        "consent_statement confirming you own this codebase or are otherwise authorized "
                        "to test it (e.g. \"I am the owner/maintainer of this codebase and authorize "
                        "this static security scan.\")."
                    )
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        site = None
        if site_id:
            try:
                site = RegisteredSite.objects.get(id=site_id)
            except RegisteredSite.DoesNotExist:
                return Response({"error": "Unknown site_id."}, status=status.HTTP_404_NOT_FOUND)
            # Ownership check — mirrors the pattern used elsewhere for
            # site-scoped resources: you can only scan code you're
            # attaching to a site you actually own.
            if site.owner_user_id and site.owner_user_id != request.user.id and not getattr(request.user, 'is_admin_user', False):
                return Response({"error": "You do not have access to this site."}, status=status.HTTP_403_FORBIDDEN)

        scan = CodeScan.objects.create(
            site=site,
            uploaded_by=request.user,
            original_filename=uploaded_file.name,
            file_size_bytes=uploaded_file.size,
            user_consented=True,
            consent_statement=consent_statement,
            status='running',
        )

        try:
            with tempfile.NamedTemporaryFile(suffix='.zip') as tmp:
                for chunk in uploaded_file.chunks():
                    tmp.write(chunk)
                tmp.flush()
                source_path = os.path.join(CODESCAN_STORAGE_ROOT, str(scan.id))
                report = scan_zip(tmp.name, persist_to=source_path)

            scan.result_json = report.to_dict()
            scan.status = 'completed'
            scan.completed_at = timezone.now()
            scan.source_path = source_path
            scan.save(update_fields=['result_json', 'status', 'completed_at', 'source_path'])

        except Exception as exc:
            logger.exception("Code scan failed for CodeScan id=%s", scan.id)
            scan.status = 'failed'
            scan.error_message = str(exc)
            scan.save(update_fields=['status', 'error_message'])
            return Response(
                {"error": "Scan failed to complete.", "detail": str(exc), "scan_id": scan.id},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        return Response({
            "scan_id": scan.id,
            "status": scan.status,
            "report": scan.result_json,
        })


class CodeScanDetailView(APIView):
    """GET /api/pentester/scan/<id>/ — retrieve a previous scan's report."""
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        try:
            scan = CodeScan.objects.get(id=scan_id)
        except CodeScan.DoesNotExist:
            return Response({"error": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        if scan.uploaded_by_id != request.user.id and not getattr(request.user, 'is_admin_user', False):
            return Response({"error": "You do not have access to this scan."}, status=status.HTTP_403_FORBIDDEN)

        return Response({
            "scan_id": scan.id,
            "status": scan.status,
            "original_filename": scan.original_filename,
            "created_at": scan.created_at,
            "completed_at": scan.completed_at,
            "error_message": scan.error_message,
            "report": scan.result_json,
        })


class CodeScanListView(APIView):
    """GET /api/pentester/scans/ — list the current user's past scans (no report bodies, for a history list)."""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        scans = CodeScan.objects.filter(uploaded_by=request.user).order_by('-created_at')[:50]
        return Response([
            {
                "scan_id": s.id,
                "original_filename": s.original_filename,
                "status": s.status,
                "created_at": s.created_at,
                "completed_at": s.completed_at,
                "summary": (s.result_json or {}).get('summary', {}),
            }
            for s in scans
        ])


def _get_owned_scan(request, scan_id):
    """Shared ownership check for every remediation endpoint below."""
    try:
        scan = CodeScan.objects.get(id=scan_id)
    except CodeScan.DoesNotExist:
        return None, Response({"error": "Scan not found."}, status=status.HTTP_404_NOT_FOUND)
    if scan.uploaded_by_id != request.user.id and not getattr(request.user, 'is_admin_user', False):
        return None, Response({"error": "You do not have access to this scan."}, status=status.HTTP_403_FORBIDDEN)
    return scan, None


def _serialize_suggestion(s: RemediationSuggestion) -> dict:
    return {
        "suggestion_id": s.id,
        "scan_id": s.scan_id,
        "rule_id": s.rule_id,
        "file": s.file,
        "line": s.line,
        "finding_title": s.finding_title,
        "status": s.status,
        "diff_text": s.diff_text,
        "explanation": s.explanation,
        "error_message": s.error_message,
        "created_at": s.created_at,
        "decided_at": s.decided_at,
    }


class RemediationGenerateView(APIView):
    """
    POST /api/pentester/scan/<scan_id>/findings/<finding_index>/remediate/

    Generates (or regenerates) an AI-proposed fix for one finding and
    returns it as a diff. This ONLY generates — nothing is written to the
    scan's source tree until RemediationApproveView is called explicitly.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, scan_id, finding_index):
        scan, err = _get_owned_scan(request, scan_id)
        if err:
            return err

        findings = (scan.result_json or {}).get('findings', [])
        finding = next((f for f in findings if f.get('index') == finding_index), None)
        if finding is None:
            return Response({"error": f"No finding with index {finding_index} in this scan."}, status=status.HTTP_404_NOT_FOUND)

        try:
            result = generate_fix(scan, finding, requested_by=request.user)
        except RemediationError as exc:
            return Response({"error": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as exc:
            logger.exception("Unexpected error generating remediation for scan=%s finding=%s", scan_id, finding_index)
            return Response({"error": f"Unexpected error generating the fix: {exc}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        suggestion = RemediationSuggestion.objects.create(
            scan=scan, requested_by=request.user,
            rule_id=finding['rule_id'], file=finding['file'], line=finding['line'],
            finding_title=finding.get('title', ''),
            status=result['status'],
            original_content=result['original_content'],
            proposed_content=result['proposed_content'],
            diff_text=result['diff_text'],
            explanation=result['explanation'],
            error_message=result['error_message'],
        )

        if result['status'] == 'failed':
            return Response(_serialize_suggestion(suggestion), status=status.HTTP_200_OK)
        return Response(_serialize_suggestion(suggestion))


class RemediationApproveView(APIView):
    """
    POST /api/pentester/remediation/<suggestion_id>/approve/

    The ONLY endpoint that writes a fix to the scan's persisted source
    tree. Requires the suggestion to currently be 'pending' — approving
    twice, or approving a rejected/failed suggestion, is refused.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, suggestion_id):
        try:
            suggestion = RemediationSuggestion.objects.select_related('scan').get(id=suggestion_id)
        except RemediationSuggestion.DoesNotExist:
            return Response({"error": "Suggestion not found."}, status=status.HTTP_404_NOT_FOUND)

        scan = suggestion.scan
        if scan.uploaded_by_id != request.user.id and not getattr(request.user, 'is_admin_user', False):
            return Response({"error": "You do not have access to this suggestion."}, status=status.HTTP_403_FORBIDDEN)

        if suggestion.status != 'pending':
            return Response({"error": f"This suggestion is '{suggestion.status}', not pending — nothing to approve."}, status=status.HTTP_400_BAD_REQUEST)

        try:
            apply_suggestion(scan, suggestion)
        except RemediationError as exc:
            return Response({"error": f"Could not apply fix: {exc}"}, status=status.HTTP_400_BAD_REQUEST)

        suggestion.status = 'approved'
        suggestion.decided_at = timezone.now()
        suggestion.save(update_fields=['status', 'decided_at'])
        return Response(_serialize_suggestion(suggestion))


class RemediationRejectView(APIView):
    """POST /api/pentester/remediation/<suggestion_id>/reject/ — discards the suggestion, no file is touched."""
    permission_classes = [IsAuthenticated]

    def post(self, request, suggestion_id):
        try:
            suggestion = RemediationSuggestion.objects.select_related('scan').get(id=suggestion_id)
        except RemediationSuggestion.DoesNotExist:
            return Response({"error": "Suggestion not found."}, status=status.HTTP_404_NOT_FOUND)

        if suggestion.scan.uploaded_by_id != request.user.id and not getattr(request.user, 'is_admin_user', False):
            return Response({"error": "You do not have access to this suggestion."}, status=status.HTTP_403_FORBIDDEN)

        if suggestion.status != 'pending':
            return Response({"error": f"This suggestion is already '{suggestion.status}'."}, status=status.HTTP_400_BAD_REQUEST)

        suggestion.status = 'rejected'
        suggestion.decided_at = timezone.now()
        suggestion.save(update_fields=['status', 'decided_at'])
        return Response(_serialize_suggestion(suggestion))


class RemediationListView(APIView):
    """GET /api/pentester/scan/<scan_id>/remediations/ — every suggestion generated for this scan so far."""
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        scan, err = _get_owned_scan(request, scan_id)
        if err:
            return err
        suggestions = scan.remediations.all()
        return Response([_serialize_suggestion(s) for s in suggestions])


class CodeScanDownloadView(APIView):
    """
    GET /api/pentester/scan/<scan_id>/download/

    Zips up the scan's persisted source tree AS IT CURRENTLY STANDS —
    including any approved fixes already applied — and returns it for
    download. 404s if the scan's source was never persisted or has since
    been cleaned up.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        scan, err = _get_owned_scan(request, scan_id)
        if err:
            return err
        if not scan.source_path or not os.path.isdir(scan.source_path):
            return Response({"error": "This scan's source is no longer available to download."}, status=status.HTTP_404_NOT_FOUND)

        base_name = os.path.join(tempfile.gettempdir(), f'codescan_{scan.id}_remediated')
        archive_path = shutil.make_archive(base_name, 'zip', scan.source_path)
        filename = f"{os.path.splitext(scan.original_filename)[0]}_remediated.zip"
        return FileResponse(open(archive_path, 'rb'), as_attachment=True, filename=filename)
