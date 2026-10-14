"""
services/code_scanner.py  (NEW — "Automated Pentester" feature)
=================================================================
Static, pattern-based source review of an uploaded codebase zip —
the same category of tool as Semgrep, Bandit, or CodeQL: it reads
code, it does not run it, exploit it, or touch any live system.
It reproduces (in automated form) the manual review process used to
find the issues in this project's own backend: grep for dangerous
patterns, check auth/permission coverage, flag missing verification
on payment-webhook-shaped endpoints, flag hardcoded secrets, etc.

SAFETY / SCOPE
--------------
- Read-only: never executes, imports, or evals anything from the
  uploaded code.
- Zip-slip and zip-bomb protected (path traversal blocked, total
  extracted size and file count capped).
- Extraction happens in an isolated temp directory that is always
  removed after the scan, even on error.
- Findings are pattern-based signals for a human to review, not a
  guarantee of exploitability or of completeness — same caveat any
  SAST tool ships with. The report says so explicitly.
- This module only ever READS files off disk. It never contacts any
  external host that isn't the caller's own platform.
"""

from __future__ import annotations

import os
import re
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from typing import List

MAX_UNCOMPRESSED_BYTES = 300 * 1024 * 1024   # 300 MB cap — zip-bomb guard
MAX_FILE_COUNT = 20_000
MAX_SINGLE_FILE_BYTES = 5 * 1024 * 1024      # skip individual files over 5MB (binaries, bundles)

SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.jsx', '.ts', '.tsx', '.java', '.kt', '.go', '.rb', '.php',
    '.env', '.yml', '.yaml', '.json', '.toml', '.ini', '.cfg', '.txt',
}

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


@dataclass
class Finding:
    rule_id: str
    severity: str            # critical | high | medium | low | info
    title: str
    file: str
    line: int
    snippet: str
    description: str
    recommendation: str


@dataclass
class ScanReport:
    findings: List[Finding] = field(default_factory=list)
    files_scanned: int = 0
    truncated: bool = False
    errors: List[str] = field(default_factory=list)

    def sorted_findings(self) -> List[Finding]:
        return sorted(self.findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.file, f.line))

    def to_dict(self) -> dict:
        return {
            'files_scanned': self.files_scanned,
            'truncated': self.truncated,
            'errors': self.errors,
            'summary': {
                sev: len([f for f in self.findings if f.severity == sev])
                for sev in ('critical', 'high', 'medium', 'low', 'info')
            },
            'findings': [
                {
                    'index': i,  # stable reference for this scan's result — used by the remediation API
                    'rule_id': f.rule_id, 'severity': f.severity, 'title': f.title,
                    'file': f.file, 'line': f.line, 'snippet': f.snippet,
                    'description': f.description, 'recommendation': f.recommendation,
                }
                for i, f in enumerate(self.sorted_findings())
            ],
        }


class UnsafeZipError(Exception):
    pass


def _safe_extract(zip_path: str, dest_dir: str) -> None:
    """Extract with zip-slip and zip-bomb protection."""
    total_size = 0
    file_count = 0
    with zipfile.ZipFile(zip_path) as zf:
        for info in zf.infolist():
            file_count += 1
            if file_count > MAX_FILE_COUNT:
                raise UnsafeZipError(f"Archive has more than {MAX_FILE_COUNT} entries — refusing to extract.")

            total_size += info.file_size
            if total_size > MAX_UNCOMPRESSED_BYTES:
                raise UnsafeZipError("Archive exceeds the uncompressed size cap — refusing to extract (possible zip bomb).")

            # Zip-slip guard: resolve the target path and make sure it's
            # still inside dest_dir before writing anything.
            target_path = os.path.normpath(os.path.join(dest_dir, info.filename))
            if not target_path.startswith(os.path.abspath(dest_dir) + os.sep) and target_path != os.path.abspath(dest_dir):
                raise UnsafeZipError(f"Unsafe path in archive: {info.filename}")

        zf.extractall(dest_dir)  # safe now — we validated every entry above


# ── Rule implementations ──────────────────────────────────────────────────
# Each rule takes (file_path, relative_path, text) and yields Finding.

def _rule_hardcoded_secrets(rel_path, text):
    patterns = [
        (r'(SECRET_KEY|API_KEY|CLIENT_SECRET|CONSUMER_SECRET|PASSWORD|PASSKEY|ACCESS_TOKEN)\s*=\s*["\'][A-Za-z0-9+/_\-]{10,}["\']',
         'Hardcoded secret-looking value assigned directly in source'),
        (r'AKIA[0-9A-Z]{16}', 'AWS access key ID literal'),
        (r'-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----', 'Embedded private key'),
    ]
    for pat, desc in patterns:
        for m in re.finditer(pat, text):
            line = text.count('\n', 0, m.start()) + 1
            yield Finding(
                rule_id='SEC-SECRET-001', severity='high', title='Hardcoded secret in source',
                file=rel_path, line=line, snippet=m.group(0)[:80],
                description=desc,
                recommendation='Move to an environment variable / secrets manager; rotate the value if this has ever been committed to a shared repo.',
            )


def _line_at(text, pos):
    return text.count('\n', 0, pos) + 1


def _snippet_for_line(text, line):
    lines = text.splitlines()
    return lines[line - 1].strip()[:120] if 0 <= line - 1 < len(lines) else ''


def _rule_dangerous_functions(rel_path, text):
    patterns = [
        (r'\beval\s*\(', 'eval() on any input that could be user-influenced enables arbitrary code execution'),
        (r'\bexec\s*\(', 'exec() carries the same risk as eval()'),
        (r'\bpickle\.loads?\s*\(', 'pickle.load(s) on untrusted data enables arbitrary code execution on deserialization'),
    ]
    for pat, desc in patterns:
        for m in re.finditer(pat, text):
            line = _line_at(text, m.start())
            yield Finding(
                rule_id='SEC-DANGEROUS-FN-001', severity='high', title='Use of a dangerous function',
                file=rel_path, line=line, snippet=_snippet_for_line(text, line) or m.group(0),
                description=desc,
                recommendation='Confirm no user-controlled data reaches this call. Prefer ast.literal_eval, json, or explicit allowlists instead.',
            )


def _rule_sql_injection(rel_path, text):
    """
    Two passes, both aimed at the same thing — a SQL string whose text was
    built with string concatenation/f-strings/%/`.format()` instead of
    parameterized placeholders — which is how SQL injection almost always
    actually looks in real code, in any framework (Flask, Django raw SQL,
    plain sqlite3/psycopg2/MySQLdb, etc.), not just Django's `.raw()`.

    Pass 1 (direct): the dangerous construction happens inline inside the
    execute(...) call itself.
    Pass 2 (indirect): a variable is built with a dangerous construction
    earlier in the file and passed into execute(...) by name later — the
    much more common real-world shape (build the query, then run it).
    """
    exec_fns = r'(?:cursor\s*\.\s*)?execute\s*\('
    sql_kw = r'(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|SET)\b'

    # Pass 1 — dangerous construction written directly inside execute(...)
    direct_pat = (
        rf'{exec_fns}\s*('
        rf'f["\'][^"\']*{sql_kw}[^"\']*["\']'              # execute(f"...SELECT...")
        rf'|["\'][^"\']*{sql_kw}[^"\']*["\']\s*\+'          # execute("...SELECT..." + x)
        rf'|["\'][^"\']*{sql_kw}[^"\']*["\']\s*%'           # execute("...SELECT..." % x)
        rf'|["\'][^"\']*{sql_kw}[^"\']*["\']\s*\.\s*format\(' # execute("...SELECT...".format(x))
        rf')'
    )
    for m in re.finditer(direct_pat, text, re.IGNORECASE):
        line = _line_at(text, m.start())
        yield Finding(
            rule_id='SEC-SQLI-001', severity='critical', title='SQL Injection — query built with string concatenation/formatting',
            file=rel_path, line=line, snippet=_snippet_for_line(text, line),
            description=(
                'This SQL query is assembled with an f-string, +, %, or .format() directly inside the '
                'execute() call rather than using parameterized placeholders. If any part of that string '
                'comes from a request (path param, query string, form field, header, cookie), this is '
                'classic SQL injection — an attacker can alter the query logic itself (e.g. '
                "id=1 OR 1=1 or id=1; DROP TABLE ...)."
            ),
            recommendation=(
                "Use parameterized queries instead: cursor.execute(\"SELECT * FROM products WHERE id = ?\", (id,)) "
                "(sqlite3/MySQLdb use ?/%s placeholders; never interpolate values into the SQL string yourself)."
            ),
        )

    # Pass 2 — a variable built dangerously earlier, executed by name later
    assign_pat = (
        rf'(\w+)\s*=\s*('
        rf'f["\'][^"\']*{sql_kw}[^"\']*["\']'
        rf'|["\'][^"\']*{sql_kw}[^"\']*["\']\s*\+'
        rf'|["\'][^"\']*{sql_kw}[^"\']*["\']\s*%'
        rf'|["\'][^"\']*{sql_kw}[^"\']*["\']\s*\.\s*format\('
        rf')'
    )
    for m in re.finditer(assign_pat, text, re.IGNORECASE):
        var_name = m.group(1)
        assign_line = _line_at(text, m.start())
        # Look for execute(var_name anywhere after the assignment (same file)
        use_pat = re.compile(rf'{exec_fns}\s*{re.escape(var_name)}\b')
        use_m = use_pat.search(text, m.end())
        if use_m:
            use_line = _line_at(text, use_m.start())
            yield Finding(
                rule_id='SEC-SQLI-002', severity='critical',
                title=f'SQL Injection — "{var_name}" built with string concatenation/formatting, then executed',
                file=rel_path, line=assign_line, snippet=_snippet_for_line(text, assign_line),
                description=(
                    f'"{var_name}" is built using an f-string, +, %, or .format() on line {assign_line}, then '
                    f'passed to execute() on line {use_line}. If any part of "{var_name}" comes from user '
                    'input, this is SQL injection — the same risk as building the string inline, just one '
                    'step removed.'
                ),
                recommendation='Build the query with parameterized placeholders (?, %s) and pass values as a separate tuple/list argument to execute(), never interpolated into the string.',
            )


def _rule_command_injection(rel_path, text):
    patterns = [
        (r'\bos\.system\s*\(\s*["\']?[^)]*[+%]|\bos\.system\s*\(\s*f["\']',
         'os.system() with concatenated/formatted input enables command injection'),
        (r'\bos\.popen\s*\(',
         'os.popen() always runs through the shell — any part of its argument built from a variable, '
         'concatenation, or an f-string is command injection if that data is user-influenced'),
        (r'\bsubprocess\.(call|run|Popen)\([^)]*shell\s*=\s*True',
         'subprocess with shell=True is command-injection prone if any argument includes user input'),
    ]
    for pat, desc in patterns:
        for m in re.finditer(pat, text):
            line = _line_at(text, m.start())
            yield Finding(
                rule_id='SEC-CMDI-001', severity='critical', title='Command Injection — shell call with dynamic input',
                file=rel_path, line=line, snippet=_snippet_for_line(text, line) or m.group(0),
                description=desc,
                recommendation='Avoid the shell entirely: use subprocess.run([...], shell=False) with a literal argument list (no string concatenation), and validate/allowlist any user-supplied values that must be included.',
            )


def _rule_ssti(rel_path, text):
    """Server-Side Template Injection — rendering user-controlled text as a template body, not just as data into one."""
    patterns = [
        (r'\brender_template_string\s*\(\s*(?!["\'])',
         'render_template_string() called with something other than a plain string literal — if that argument is user input (a message, a name, a search term), this is SSTI: Jinja2 will execute template syntax ({{ }}) inside it, not just display it as text'),
        (r'\bTemplate\s*\(\s*(?!["\'])[^)]*\)\s*\.\s*render\s*\(',
         'jinja2.Template()/django.template.Template() constructed from a non-literal value and rendered — same SSTI risk as render_template_string() if the template source itself comes from user input'),
    ]
    for pat, desc in patterns:
        for m in re.finditer(pat, text):
            line = _line_at(text, m.start())
            yield Finding(
                rule_id='SEC-SSTI-001', severity='critical', title='Server-Side Template Injection (SSTI)',
                file=rel_path, line=line, snippet=_snippet_for_line(text, line),
                description=desc,
                recommendation='Never pass user input as the template source. Use render_template() with a fixed template file and pass user data only as context variables (e.g. render_template("preview.html", message=msg)), where it\'s auto-escaped as data, not parsed as template syntax.',
            )


def _rule_path_traversal(rel_path, text):
    """A file-serving/opening call whose path is built dynamically (concatenation/f-string/os.path.join
    with a variable) rather than a fixed literal — the classic ../../../etc/passwd shape."""
    patterns = [
        (r'\bsend_file\s*\(\s*(?!["\'][^"\')]*["\']\s*\))',
         'send_file() with a dynamically-built path — if the variable portion comes from a request parameter, "../" sequences can escape the intended directory'),
        (r'\bsend_from_directory\s*\([^,]+,\s*(?!["\'])',
         'send_from_directory() second argument is dynamic — confirm it cannot contain "../" path traversal sequences before this point'),
        (r'\bopen\s*\(\s*[^)]*\+[^)]*\)',
         'open() called with a concatenated path — if any part comes from user input, this can read/write outside the intended directory via "../" sequences'),
    ]
    for pat, desc in patterns:
        for m in re.finditer(pat, text):
            line = _line_at(text, m.start())
            yield Finding(
                rule_id='SEC-PATHTRAVERSAL-001', severity='high', title='Possible Path Traversal',
                file=rel_path, line=line, snippet=_snippet_for_line(text, line),
                description=desc,
                recommendation='Resolve the final path with os.path.realpath() and verify it is still inside the intended base directory before opening it, and/or strip path separators and ".." from the input, and/or use werkzeug.utils.secure_filename() for filenames.',
            )


def _rule_plaintext_password_compare(rel_path, text):
    # Line-based rather than a single tight regex: the "password" token and
    # the "==" can appear in either order on the line (`pw == input` or
    # `input == record['password']`), so match on co-occurrence within one
    # line rather than a strict left-of/right-of pattern.
    for lineno, raw_line in enumerate(text.splitlines(), start=1):
        if '==' not in raw_line:
            continue
        if not re.search(r'\b(password|pwd)\b', raw_line, re.IGNORECASE):
            continue
        snippet = raw_line.strip()[:120]
        if re.search(r'hash|bcrypt|argon2|pbkdf2|check_password|verify|scrypt', snippet, re.IGNORECASE):
            continue
        if re.search(r'==\s*(True|False|None|\'\'|"")', snippet):
            continue
        line = lineno
        yield Finding(
            rule_id='SEC-AUTH-001', severity='critical', title='Plaintext password comparison',
            file=rel_path, line=line, snippet=snippet,
            description='Password appears to be compared with == directly rather than through a hashing/verification function. This implies passwords are stored or compared in plaintext, and the comparison itself is also vulnerable to timing attacks.',
            recommendation='Store password hashes (bcrypt/argon2/PBKDF2) and compare using the library\'s constant-time verify function (e.g. bcrypt.checkpw(), werkzeug.security.check_password_hash()) — never ==.',
        )


def _rule_idor_candidate(rel_path, text):
    """
    Heuristic only, flagged as such: a route whose path takes an id-like
    parameter, whose handler does a lookup, but whose body contains no
    token suggesting an ownership/auth check. This cannot know whether a
    check happens in a decorator or middleware it can't see — it's a
    pointer for human review, not a confirmed finding.
    """
    ownership_tokens = re.compile(r'current_user|request\.user|session\[|login_required|@login_required|owner|user_id\s*==|\.user\s*==')
    lookup_tokens = re.compile(r'\.get\(|\.query\(|\.filter\(|_get_|db_get|SELECT|fetchone|fetchall', re.IGNORECASE)

    for m in re.finditer(r'@app\.route\s*\(\s*["\'][^"\']*<[^>]*(id|pk)[^>]*>[^"\']*["\'][^)]*\)\s*\n\s*def\s+(\w+)\s*\([^)]*\)\s*:', text, re.IGNORECASE):
        func_start = m.end()
        next_def = re.search(r'\n@app\.route|\ndef\s+\w+\s*\(', text[func_start:])
        block_end = func_start + next_def.start() if next_def else min(func_start + 800, len(text))
        block = text[func_start:block_end]
        if lookup_tokens.search(block) and not ownership_tokens.search(block):
            line = _line_at(text, m.start())
            yield Finding(
                rule_id='SEC-IDOR-CANDIDATE-001', severity='medium',
                title=f'Possible IDOR — route "{m.group(2)}" takes an id parameter with no visible ownership check',
                file=rel_path, line=line, snippet=_snippet_for_line(text, line),
                description=(
                    'This route accepts an id-like path parameter and performs a lookup, but the handler body '
                    'has no visible reference to the current user/session/login check. If a check happens in a '
                    'decorator or shared middleware this scanner can\'t see, this is a false positive — but if '
                    'not, any authenticated (or anonymous) user can view/act on any id by changing it in the URL.'
                ),
                recommendation='Verify the requested object actually belongs to the requesting user before returning/acting on it (e.g. WHERE id = %s AND user_id = %s, not just WHERE id = %s).',
            )


def _rule_unauthenticated_webhook(rel_path, text):
    """
    Heuristic for the exact class of bug found in this project: a view
    with permission_classes = [] / authentication_classes = [] that also
    reads an amount/status field straight out of the request body and
    uses it in what looks like a finalize/credit/complete call — i.e. a
    payment- or status-callback endpoint trusting its own input.
    """
    if not re.search(r'permission_classes\s*=\s*\[\s*\]', text):
        return
    if not re.search(r'authentication_classes\s*=\s*\[\s*\]', text):
        return
    # Look for a body-derived amount/result used near a finalize/credit call
    window = text
    trust_pattern = re.search(r'request\.data(\.get)?\([^)]*(amount|Amount|result|Result|status|Status)', window)
    finalize_pattern = re.search(r'(credit|finalize|complete|approve|clear)\w*\s*\(', window, re.IGNORECASE)
    if trust_pattern and finalize_pattern:
        line = text.count('\n', 0, trust_pattern.start()) + 1
        yield Finding(
            rule_id='SEC-WEBHOOK-001', severity='critical',
            title='Possible unauthenticated payment/status webhook trusting client input',
            file=rel_path, line=line,
            snippet=text.splitlines()[line-1].strip()[:120] if line-1 < len(text.splitlines()) else '',
            description=(
                'This view has no authentication/permission checks AND appears to read an '
                'amount/result/status field from the request body that flows into what looks '
                'like a finalize/credit/complete call. If this is a payment gateway callback '
                '(M-Pesa, PayPal, Stripe, etc.), anyone who can guess or obtain a valid reference '
                'ID may be able to forge this callback and trigger the finalize action without a '
                'real payment.'
            ),
            recommendation=(
                'Never trust ResultCode/Amount/status fields from the callback body. Use the '
                'callback only as a signal to re-verify server-side via the gateway\'s own status/'
                'query API using your own credentials, and act on that authoritative response '
                'instead. Add IP allowlisting for the gateway\'s published callback IP range as a '
                'second layer. Manual review of this specific finding is strongly recommended — '
                'this is a heuristic match, not a certainty.'
            ),
        )


def _rule_permissive_cors_or_hosts(rel_path, text):
    checks = [
        (r'ALLOWED_HOSTS\s*=\s*\[?\s*["\']?\*["\']?', 'ALLOWED_HOSTS permits any Host header'),
        (r'CORS_ALLOW_ALL_ORIGINS\s*=\s*True', 'CORS is open to any origin'),
        (r'X_FRAME_OPTIONS\s*=\s*["\']ALLOWALL["\']', 'Clickjacking protection disabled (X_FRAME_OPTIONS=ALLOWALL)'),
        (r'DEBUG\s*=\s*True\b(?!.*os\.environ)', 'DEBUG hardcoded True — verbose error pages may leak internals if this ships to prod'),
        (r"DEFAULT_PERMISSION_CLASSES['\"]?\s*:\s*\[?\s*['\"]rest_framework\.permissions\.AllowAny", 'Global DRF default permission is AllowAny — every view is open unless it overrides this explicitly'),
    ]
    for pat, desc in checks:
        for m in re.finditer(pat, text):
            line = text.count('\n', 0, m.start()) + 1
            yield Finding(
                rule_id='SEC-CONFIG-001', severity='medium', title='Permissive security configuration',
                file=rel_path, line=line, snippet=m.group(0)[:100],
                description=desc,
                recommendation='Set this from an environment variable with a safe default, and verify every view explicitly sets its own permission_classes if the global default is AllowAny.',
            )


def _rule_ip_trust(rel_path, text):
    pat = r"X_FORWARDED_FOR['\"]?\)?\s*\.split\(['\"],['\"]\)\[0\]|X-Forwarded-For.{0,40}split\(','\)\[0\]"
    for m in re.finditer(pat, text):
        line = text.count('\n', 0, m.start()) + 1
        yield Finding(
            rule_id='SEC-IPTRUST-001', severity='medium', title='Client-controlled header trusted for IP-based logic',
            file=rel_path, line=line, snippet=text.splitlines()[line-1].strip()[:100] if line-1 < len(text.splitlines()) else '',
            description='Taking the first entry of X-Forwarded-For trusts a value the client can set directly, which can defeat IP-based rate limiting or audit logging.',
            recommendation='Trust only the hop your own reverse proxy appended (typically the LAST entry for a single-proxy deployment), not the first.',
        )


def _rule_insecure_mobile_storage(rel_path, text):
    if not re.search(r'AsyncStorage', text):
        return
    if re.search(r'(token|jwt|auth|secret|password|session)', text, re.IGNORECASE):
        for m in re.finditer(r'AsyncStorage\.setItem\([^)]*', text, re.IGNORECASE):
            line = text.count('\n', 0, m.start()) + 1
            yield Finding(
                rule_id='SEC-MOBILE-STORAGE-001', severity='medium',
                title='Sensitive value possibly stored in unencrypted AsyncStorage',
                file=rel_path, line=line, snippet=m.group(0)[:100],
                description='React Native AsyncStorage is unencrypted plaintext on disk. Auth tokens/credentials stored this way are readable by anyone with filesystem access to a rooted/jailbroken device or a backup.',
                recommendation='Use expo-secure-store (iOS Keychain / Android Keystore) for tokens and credentials instead.',
            )


def _rule_missing_drf_permission(rel_path, text):
    if 'APIView' not in text and 'ViewSet' not in text and 'generics.' not in text:
        return
    for m in re.finditer(r'^class\s+(\w+)\s*\((?:[^)]*\b(?:APIView|ViewSet|generics\.\w+)\b[^)]*)\)\s*:', text, re.MULTILINE):
        class_start = m.start()
        next_class = re.search(r'^class\s+\w+\s*\(', text[m.end():], re.MULTILINE)
        block_end = m.end() + next_class.start() if next_class else min(m.end() + 1500, len(text))
        block = text[class_start:block_end]
        if 'permission_classes' not in block:
            line = text.count('\n', 0, class_start) + 1
            yield Finding(
                rule_id='SEC-DRF-PERM-001', severity='medium',
                title=f'DRF view "{m.group(1)}" has no explicit permission_classes',
                file=rel_path, line=line, snippet=m.group(0)[:100],
                description='Without an explicit permission_classes, this view falls back to your DRF DEFAULT_PERMISSION_CLASSES setting — if that default is AllowAny, this endpoint is silently public.',
                recommendation='Set permission_classes explicitly on every view rather than relying on a global default.',
            )


_RULES = [
    _rule_hardcoded_secrets,
    _rule_dangerous_functions,
    _rule_sql_injection,
    _rule_command_injection,
    _rule_ssti,
    _rule_path_traversal,
    _rule_plaintext_password_compare,
    _rule_idor_candidate,
    _rule_unauthenticated_webhook,
    _rule_permissive_cors_or_hosts,
    _rule_ip_trust,
    _rule_insecure_mobile_storage,
    _rule_missing_drf_permission,
]


def scan_zip(zip_path: str, persist_to: str | None = None) -> ScanReport:
    """
    Extract `zip_path` into an isolated temp dir, run every rule over every
    scannable text file, and return a ScanReport.

    If `persist_to` is given, the extracted tree is moved there on success
    instead of being deleted — this is what lets remediation later read the
    actual full file content for a finding (a one-line snippet isn't enough
    to generate a safe, context-aware fix). `persist_to` must not already
    exist. On any failure, nothing is persisted and the temp dir is still
    cleaned up as before.
    """
    report = ScanReport()
    tmp_dir = tempfile.mkdtemp(prefix='gm_codescan_')
    try:
        try:
            _safe_extract(zip_path, tmp_dir)
        except UnsafeZipError as exc:
            report.errors.append(str(exc))
            return report
        except zipfile.BadZipFile:
            report.errors.append("Not a valid zip file.")
            return report

        for root, _dirs, files in os.walk(tmp_dir):
            for name in files:
                ext = os.path.splitext(name)[1].lower()
                if ext not in SCANNABLE_EXTENSIONS:
                    continue
                full_path = os.path.join(root, name)
                try:
                    if os.path.getsize(full_path) > MAX_SINGLE_FILE_BYTES:
                        continue
                    with open(full_path, 'r', encoding='utf-8', errors='ignore') as fh:
                        text = fh.read()
                except OSError as exc:
                    report.errors.append(f"Could not read {name}: {exc}")
                    continue

                rel_path = os.path.relpath(full_path, tmp_dir)
                report.files_scanned += 1
                for rule in _RULES:
                    try:
                        for finding in rule(rel_path, text):
                            report.findings.append(finding)
                    except Exception as exc:  # a single bad rule/file must never kill the whole scan
                        report.errors.append(f"Rule {rule.__name__} failed on {rel_path}: {exc}")

                if report.files_scanned >= MAX_FILE_COUNT:
                    report.truncated = True
                    return report

        if report.files_scanned == 0:
            report.errors.append(
                "No scannable source files were found in this archive (looked for "
                f"{', '.join(sorted(SCANNABLE_EXTENSIONS))}). This usually means the zip only "
                "contains binaries/assets, has an unexpected internal structure, or is empty — "
                "not that the scan itself failed."
            )

        if persist_to:
            os.makedirs(os.path.dirname(persist_to) or '.', exist_ok=True)
            if os.path.exists(persist_to):
                shutil.rmtree(persist_to, ignore_errors=True)
            shutil.move(tmp_dir, persist_to)
            tmp_dir = None  # already moved — don't also delete it in `finally`

        return report
    finally:
        if tmp_dir:
            shutil.rmtree(tmp_dir, ignore_errors=True)
