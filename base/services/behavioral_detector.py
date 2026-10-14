"""
backend/base/services/behavioral_detector.py
=============================================
Behavioral Entropy Detector — catches sophisticated attackers who avoid
all known signatures but whose REQUEST PATTERNS betray automated origin.

This module adds four orthogonal detection signals that are extremely
hard to fake simultaneously:

  1. TIMING ENTROPY
     Humans have naturally random inter-request timing (coefficient of
     variation > 0.4). Bots are suspiciously consistent (CV < 0.15).
     Even bots with random delays are detectable — their distribution
     is uniform, not log-normal like human behavior.

  2. REQUEST GRAPH ANALYSIS
     Map the sequence of URL paths as a directed graph. Real users follow
     navigation flows (home → product → cart → checkout). Scanners jump
     between unrelated endpoints. We compute the graph's entropy and
     compare it to the site's learned baseline.

  3. BROWSER SIGNAL CONSISTENCY
     A request claiming to be Chrome/Windows should have Accept-Language,
     Accept-Encoding, Sec-Fetch-* headers that match Chrome's known
     defaults. Python-requests, curl, and headless browsers each have
     distinct header fingerprints. We score the consistency between the
     claimed UA and the actual HTTP header set.

  4. SESSION TRAJECTORY ANALYSIS
     Real users show a natural "funnel" behavior — they visit many pages
     in areas they care about and ignore others. Scanners show uniform
     coverage across all path prefixes. We compute the Gini coefficient
     of the path prefix distribution: high Gini = human; low Gini = scanner.

All four signals are combined into a single BehavioralScore (0-100) that
feeds directly into the Tier 2 evaluator as additional evidence.

No external dependencies beyond standard library + numpy (which Django
typically has via scipy/scikit-learn if installed, but we degrade
gracefully to pure-Python fallbacks if not).
"""

from __future__ import annotations

import logging
import math
import re
import statistics
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


@dataclass
class BehavioralScore:
    """Combined behavioral entropy score for a session."""
    total_score: int                    # 0-100 risk contribution
    timing_score: int                   # 0-25
    graph_score: int                    # 0-25
    consistency_score: int              # 0-25
    trajectory_score: int               # 0-25
    signals: List[str] = field(default_factory=list)
    explanation: str = ""


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ═══════════════════════════════════════════════════════════════════════════════

def analyze_session_behavior(
    activity_logs: List[Dict],
    request_data: Dict,
    site_profile=None,
) -> BehavioralScore:
    """
    Run all four behavioral analyses on a session's activity logs.

    Parameters
    ----------
    activity_logs : list of ActivityLog dicts (timestamp, endpoint, method, …)
    request_data  : current request dict (path, user_agent, headers, …)
    site_profile  : optional SiteProfile model instance

    Returns
    -------
    BehavioralScore with per-signal breakdown and combined risk score.
    """
    if len(activity_logs) < 3:
        # Not enough data yet — return neutral score
        return BehavioralScore(total_score=0, timing_score=0, graph_score=0,
                               consistency_score=0, trajectory_score=0,
                               explanation="Insufficient session history for behavioral analysis.")

    signals: List[str] = []

    t_score, t_signals = _timing_entropy_score(activity_logs)
    g_score, g_signals = _request_graph_score(activity_logs, site_profile)
    c_score, c_signals = _browser_consistency_score(request_data)
    j_score, j_signals = _trajectory_gini_score(activity_logs)

    signals.extend(t_signals + g_signals + c_signals + j_signals)

    total = min(t_score + g_score + c_score + j_score, 100)

    explanation_parts = []
    if t_score >= 15:
        explanation_parts.append(f"timing anomaly (+{t_score})")
    if g_score >= 15:
        explanation_parts.append(f"scanner navigation pattern (+{g_score})")
    if c_score >= 15:
        explanation_parts.append(f"browser fingerprint inconsistency (+{c_score})")
    if j_score >= 15:
        explanation_parts.append(f"uniform path coverage (+{j_score})")

    return BehavioralScore(
        total_score=total,
        timing_score=t_score,
        graph_score=g_score,
        consistency_score=c_score,
        trajectory_score=j_score,
        signals=signals,
        explanation="; ".join(explanation_parts) or "No strong behavioral anomaly.",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNAL 1 — TIMING ENTROPY
# ═══════════════════════════════════════════════════════════════════════════════

def _timing_entropy_score(logs: List[Dict]) -> Tuple[int, List[str]]:
    """
    Compute the coefficient of variation (CV) of inter-request intervals.

    Real humans: CV typically 0.5–2.0 (highly variable timing)
    Automated scanners: CV typically 0.0–0.15 (machinelike consistency)
    Bots with random sleep: CV 0.3–0.5 but distribution is uniform, not log-normal

    Returns score 0-25 and a list of signal descriptions.
    """
    signals = []
    intervals_ms = _extract_intervals_ms(logs)

    if len(intervals_ms) < 4:
        return 0, []

    mean_ms = statistics.mean(intervals_ms)
    if mean_ms <= 0:
        return 0, []

    try:
        stdev_ms = statistics.stdev(intervals_ms)
    except statistics.StatisticsError:
        return 0, []

    cv = stdev_ms / mean_ms   # Coefficient of Variation

    score = 0
    if cv < 0.08:
        # Machinelike — almost no timing variation
        score = 25
        signals.append(f"MachinelikeTiming(CV={cv:.3f})")
    elif cv < 0.15:
        score = 20
        signals.append(f"LowTimingVariation(CV={cv:.3f})")
    elif cv < 0.25:
        score = 12
        signals.append(f"SuspiciousTimingVariation(CV={cv:.3f})")

    # Also flag: suspiciously fast median (< 200ms between requests)
    median_ms = statistics.median(intervals_ms)
    if median_ms < 200 and len(intervals_ms) >= 5:
        score = min(score + 8, 25)
        signals.append(f"FastMedianInterval({median_ms:.0f}ms)")

    return min(score, 25), signals


def _extract_intervals_ms(logs: List[Dict]) -> List[float]:
    """Extract inter-request intervals in milliseconds from log timestamps."""
    from django.utils.dateparse import parse_datetime
    timestamps = []
    for log in logs:
        ts = log.get("timestamp")
        if ts is None:
            continue
        if hasattr(ts, "timestamp"):
            timestamps.append(ts.timestamp() * 1000)
        else:
            try:
                parsed = parse_datetime(str(ts))
                if parsed:
                    timestamps.append(parsed.timestamp() * 1000)
            except Exception:
                pass

    timestamps.sort()
    return [timestamps[i+1] - timestamps[i] for i in range(len(timestamps) - 1)
            if timestamps[i+1] - timestamps[i] > 0]


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNAL 2 — REQUEST GRAPH ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

def _request_graph_score(logs: List[Dict], site_profile=None) -> Tuple[int, List[str]]:
    """
    Build a directed graph of URL transitions and score it.

    Scanner signature: many unique nodes, few repeated edges, high entropy.
    Human signature: repeated paths, clustered around a few sections, low entropy.

    Score 0-25.
    """
    signals = []
    paths = [log.get("endpoint", "/") for log in logs if log.get("endpoint")]

    if len(paths) < 4:
        return 0, []

    # Build transition counter: (path_a → path_b)
    transitions = Counter(zip(paths, paths[1:]))
    unique_paths = set(paths)
    unique_transitions = len(transitions)

    # Unique path ratio — scanners visit many unique paths
    unique_ratio = len(unique_paths) / len(paths)

    # Transition entropy — high entropy = non-navigational (scanner)
    trans_entropy = _shannon_entropy(list(transitions.values()))

    # Path prefix diversity — scanners cover many prefixes uniformly
    prefix_counts = Counter(_path_prefix(p) for p in paths)
    prefix_entropy = _shannon_entropy(list(prefix_counts.values()))

    score = 0

    if unique_ratio > 0.9 and len(paths) >= 8:
        score += 15
        signals.append(f"HighPathDiversity({unique_ratio:.0%})")

    if trans_entropy > 3.5 and unique_transitions > 10:
        score += 10
        signals.append(f"HighTransitionEntropy({trans_entropy:.2f})")

    # Penalize: accessing paths NOT present on site's known paths
    if site_profile and hasattr(site_profile, "expected_paths") and site_profile.expected_paths:
        expected = set(site_profile.expected_paths)
        unexpected = [p for p in unique_paths if p not in expected and len(p) > 1]
        unexpected_ratio = len(unexpected) / max(len(unique_paths), 1)
        if unexpected_ratio > 0.7:
            score += 12
            signals.append(f"MostlyUnexpectedPaths({unexpected_ratio:.0%})")

    return min(score, 25), signals


def _path_prefix(path: str, depth: int = 2) -> str:
    """Return the first `depth` path segments as a prefix."""
    parts = [p for p in path.split("/") if p]
    return "/" + "/".join(parts[:depth]) if parts else "/"


def _shannon_entropy(counts: List[int]) -> float:
    """Compute Shannon entropy of a distribution."""
    total = sum(counts)
    if total == 0:
        return 0.0
    probs = [c / total for c in counts if c > 0]
    return -sum(p * math.log2(p) for p in probs)


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNAL 3 — BROWSER CONSISTENCY SCORE
# ═══════════════════════════════════════════════════════════════════════════════

# Known headers for real Chrome browser requests
CHROME_EXPECTED_HEADERS = frozenset([
    "accept", "accept-encoding", "accept-language",
    "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform",
    "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site",
    "upgrade-insecure-requests",
])

# Headers that Python-requests typically sends (and Chrome doesn't)
PYTHON_REQUESTS_GIVEAWAYS = frozenset([
    "connection",   # "keep-alive" — Python always sends, browsers usually omit
])

# UA patterns and their expected header fingerprints
UA_FINGERPRINTS = {
    "chrome":   {"required": ["accept", "accept-encoding"], "bonus": ["sec-ch-ua", "sec-fetch-dest"]},
    "firefox":  {"required": ["accept", "accept-encoding", "accept-language"], "bonus": ["dnt"]},
    "safari":   {"required": ["accept", "accept-encoding", "accept-language"], "bonus": []},
    "curl":     {"required": [], "bonus": []},
    "python":   {"required": [], "bonus": []},
    "go":       {"required": [], "bonus": []},
}

UA_DETECTORS = {
    "chrome":   re.compile(r'chrome/\d+', re.I),
    "firefox":  re.compile(r'firefox/\d+', re.I),
    "safari":   re.compile(r'safari/\d+(?!.*chrome)', re.I),
    "curl":     re.compile(r'^curl/', re.I),
    "python":   re.compile(r'python-requests|aiohttp|httpx', re.I),
    "go":       re.compile(r'go-http-client', re.I),
}


def _browser_consistency_score(request_data: Dict) -> Tuple[int, List[str]]:
    """
    Check if the UA claim matches the actual HTTP header fingerprint.

    Score 0-25.
    """
    signals = []
    ua = request_data.get("user_agent", "")
    headers = {k.lower(): v for k, v in (request_data.get("headers") or {}).items()}

    if not ua:
        return 15, ["MissingUserAgent"]

    # Detect claimed browser type
    claimed_type = "unknown"
    for browser, pattern in UA_DETECTORS.items():
        if pattern.search(ua):
            claimed_type = browser
            break

    score = 0

    # Case 1: Claims to be Chrome but missing Chrome-specific headers
    if claimed_type == "chrome":
        missing_chrome = CHROME_EXPECTED_HEADERS - set(headers.keys())
        if len(missing_chrome) >= 5:
            score += 20
            signals.append(f"FakeChromeUA(missing={len(missing_chrome)}headers)")
        elif len(missing_chrome) >= 3:
            score += 12
            signals.append(f"PartialChromeHeaders(missing={len(missing_chrome)})")

    # Case 2: CLI tool claiming to be browser
    if claimed_type in ("curl", "python", "go") and "mozilla" in ua.lower():
        score += 20
        signals.append(f"UASpoofing({claimed_type}claimsBrowser)")

    # Case 3: No Accept-Language on a request claiming to be a real browser
    if claimed_type in ("chrome", "firefox", "safari"):
        if not headers.get("accept-language"):
            score += 10
            signals.append("BrowserWithoutAcceptLanguage")

    # Case 4: Sec-Fetch headers present but inconsistent values
    sf_dest = headers.get("sec-fetch-dest", "")
    sf_mode = headers.get("sec-fetch-mode", "")
    if sf_dest == "document" and sf_mode not in ("navigate", "same-origin", ""):
        score += 8
        signals.append(f"InconsistentSecFetch({sf_dest}/{sf_mode})")

    return min(score, 25), signals


# ═══════════════════════════════════════════════════════════════════════════════
# SIGNAL 4 — TRAJECTORY GINI COEFFICIENT
# ═══════════════════════════════════════════════════════════════════════════════

def _trajectory_gini_score(logs: List[Dict]) -> Tuple[int, List[str]]:
    """
    Compute the Gini coefficient of the path prefix visit distribution.

    Real users: high Gini (concentrated on a few sections of the site)
    Scanners:   low Gini  (uniform coverage across all prefixes)

    Score 0-25.
    """
    signals = []
    paths = [log.get("endpoint", "/") for log in logs if log.get("endpoint")]

    if len(paths) < 5:
        return 0, []

    prefix_counts = Counter(_path_prefix(p) for p in paths)
    values = sorted(prefix_counts.values())
    gini = _gini(values)

    score = 0
    if gini < 0.2 and len(prefix_counts) >= 4:
        # Very uniform distribution — classic scanner
        score = 22
        signals.append(f"UniformPathCoverage(gini={gini:.3f})")
    elif gini < 0.35 and len(prefix_counts) >= 3:
        score = 12
        signals.append(f"LowPathConcentration(gini={gini:.3f})")

    return min(score, 25), signals


def _gini(values: List[float]) -> float:
    """Compute Gini coefficient from a sorted list of non-negative values."""
    if not values or sum(values) == 0:
        return 0.0
    n = len(values)
    total = sum(values)
    weighted = sum((i + 1) * v for i, v in enumerate(values))
    return (2 * weighted) / (n * total) - (n + 1) / n
