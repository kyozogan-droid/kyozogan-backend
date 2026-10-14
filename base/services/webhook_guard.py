"""
services/webhook_guard.py  (NEW)
=================================================================
Payment-webhook forgery detection.

WHY THIS EXISTS
---------------
Tier 1/2 (threat_evaluator.py) catch attacker *behavior*: scanning,
injection payloads, known tool signatures, machine-speed traffic. They
have nothing to say about a single, perfectly ordinary-looking POST
request to a payment callback URL (e.g. an M-Pesa/PayPal webhook) made
by a legitimate, logged-in user, in a real browser or a plain HTTP
client — because nothing about that *one request* looks anomalous in
isolation.

That's exactly the shape of a "forged webhook" attack: the attacker
first calls the site's own "initiate payment" endpoint (as themselves,
completely legitimately) to obtain a real reference/checkout ID, then
POSTs directly to the webhook URL the site was going to use to receive
Safaricom's/PayPal's real callback, supplying whatever amount/result
they want. If the receiving endpoint has no signature or IP verification
(the actual root-cause fix — see below), it credits money or clears a
debt that was never really paid.

This module adds two signals that ARE visible even for a single,
otherwise-clean-looking request to a *declared webhook path*:

  WH-01/02  Browser fingerprint on a path that should only ever be hit
            server-to-server. Real payment-gateway servers (Safaricom,
            PayPal, Stripe, etc.) never send Sec-Fetch-*/Sec-Ch-Ua
            headers or a Mozilla/Chrome/Safari User-Agent — those only
            come from an actual browser or a client pretending to be one.

  WH-03     Traffic correlation: the same source IP that just called a
            *declared payment-initiate path* on this site calls the
            *declared webhook path* directly, within a short window.
            A real gateway's callback comes from the gateway's own
            servers, never from the same IP that just initiated the
            payment as a customer.

None of this requires knowing Safaricom's/PayPal's actual server IP
ranges (nice, because that list is real, gateway-specific, changes over
time, and you may not have it yet) — it works purely from traffic shape.
If you DO have a confirmed list of your payment gateway's egress IPs,
add WEBHOOK_TRUSTED_IPS below for a stronger, IP-allowlist-based signal
on top of this (recommended as the strongest control once available).

IMPORTANT — this is a compensating control, not a replacement fix
-------------------------------------------------------------------
This makes it much harder to forge a webhook *unnoticed*, and routes
attempts to the decoy/deception path instead of the real one. But the
underlying application bug — trusting the callback body's `Amount`
without verifying the request's authenticity (HMAC signature, IP
allowlist, or a server-initiated re-poll via query_stk_status()/
equivalent) — should still be fixed in the client app itself. Treat
this as defense-in-depth on top of that fix, not instead of it.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Tuple

from django.core.cache import cache

logger = logging.getLogger(__name__)

# Real payment-gateway server callbacks never carry these — they're
# added by browsers (and by fetch()/XHR from a page), never by a
# server-to-server HTTP client library.
_BROWSER_FINGERPRINT_HEADERS = (
    'Sec-Fetch-Site', 'Sec-Fetch-Mode', 'Sec-Fetch-Dest', 'Sec-Fetch-User',
    'Sec-Ch-Ua', 'Sec-Ch-Ua-Mobile', 'Sec-Ch-Ua-Platform',
)

_BROWSER_UA = re.compile(r'(Mozilla|Chrome/|Safari/|Firefox/|Edg/|OPR/)', re.IGNORECASE)

# Populate once you have a confirmed, current IP range from your gateway
# (Safaricom Daraja support, PayPal's published webhook IPs, etc.). Left
# empty by default — WH-04 simply won't fire until you fill this in.
# Example: {'site-abc123': {'196.201.214.0/24', '196.201.213.0/24'}}
WEBHOOK_TRUSTED_IPS: Dict[str, set] = {}

_INITIATE_CACHE_TTL = 600  # 10 minutes — generous enough to cover a slow attacker,
                           # short enough not to false-positive on unrelated later traffic


def mark_payment_initiate(ip: str, site_id: str) -> None:
    """
    Call this whenever a request hits a *declared payment-initiate path*
    (see django_sdk.py's GENIUS_MIRAGE_PAYMENT_INITIATE_PATHS). Records
    that this IP legitimately started a payment, so a follow-up direct
    hit on the webhook path from the SAME ip can be correlated.
    """
    if not ip or ip == '0.0.0.0' or not site_id:
        return
    cache.set(f'gm_wh_initiate:{site_id}:{ip}', True, timeout=_INITIATE_CACHE_TTL)


def check_webhook_forgery(request_data: Dict, ip: str, site_id: str) -> Tuple[bool, List[str]]:
    """
    Call this only for requests to a *declared webhook path*
    (request_data['is_webhook_path'] is True). Returns (triggered, reasons).
    """
    if not request_data.get('is_webhook_path'):
        return False, []

    triggers: List[str] = []
    headers = request_data.get('headers') or {}
    ua = request_data.get('user_agent', '') or headers.get('User-Agent', '')

    present_fingerprints = [h for h in _BROWSER_FINGERPRINT_HEADERS if h in headers]
    if present_fingerprints:
        triggers.append(
            "WH-01: Browser fingerprint headers ("
            + ", ".join(present_fingerprints)
            + ") present on a payment-webhook path — real gateway servers never send these"
        )

    if ua and _BROWSER_UA.search(ua):
        triggers.append(f"WH-02: Browser User-Agent on a payment-webhook path — {ua[:70]}")

    if ip and ip != '0.0.0.0' and site_id:
        if cache.get(f'gm_wh_initiate:{site_id}:{ip}'):
            triggers.append(
                f"WH-03: Source IP {ip} called this site's payment-initiate endpoint "
                "within the last 10 minutes, then called the webhook path directly — "
                "classic self-forged callback pattern"
            )

    trusted = WEBHOOK_TRUSTED_IPS.get(site_id)
    if trusted and ip and ip not in trusted:
        # Only meaningful once you've actually populated WEBHOOK_TRUSTED_IPS
        # for this site — otherwise every legit callback would also "fail" this.
        triggers.append(
            f"WH-04: Webhook path called from {ip}, which is not in the configured "
            "trusted gateway IP range for this site"
        )

    return bool(triggers), triggers
