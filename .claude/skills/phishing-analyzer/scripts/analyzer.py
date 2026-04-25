import email
import email.policy
import hashlib
import re
from dataclasses import dataclass
from typing import Optional

import requests


KNOWN_BRANDS = [
    "paypal", "amazon", "google", "microsoft", "apple", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "github",
    "chase", "bankofamerica", "wellsfargo", "citibank", "irs", "usps",
    "fedex", "ups", "dhl", "outlook", "yahoo", "gmail", "docusign",
    "coinbase", "binance", "stripe", "shopify", "ebay", "walmart",
]


@dataclass
class EmailAnalysis:
    headers: dict
    spf: Optional[str]
    dkim: Optional[str]
    dmarc: Optional[str]
    urls: list
    attachment_hashes: list
    lookalike_domains: list
    raw_from: Optional[str]
    raw_subject: Optional[str]
    raw_reply_to: Optional[str]


def _levenshtein(s1: str, s2: str) -> int:
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = range(len(s2) + 1)
    for c1 in s1:
        curr = [prev[0] + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _extract_headers(msg: email.message.Message) -> dict:
    seen = set()
    headers = {}
    for key in msg.keys():
        if key not in seen:
            headers[key] = msg[key]
            seen.add(key)
    return headers


def _extract_auth(msg: email.message.Message) -> tuple:
    auth = msg.get("Authentication-Results", "")
    received_spf = msg.get("Received-SPF", "")

    spf = None
    m = re.search(r"spf=(\w+)", auth, re.I)
    if m:
        spf = m.group(1)
    elif received_spf:
        m2 = re.match(r"(\w+)", received_spf.strip())
        if m2:
            spf = m2.group(1)

    dkim = None
    m = re.search(r"dkim=(\w+)", auth, re.I)
    if m:
        dkim = m.group(1)

    dmarc = None
    m = re.search(r"dmarc=(\w+)", auth, re.I)
    if m:
        dmarc = m.group(1)

    return spf, dkim, dmarc


def _resolve_url(url: str, timeout: int = 6) -> dict:
    try:
        resp = requests.head(
            url,
            allow_redirects=True,
            timeout=timeout,
            headers={"User-Agent": "Mozilla/5.0"},
        )
        return {
            "original": url,
            "final": resp.url,
            "redirected": resp.url != url,
            "status_code": resp.status_code,
        }
    except Exception as exc:
        return {"original": url, "final": url, "redirected": False, "error": str(exc)}


def _extract_urls(msg: email.message.Message) -> list:
    pattern = re.compile(r"https?://[^\s<>\"']+", re.I)
    seen: set[str] = set()
    for part in msg.walk():
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        for raw in pattern.findall(text):
            url = raw.rstrip(".,;)")
            seen.add(url)
    return [_resolve_url(u) for u in list(seen)[:20]]


def _extract_attachments(msg: email.message.Message) -> list:
    results = []
    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue
        data = part.get_payload(decode=True)
        if not data:
            continue
        results.append({
            "filename": part.get_filename() or "unknown",
            "content_type": part.get_content_type(),
            "size_bytes": len(data),
            "md5": hashlib.md5(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest(),
        })
    return results


def _domain_from_addr(addr: str) -> Optional[str]:
    m = re.search(r"@([\w.-]+)", addr)
    return m.group(1).lower() if m else None


def _check_lookalikes(msg: email.message.Message) -> list:
    candidates: set[str] = set()

    for header in ("From", "Reply-To", "Return-Path"):
        val = msg.get(header, "")
        d = _domain_from_addr(val)
        if d:
            candidates.add(d)

    url_host_pat = re.compile(r"https?://([^/\s<>\"':]+)", re.I)
    for part in msg.walk():
        if part.get_content_type() not in ("text/plain", "text/html"):
            continue
        payload = part.get_payload(decode=True)
        if not payload:
            continue
        text = payload.decode(part.get_content_charset() or "utf-8", errors="replace")
        for m in url_host_pat.finditer(text):
            host = m.group(1).lower()
            parts = host.split(".")
            base_name = parts[-2] if len(parts) >= 2 else host
            candidates.add(base_name + ("." + parts[-1] if len(parts) >= 2 else ""))

    results = []
    for domain in candidates:
        parts = domain.split(".")
        name = parts[-2] if len(parts) >= 2 else domain
        for brand in KNOWN_BRANDS:
            dist = _levenshtein(name, brand)
            if 0 < dist <= 3:
                results.append({
                    "domain": domain,
                    "closest_brand": brand,
                    "edit_distance": dist,
                    "suspicious": True,
                })
    return results


def analyze_email(raw_email: str) -> EmailAnalysis:
    msg = email.message_from_string(raw_email, policy=email.policy.compat32)
    spf, dkim, dmarc = _extract_auth(msg)
    return EmailAnalysis(
        headers=_extract_headers(msg),
        spf=spf,
        dkim=dkim,
        dmarc=dmarc,
        urls=_extract_urls(msg),
        attachment_hashes=_extract_attachments(msg),
        lookalike_domains=_check_lookalikes(msg),
        raw_from=msg.get("From"),
        raw_subject=msg.get("Subject"),
        raw_reply_to=msg.get("Reply-To"),
    )
