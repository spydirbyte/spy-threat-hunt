"""
SPY-THREAT-HUNT V2 :: enrichment
Optional reputation lookups against VirusTotal, AbuseIPDB, and Shodan.
All three are opt-in — set the relevant API key in .env and enrichment
becomes available. Without keys, the tool still works fine; you just
won't get inline reputation scores.
"""
import base64
import os
import re
from datetime import datetime, timezone

import requests

VT_KEY = os.environ.get("VT_API_KEY", "").strip()
ABUSEIPDB_KEY = os.environ.get("ABUSEIPDB_API_KEY", "").strip()
SHODAN_KEY = os.environ.get("SHODAN_API_KEY", "").strip()

TIMEOUT = 8


def config_status():
    return {
        "virustotal": bool(VT_KEY),
        "abuseipdb": bool(ABUSEIPDB_KEY),
        "shodan": bool(SHODAN_KEY),
    }


# ------------------------------------------------------------- VirusTotal
def _vt_endpoint(ioc_type, value):
    if ioc_type == "ip":
        return f"ip_addresses/{value}"
    if ioc_type == "domain":
        return f"domains/{value}"
    if ioc_type == "url":
        b64 = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=")
        return f"urls/{b64}"
    if ioc_type in ("sha256", "sha1", "md5"):
        return f"files/{value}"
    return None


def enrich_virustotal(ioc_type, value):
    if not VT_KEY:
        return None
    endpoint = _vt_endpoint(ioc_type, value)
    if not endpoint:
        return None
    try:
        r = requests.get(
            f"https://www.virustotal.com/api/v3/{endpoint}",
            headers={"x-apikey": VT_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        attrs = (r.json().get("data") or {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        total = sum(stats.get(k, 0) for k in ("harmless", "suspicious", "malicious", "undetected"))
        score = round((malicious / total) * 100) if total else 0
        threat_label = (attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")
        return {
            "provider": "virustotal",
            "reputation_score": score,
            "country": attrs.get("country"),
            "asn": str(attrs["asn"]) if attrs.get("asn") else None,
            "asn_org": attrs.get("as_owner"),
            "malware_family": [threat_label] if threat_label else [],
            "positives": malicious,
            "total": total,
            "first_seen": _epoch_iso(attrs.get("first_submission_date")),
            "last_seen": _epoch_iso(attrs.get("last_submission_date")),
        }
    except Exception:
        return None


def _epoch_iso(epoch):
    if not epoch:
        return None
    try:
        return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()
    except Exception:
        return None


# --------------------------------------------------------------- AbuseIPDB
def enrich_abuseipdb(ioc_type, value):
    if ioc_type not in ("ip", "ipv6"):
        return None
    if ABUSEIPDB_KEY:
        return _abuseipdb_api(value)
    return _abuseipdb_public_scrape(value)


def _abuseipdb_api(ip):
    try:
        r = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=TIMEOUT,
        )
        r.raise_for_status()
        d = r.json().get("data", {})
        return {
            "provider": "abuseipdb",
            "reputation_score": d.get("abuseConfidenceScore", 0),
            "country": d.get("countryCode"),
            "asn_org": d.get("isp"),
            "positives": d.get("totalReports"),
            "last_seen": d.get("lastReportedAt"),
        }
    except Exception:
        return None


_CONF_PATTERNS = [
    re.compile(r'"abuseConfidenceScore"\s*:\s*(\d+)'),
    re.compile(r"confidence[^%]*?(\d{1,3})%", re.I),
]


def _abuseipdb_public_scrape(ip):
    """No API key needed — reads the public check page, same as the browser would show."""
    try:
        r = requests.get(
            f"https://www.abuseipdb.com/check/{ip}",
            headers={"User-Agent": "Mozilla/5.0 (compatible; SPY-THREAT-HUNT/2.0)"},
            timeout=TIMEOUT,
        )
        if not r.ok:
            return None
        html = r.text
        score = 0
        for pat in _CONF_PATTERNS:
            m = pat.search(html)
            if m:
                score = int(m.group(1))
                break
        isp_m = re.search(r'"isp"\s*:\s*"([^"]+)"', html)
        country_m = re.search(r'"countryCode"\s*:\s*"([^"]+)"', html)
        return {
            "provider": "abuseipdb-public",
            "reputation_score": score,
            "country": country_m.group(1) if country_m else None,
            "asn_org": isp_m.group(1) if isp_m else None,
        }
    except Exception:
        return None


# ------------------------------------------------------------------ Shodan
def enrich_shodan(ioc_type, value):
    if not SHODAN_KEY or ioc_type not in ("ip", "ipv6"):
        return None
    try:
        r = requests.get(
            f"https://api.shodan.io/shodan/host/{value}",
            params={"key": SHODAN_KEY},
            timeout=TIMEOUT,
        )
        if r.status_code == 404:
            return None
        r.raise_for_status()
        d = r.json()
        return {
            "provider": "shodan",
            "country": d.get("country_code"),
            "city": d.get("city"),
            "asn": d.get("asn"),
            "asn_org": d.get("org") or d.get("isp"),
            "latitude": d.get("latitude"),
            "longitude": d.get("longitude"),
            "last_seen": d.get("last_update"),
            "raw": {"ports": d.get("ports"), "tags": d.get("tags")},
        }
    except Exception:
        return None


# --------------------------------------------------------------- orchestrate
def enrich_ioc(ioc_type, value):
    """Run every configured provider for this IOC and merge results.
    Returns None if nothing is configured or nothing came back."""
    results = []
    vt = enrich_virustotal(ioc_type, value)
    if vt:
        results.append(vt)
    abuse = enrich_abuseipdb(ioc_type, value)
    if abuse:
        results.append(abuse)
    shodan = enrich_shodan(ioc_type, value)
    if shodan:
        results.append(shodan)

    if not results:
        return None

    merged = {"provider": "+".join(r["provider"] for r in results)}
    scores = [r["reputation_score"] for r in results if r.get("reputation_score") is not None]
    if scores:
        merged["reputation_score"] = max(scores)

    for key in ("country", "city", "asn", "asn_org", "latitude", "longitude", "first_seen", "last_seen"):
        for r in results:
            if r.get(key) and not merged.get(key):
                merged[key] = r[key]

    families = [f for r in results for f in (r.get("malware_family") or [])]
    if families:
        merged["malware_family"] = list(set(families))

    return merged


def score_to_classification(score):
    if score is None:
        return "unknown"
    if score >= 70:
        return "malicious"
    if score >= 30:
        return "suspicious"
    return "unknown"
