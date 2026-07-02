"""
SPY-THREAT-HUNT V2 :: threat intel feeds
Pulls known-bad indicators from public blocklists and threat-intel feeds so
you don't have to manually copy-paste them. Free feeds work with no
configuration; a couple of optional ones use a key from .env if you have
a paid/premium subscription tier for higher rate limits or richer data.
"""
import csv
import io
import os
import re

import requests

from . import extractor

TIMEOUT = 15
UA = {"User-Agent": "SPY-THREAT-HUNT/2.0 (local threat intel tool)"}

OTX_API_KEY = os.environ.get("OTX_API_KEY", "").strip()


def _get(url, **kw):
    r = requests.get(url, headers=UA, timeout=TIMEOUT, **kw)
    r.raise_for_status()
    return r


# --------------------------------------------------------------- abuse.ch
def fetch_urlhaus():
    """Recent malicious URLs — abuse.ch URLhaus, free, no key required."""
    r = _get("https://urlhaus.abuse.ch/downloads/text_recent/")
    lines = [l for l in r.text.splitlines() if l and not l.startswith("#")]
    return {"iocs_text": "\n".join(lines), "count_hint": len(lines)}


def fetch_threatfox():
    """Recent IOCs (IPs, domains, hashes, URLs) — abuse.ch ThreatFox, free, no key."""
    r = requests.post(
        "https://threatfox-api.abuse.ch/api/v1/",
        json={"query": "get_iocs", "days": 3},
        headers=UA, timeout=TIMEOUT,
    )
    r.raise_for_status()
    data = r.json()
    rows = data.get("data") or []
    values = [row.get("ioc", "") for row in rows if row.get("ioc")]
    return {"iocs_text": "\n".join(values), "count_hint": len(values)}


def fetch_feodotracker():
    """Active botnet C2 IPs — abuse.ch Feodo Tracker, free, no key."""
    r = _get("https://feodotracker.abuse.ch/downloads/ipblocklist.txt")
    lines = [l for l in r.text.splitlines() if l and not l.startswith("#")]
    return {"iocs_text": "\n".join(lines), "count_hint": len(lines)}


# ------------------------------------------------------------------- CISA
def fetch_cisa_kev():
    """CISA Known Exploited Vulnerabilities catalog — free, no key, CVE-focused."""
    r = _get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    data = r.json()
    vulns = data.get("vulnerabilities", [])
    cves = [v.get("cveID", "") for v in vulns if v.get("cveID")]
    return {"iocs_text": "\n".join(cves), "count_hint": len(cves)}


# --------------------------------------------------------------- AlienVault OTX
def fetch_otx_pulses():
    """AlienVault OTX subscribed pulses — free tier available, optional API key."""
    if not OTX_API_KEY:
        return None
    r = _get(
        "https://otx.alienvault.com/api/v1/pulses/subscribed",
        headers={**UA, "X-OTX-API-KEY": OTX_API_KEY},
        params={"limit": 20},
    )
    data = r.json()
    values = []
    for pulse in data.get("results", []):
        for ind in pulse.get("indicators", []):
            if ind.get("indicator"):
                values.append(ind["indicator"])
    return {"iocs_text": "\n".join(values), "count_hint": len(values)}


# -------------------------------------------------------------- custom feed
def fetch_custom(url, api_key=None):
    """Any plain-text, CSV, or JSON feed URL — for paid/private threat-intel
    subscriptions. Pulls the raw content and lets the normal extractor pull
    IOCs out of it, so it works with most feed formats without custom parsing."""
    headers = dict(UA)
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
        headers["X-API-Key"] = api_key
    r = requests.get(url, headers=headers, timeout=TIMEOUT)
    r.raise_for_status()
    text = r.text
    # if it's JSON, flatten values so the extractor has plain text to scan
    ctype = r.headers.get("content-type", "")
    if "json" in ctype:
        import json as _json
        try:
            text = _json.dumps(r.json())
        except Exception:
            pass
    return {"iocs_text": text, "count_hint": None}


FEEDS = {
    "urlhaus": {
        "name": "URLhaus (abuse.ch)",
        "description": "Recently reported malicious URLs used for malware distribution.",
        "fetch": fetch_urlhaus,
        "requires_key": False,
        "cost": "free",
    },
    "threatfox": {
        "name": "ThreatFox (abuse.ch)",
        "description": "Recent IOCs (IPs, domains, hashes, URLs) shared by the community, last 3 days.",
        "fetch": fetch_threatfox,
        "requires_key": False,
        "cost": "free",
    },
    "feodotracker": {
        "name": "Feodo Tracker (abuse.ch)",
        "description": "Active botnet command-and-control server IP addresses.",
        "fetch": fetch_feodotracker,
        "requires_key": False,
        "cost": "free",
    },
    "cisa_kev": {
        "name": "CISA Known Exploited Vulnerabilities",
        "description": "CVEs with confirmed real-world exploitation, maintained by CISA.",
        "fetch": fetch_cisa_kev,
        "requires_key": False,
        "cost": "free",
    },
    "otx": {
        "name": "AlienVault OTX (subscribed pulses)",
        "description": "Indicators from threat-intel pulses you follow on OTX. Free account, optional API key.",
        "fetch": fetch_otx_pulses,
        "requires_key": True,
        "key_env": "OTX_API_KEY",
        "cost": "free tier / paid tiers available",
    },
}


def feed_status():
    return {
        fid: {
            "name": f["name"], "description": f["description"],
            "requiresKey": f["requires_key"], "cost": f["cost"],
            "configured": (not f["requires_key"]) or bool(os.environ.get(f.get("key_env", ""), "").strip()),
        }
        for fid, f in FEEDS.items()
    }


def pull_feed(feed_id):
    feed = FEEDS.get(feed_id)
    if not feed:
        return None, "unknown feed"
    try:
        result = feed["fetch"]()
    except Exception as e:
        return None, str(e)
    if result is None:
        return None, "feed requires an API key — add one to .env"
    return result, None
