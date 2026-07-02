"""
SPY-THREAT-HUNT V2 :: classification heuristics
Pre-enrichment scoring of IOCs — DGA detection, known bad ranges, cheap TLDs.
"""
import math
import re
from urllib.parse import urlparse

MALICIOUS_TLDS = {".onion", ".bit", ".i2p", ".bazar", ".coin", ".lib"}

SUSPICIOUS_PATTERNS = [
    re.compile(r"\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}\."),
    re.compile(r"[a-z0-9]{25,}\.(com|net|org|info)$", re.I),
    re.compile(r"[0-9a-f]{8,}\.(xyz|top|pw|club|tk|ml|ga|cf|gq)$", re.I),
    re.compile(r"update.*\.(xyz|top|pw|club|info)$", re.I),
    re.compile(r"secure.*\.(xyz|top|pw)$", re.I),
    re.compile(r"login.*\.(xyz|top|pw)$", re.I),
]

SUSPICIOUS_IP_RANGES = [
    re.compile(r"^5\.188\."),
    re.compile(r"^185\.220\."),
    re.compile(r"^45\.142\."),
    re.compile(r"^91\.108\."),
]


def _is_dga(domain: str) -> bool:
    label = domain.split(".")[0]
    if len(label) < 10:
        return False
    vowels = len(re.findall(r"[aeiou]", label, re.I))
    if vowels / len(label) < 0.15:
        return True
    freq = {}
    for c in label:
        freq[c] = freq.get(c, 0) + 1
    entropy = -sum((n / len(label)) * math.log2(n / len(label)) for n in freq.values())
    return entropy > 3.8


def classify_heuristic(ioc) -> str:
    """ioc: dict-like with 'type', 'value', 'classification', 'enrichment'."""
    if ioc.get("classification") == "malicious":
        return "malicious"

    enrichment = ioc.get("enrichment") or {}
    score = enrichment.get("reputation_score")
    if score is not None:
        if score >= 70:
            return "malicious"
        if score >= 30:
            return "suspicious"
        return "unknown"

    t = ioc.get("type")
    v = (ioc.get("value") or "")

    if t == "domain":
        vl = v.lower()
        tld = "." + vl.split(".")[-1]
        if tld in MALICIOUS_TLDS:
            return "malicious"
        if any(p.search(vl) for p in SUSPICIOUS_PATTERNS):
            return "suspicious"
        if _is_dga(vl):
            return "suspicious"
    elif t == "ip":
        if any(r.search(v) for r in SUSPICIOUS_IP_RANGES):
            return "suspicious"
    elif t == "url":
        try:
            host = urlparse(v).hostname or ""
            return classify_heuristic({**ioc, "type": "domain", "value": host})
        except Exception:
            pass

    return ioc.get("classification") or "unknown"


TAG_MAP = {
    "malicious": "malicious", "bad": "malicious", "c2": "malicious",
    "suspicious": "suspicious", "suspect": "suspicious",
    "internal": "internal", "whitelist": "external", "external": "external",
}


def classify_by_tag(ioc, tag: str) -> str:
    return TAG_MAP.get(tag.lower(), ioc.get("classification", "unknown"))
