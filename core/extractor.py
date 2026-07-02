"""
SPY-THREAT-HUNT V2 :: extraction engine
Turns raw pasted text / scraped pages / uploaded files into structured IOCs.
"""
import re
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional, List, Dict
from urllib.parse import urlparse, urlunparse

from .patterns import PATTERNS, defang


IOC_TYPES = [
    "ip", "ipv6", "domain", "url", "sha256", "sha1", "md5",
    "email", "cve", "hostname", "registry_key", "filename",
]
CLASSIFICATIONS = ["malicious", "suspicious", "unknown", "internal", "external"]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class IOC:
    id: str
    value: str
    type: str
    classification: str = "unknown"
    source: str = "manual"
    source_url: Optional[str] = None
    source_file: Optional[str] = None
    extracted_at: str = field(default_factory=now_iso)
    enriched_at: Optional[str] = None
    enrichment: Optional[dict] = None
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    tlp: Optional[str] = None
    ignored: bool = False

    def to_dict(self):
        return asdict(self)


def _normalize(value: str, type_: str) -> str:
    v = value.strip()
    if type_ in ("ip", "ipv6"):
        return v.lower()
    if type_ in ("domain", "hostname"):
        return v.lower().rstrip(".")
    if type_ == "url":
        return _normalize_url(v)
    if type_ == "email":
        return v.lower()
    if type_ in ("sha256", "sha1", "md5"):
        return v.lower()
    if type_ == "cve":
        return v.upper()
    if type_ == "registry_key":
        return _normalize_registry(v)
    return v


def _normalize_url(url: str) -> str:
    try:
        u = urlparse(url)
        path = "" if u.path == "/" else u.path
        return urlunparse((u.scheme, u.netloc, path, u.params, u.query, u.fragment))
    except Exception:
        return url


_REG_PREFIXES = [
    (re.compile(r"^HKLM\\", re.I), "HKEY_LOCAL_MACHINE\\"),
    (re.compile(r"^HKCU\\", re.I), "HKEY_CURRENT_USER\\"),
    (re.compile(r"^HKCR\\", re.I), "HKEY_CLASSES_ROOT\\"),
    (re.compile(r"^HKU\\", re.I), "HKEY_USERS\\"),
    (re.compile(r"^HKCC\\", re.I), "HKEY_CURRENT_CONFIG\\"),
]


def _normalize_registry(key: str) -> str:
    for pattern, repl in _REG_PREFIXES:
        key = pattern.sub(repl, key)
    return key


def _strip_port(value: str) -> str:
    m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):\d+$", value)
    return m.group(1) if m else value


def extract(
    raw_text: str,
    source: str = "manual",
    source_url: Optional[str] = None,
    source_file: Optional[str] = None,
    include_hostnames: bool = False,
    tags: Optional[List[str]] = None,
) -> Dict:
    """Core extraction pass. Returns dict with iocs + stats."""
    text = defang(raw_text)
    seen: Dict[str, IOC] = {}
    claimed: List[tuple] = []
    now = now_iso()
    tags = tags or []

    def is_claimed(start, end):
        return any(start < e and end > s for s, e in claimed)

    for pdef in sorted(PATTERNS, key=lambda p: -p.priority):
        if pdef.type == "hostname" and not include_hostnames:
            continue
        for m in pdef.pattern.finditer(text):
            raw = m.group(0)
            start, end = m.start(), m.end()
            if is_claimed(start, end):
                continue
            value = _normalize(raw, pdef.type)
            if pdef.type == "ip":
                value = _strip_port(value)
            if pdef.validate and not pdef.validate(value):
                continue
            key = f"{pdef.type}:{value}"
            if key in seen:
                continue
            claimed.append((start, end))
            seen[key] = IOC(
                id=str(uuid.uuid4()),
                value=value,
                type=pdef.type,
                source=source,
                source_url=source_url,
                source_file=source_file,
                extracted_at=now,
                tags=list(tags),
            )

    iocs = list(seen.values())
    by_type: Dict[str, int] = {}
    for ioc in iocs:
        by_type[ioc.type] = by_type.get(ioc.type, 0) + 1

    return {
        "iocs": iocs,
        "source_url": source_url,
        "source_file": source_file,
        "extracted_at": now,
        "stats": {"total": len(iocs), "by_type": by_type},
    }
