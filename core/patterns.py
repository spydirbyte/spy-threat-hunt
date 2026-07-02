"""
SPY-THREAT-HUNT V2 :: pattern engine
Regex + heuristic definitions used to pull indicators of compromise (IOCs)
out of raw threat-intel text. Ported and extended from the original
lazy_threat_hunt TS engine.
"""
import re
from dataclasses import dataclass, field
from typing import Callable, Optional, List
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Defanging — undo common threat-intel obfuscation (hxxp, [.], (dot), etc.)
# ---------------------------------------------------------------------------
_DEFANG_STEPS = [
    (re.compile(r"hxxp(s?)://", re.I), r"http\1://"),
    (re.compile(r"\[dot\]", re.I), "."),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(dot\)", re.I), "."),
    (re.compile(r"\[at\]", re.I), "@"),
    (re.compile(r"\[@\]"), "@"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[(\w)\]"), r"\1"),
]


def defang(text: str) -> str:
    for pattern, repl in _DEFANG_STEPS:
        text = pattern.sub(repl, text)
    return text


# ---------------------------------------------------------------------------
# Filters
# ---------------------------------------------------------------------------
PRIVATE_RANGES = [
    re.compile(r"^127\."),
    re.compile(r"^10\."),
    re.compile(r"^192\.168\."),
    re.compile(r"^172\.(1[6-9]|2\d|3[01])\."),
    re.compile(r"^0\.0\.0\.0$"),
    re.compile(r"^255\.255\.255\.255$"),
    re.compile(r"^169\.254\."),
    re.compile(r"^::1$"),
    re.compile(r"^fe80:", re.I),
]


def is_private_ip(ip: str) -> bool:
    return any(p.search(ip) for p in PRIVATE_RANGES)


NOISE_DOMAINS = {
    "example.com", "example.org", "example.net", "localhost", "local",
    "google.com", "youtube.com", "microsoft.com", "office.com", "live.com",
    "amazon.com", "amazonaws.com", "cloudflare.com",
    "github.com", "githubusercontent.com", "githubassets.com",
    "schema.org", "w3.org", "mozilla.org",
    "jquery.com", "bootstrapcdn.com",
    "slack.com", "discord.com", "twitter.com", "x.com", "linkedin.com",
    "npmjs.com", "pypi.org", "rubygems.org", "crates.io",
    "hub.docker.com", "docker.com",
    "aquasecurity.io", "aquasec.com",
    "socket.dev",
    "virustotal.com", "abuseipdb.com",
}

SCRIPT_TLDS = {"sh", "py", "pl", "rb", "lua", "ps1", "bat", "cmd"}


def is_noise_domain(domain: str) -> bool:
    lower = domain.lower()
    if lower.startswith("www."):
        lower = lower[4:]
    if lower in NOISE_DOMAINS:
        return True
    parts = lower.split(".")
    for i in range(1, len(parts) - 1):
        if ".".join(parts[i:]) in NOISE_DOMAINS:
            return True
    return False


def is_script_filename(domain: str) -> bool:
    parts = domain.split(".")
    tld = parts[-1].lower()
    return tld in SCRIPT_TLDS and len(parts) == 2 and not re.search(r"\d", parts[0])


def is_noise_url(url: str) -> bool:
    try:
        host = urlparse(url).hostname or ""
        return is_noise_domain(host)
    except Exception:
        return False


HEX_ONLY = re.compile(r"^[a-f0-9]+$", re.I)

_TLDS = (
    "com|net|org|io|gov|mil|edu|co|uk|de|fr|ru|cn|jp|br|au|nl|se|no|fi|it|es|"
    "info|biz|name|mobi|travel|aero|coop|museum|pro|tel|xxx|int|ac|ad|ae|af|ag|"
    "ai|al|am|ao|aq|ar|as|at|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|bs|bt|bv|bw|"
    "by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cr|cu|cv|cx|cy|cz|dj|dk|dm|do|dz|ec|ee|"
    "eg|eh|er|et|eu|fi|fj|fk|fm|fo|ga|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|"
    "gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|iq|ir|is|je|jm|jo|ke|kg|kh|ki|km|"
    "kn|kp|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|me|mg|mh|mk|ml|"
    "mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|np|nr|nu|nz|om|"
    "pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|rs|rw|sa|sb|sc|sd|sg|sh|"
    "si|sj|sk|sl|sm|sn|so|sr|st|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|"
    "tt|tv|tw|tz|ua|ug|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|za|zm|zw|onion|"
    "bit|i2p|top|xyz|pw|club|tk|ml|ga|cf|gq|bazar|coin|lib|icu|cyou|rest|cc|"
    "site|online|live|shop|fun|link|click|work|world|space|store|app|dev"
)


@dataclass
class PatternDef:
    type: str
    pattern: re.Pattern
    priority: int
    validate: Optional[Callable[[str], bool]] = None


PATTERNS: List[PatternDef] = [
    PatternDef("cve", re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I), 100),
    PatternDef(
        "registry_key",
        re.compile(
            r"\bHKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)(?:\\[^\\\s<>\"']+)+",
            re.I,
        ),
        95,
    ),
    PatternDef("sha256", re.compile(r"\b[a-f0-9]{64}\b", re.I), 90, lambda m: bool(HEX_ONLY.match(m))),
    PatternDef("sha1", re.compile(r"\b[a-f0-9]{40}\b", re.I), 85, lambda m: bool(HEX_ONLY.match(m))),
    PatternDef("md5", re.compile(r"\b[a-f0-9]{32}\b", re.I), 80, lambda m: bool(HEX_ONLY.match(m))),
    PatternDef("email", re.compile(r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"), 75),
    PatternDef(
        "url",
        re.compile(r"https?://[^\s<>\"'`\[\]{}|\\^]+", re.I),
        70,
        lambda m: not is_noise_url(m) and not re.search(r"\$\{?[A-Z_]|\$[0-9]", m),
    ),
    PatternDef(
        "ipv6",
        re.compile(
            r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b"
        ),
        65,
    ),
    PatternDef(
        "ip",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        60,
        lambda m: not is_private_ip(m),
    ),
    PatternDef(
        "domain",
        re.compile(
            r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:" + _TLDS + r")\b",
            re.I,
        ),
        50,
        lambda m: not is_noise_domain(m) and not is_script_filename(m),
    ),
    PatternDef(
        "hostname",
        re.compile(r"\b[a-zA-Z][a-zA-Z0-9\-]{2,63}\b"),
        40,
        lambda m: bool(re.search(r"[0-9]", m) or "-" in m),
    ),
    PatternDef(
        "filename",
        re.compile(
            r"\b[\w\-]{1,64}\.(exe|dll|bat|ps1|vbs|js|jar|sh|py|pl|php|asp|aspx|jsp|hta|cmd|scr|pif|sys|msi|msp|lnk|doc|docx|xls|xlsx|pdf|zip|rar|7z|tar|gz)\b",
            re.I,
        ),
        72,
        lambda m: _validate_filename(m),
    ),
    PatternDef(
        "filename",
        re.compile(r"[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n\s]+\\)*[^\\/:*?\"<>|\r\n\s]+\.[a-zA-Z]{2,6}"),
        71,
    ),
    PatternDef("filename", re.compile(r"/(?:tmp|var/tmp|proc|dev/shm)/[\w.\-]{2,64}"), 70),
]


def _validate_filename(m: str) -> bool:
    name = m.split(".")[0].lower()
    if name in {"index", "readme", "default", "style", "main", "app", "base"}:
        return False
    ext = m.split(".")[-1].lower()
    looks_like_domain = re.fullmatch(r"[a-z]+", name) is not None and ext in {"net", "org", "io", "co", "gov", "edu"}
    return not looks_like_domain
