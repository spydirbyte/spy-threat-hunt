"""
SPY-THREAT-HUNT V2 :: MITRE ATT&CK tagging
Lightweight heuristic mapping from IOC type/context to likely ATT&CK
techniques. This is intentionally conservative — it suggests techniques
worth investigating, not a confirmed diagnosis.
"""

TECHNIQUE_NAMES = {
    "T1071": "Application Layer Protocol (C2)",
    "T1071.001": "Web Protocols",
    "T1071.004": "DNS",
    "T1105": "Ingress Tool Transfer",
    "T1566": "Phishing",
    "T1566.001": "Spearphishing Attachment",
    "T1566.002": "Spearphishing Link",
    "T1204": "User Execution",
    "T1204.002": "Malicious File",
    "T1027": "Obfuscated Files or Information",
    "T1055": "Process Injection",
    "T1547": "Boot or Logon Autostart Execution",
    "T1547.001": "Registry Run Keys / Startup Folder",
    "T1112": "Modify Registry",
    "T1053": "Scheduled Task/Job",
    "T1041": "Exfiltration Over C2 Channel",
    "T1190": "Exploit Public-Facing Application",
    "T1583": "Acquire Infrastructure",
    "T1583.001": "Domains",
    "T1583.003": "Virtual Private Server",
    "T1595": "Active Scanning",
    "T1078": "Valid Accounts",
    "T1114": "Email Collection",
}


def suggest_techniques(ioc):
    """ioc: dict with 'type', 'value', 'classification'."""
    t = ioc.get("type")
    cls = ioc.get("classification")
    techniques = []

    if t in ("ip", "ipv6", "domain", "hostname"):
        techniques += ["T1071", "T1071.001"]
        if t == "domain":
            techniques += ["T1071.004", "T1583.001"]
        if t == "ip":
            techniques.append("T1583.003")
    elif t == "url":
        techniques += ["T1071.001", "T1566.002", "T1105"]
    elif t in ("sha256", "sha1", "md5"):
        techniques += ["T1105", "T1204.002", "T1027"]
    elif t == "email":
        techniques += ["T1566", "T1566.001", "T1114"]
    elif t == "cve":
        techniques.append("T1190")
    elif t == "registry_key":
        techniques += ["T1547.001", "T1112"]
    elif t == "filename":
        ext = ioc.get("value", "").split(".")[-1].lower()
        if ext in ("exe", "dll", "scr", "sys", "msi"):
            techniques += ["T1204.002", "T1055"]
        elif ext in ("ps1", "bat", "vbs", "js", "cmd"):
            techniques += ["T1204.002", "T1027"]

    if cls == "malicious":
        techniques.append("T1041")

    seen, out = set(), []
    for tid in techniques:
        if tid not in seen:
            seen.add(tid)
            out.append({"id": tid, "name": TECHNIQUE_NAMES.get(tid, tid)})
    return out


def tag_batch(iocs):
    for ioc in iocs:
        ioc["attackTechniques"] = suggest_techniques(ioc)
    return iocs


def summarize_techniques(iocs):
    """Aggregate technique counts across a set of IOCs for reporting."""
    counts = {}
    for ioc in iocs:
        for tech in suggest_techniques(ioc):
            key = tech["id"]
            if key not in counts:
                counts[key] = {"id": key, "name": tech["name"], "count": 0}
            counts[key]["count"] += 1
    return sorted(counts.values(), key=lambda x: -x["count"])
