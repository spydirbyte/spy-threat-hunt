"""
SPY-THREAT-HUNT V2 :: reporting
Generates executive-brief and analyst-detail views of the current IOC set.
"""
from datetime import datetime, timezone
from collections import defaultdict

from . import hunting


def executive_report(iocs, hunt_name=None):
    now = datetime.now(timezone.utc).isoformat()
    critical = [i for i in iocs if i["classification"] == "malicious"]
    suspicious = [i for i in iocs if i["classification"] == "suspicious"]

    if len(critical) > 10:
        severity = "critical"
    elif len(critical) > 0:
        severity = "high"
    elif len(suspicious) > 5:
        severity = "medium"
    else:
        severity = "low"

    countries = sorted({i["enrichment"]["country"] for i in iocs
                         if i.get("enrichment") and i["enrichment"].get("country")})
    external_comms = any(i["type"] in ("ip", "domain", "url") for i in critical)

    timeline = []
    for i in sorted(iocs, key=lambda x: x["extracted_at"])[:25]:
        sev = "critical" if i["classification"] == "malicious" else (
            "medium" if i["classification"] == "suspicious" else "low")
        timeline.append({
            "timestamp": i["extracted_at"],
            "event": f"{i['type'].upper()} indicator observed: {i['value']}",
            "severity": sev,
        })

    techniques = sorted({t for i in iocs if i.get("enrichment")
                          for t in (i["enrichment"].get("attack_techniques") or [])})

    recs = ["Block and monitor all indicators classified as malicious across perimeter and endpoint controls."]
    if critical:
        recs.append(f"Prioritize incident response triage on {len(critical)} confirmed-malicious indicator(s).")
    if external_comms:
        recs.append("Review egress logs for beaconing behavior to flagged external infrastructure.")
    if suspicious:
        recs.append(f"Escalate {len(suspicious)} suspicious indicator(s) for enrichment / analyst review.")
    recs.append("Feed confirmed IOCs into detection content (SIEM/EDR) using the hunt query generator.")

    return {
        "huntName": hunt_name or None,
        "generatedAt": now,
        "totalIOCs": len(iocs),
        "criticalCount": len(critical),
        "severity": severity,
        "businessImpact": {
            "usersAtRisk": len([i for i in iocs if i["type"] == "email"]),
            "externalCommunications": external_comms,
            "estimatedImpact": {
                "critical": "Severe — active compromise indicators present, immediate response required.",
                "high": "Significant — confirmed malicious infrastructure identified.",
                "medium": "Moderate — suspicious activity warrants investigation.",
                "low": "Limited — no confirmed malicious indicators at this time.",
            }[severity],
            "geographicSpread": countries,
        },
        "timeline": timeline,
        "attackTechniques": techniques,
        "recommendations": recs,
    }


def analyst_report(iocs, hunt_platforms=("splunk", "sigma", "kql"), hunt_name=None):
    now = datetime.now(timezone.utc).isoformat()
    by_type = defaultdict(list)
    by_class = defaultdict(list)
    for i in iocs:
        by_type[i["type"]].append(i)
        by_class[i["classification"]].append(i)

    enriched = len([i for i in iocs if i.get("enrichment")])
    hunt_queries = []
    for type_, group in by_type.items():
        if type_ in ("hostname", "filename"):
            continue
        for platform in hunt_platforms:
            q = hunting.generate(platform, type_, group)
            if q:
                hunt_queries.append(q)

    hypotheses = []
    domains = by_type.get("domain", [])
    ips = by_type.get("ip", [])
    hashes = by_type.get("sha256", []) + by_type.get("md5", []) + by_type.get("sha1", [])
    if domains and ips:
        hypotheses.append("Correlated domain and IP indicators suggest an active C2 infrastructure cluster.")
    if hashes:
        hypotheses.append("File hash indicators present — consider this a malware-delivery or execution-stage campaign.")
    if by_type.get("cve"):
        hypotheses.append("CVE references indicate exploitation of a known vulnerability as an initial access vector.")
    if not hypotheses:
        hypotheses.append("Insufficient correlation to form a confident threat-actor hypothesis yet — enrich indicators for more context.")

    opportunities = []
    if ips or domains:
        opportunities.append("Network-layer detections: DNS/proxy/firewall logs against domain & IP IOCs.")
    if hashes:
        opportunities.append("Endpoint detections: EDR/AV hash matching, plus YARA scan of file shares.")
    if by_type.get("registry_key"):
        opportunities.append("Persistence detections: Windows registry monitoring (Sysmon Event ID 12/13/14).")
    if by_type.get("email"):
        opportunities.append("Email-gateway detections: sender/recipient IOC matching against mail logs.")

    return {
        "huntName": hunt_name or None,
        "generatedAt": now,
        "iocs": iocs,
        "huntQueries": hunt_queries,
        "enrichmentSummary": {"enriched": enriched, "pending": len(iocs) - enriched, "failed": 0},
        "iocsByType": dict(by_type),
        "iocsByClassification": dict(by_class),
        "threatActorHypotheses": hypotheses,
        "detectionOpportunities": opportunities,
    }
