"""
SPY-THREAT-HUNT V2 :: export
Turns the ledger (or a selection) into CSV, plain JSON, or a lightweight
STIX 2.1 bundle for sharing with other tooling / partners.
"""
import csv
import io
import json
import uuid
from datetime import datetime, timezone

STIX_TYPE_MAP = {
    "ip": "ipv4-addr", "ipv6": "ipv6-addr", "domain": "domain-name",
    "url": "url", "email": "email-addr",
    "sha256": "file", "sha1": "file", "md5": "file",
}

STIX_PATTERN_FIELD = {
    "ip": "ipv4-addr:value", "ipv6": "ipv6-addr:value", "domain": "domain-name:value",
    "url": "url:value", "email": "email-addr:value",
    "sha256": "file:hashes.SHA-256", "sha1": "file:hashes.SHA-1", "md5": "file:hashes.MD5",
}


def to_csv(iocs):
    buf = io.StringIO()
    fields = ["value", "type", "classification", "source", "source_url", "source_file",
              "extracted_at", "tags", "tlp", "notes"]
    writer = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    for i in iocs:
        row = dict(i)
        row["tags"] = ",".join(i.get("tags") or [])
        writer.writerow(row)
    return buf.getvalue()


def to_json(iocs):
    return json.dumps(iocs, indent=2, default=str)


def to_stix_bundle(iocs):
    objects = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    for ioc in iocs:
        stix_type = STIX_TYPE_MAP.get(ioc["type"])
        pattern_field = STIX_PATTERN_FIELD.get(ioc["type"])
        if not stix_type or not pattern_field:
            continue

        if ioc["type"] in ("sha256", "sha1", "md5"):
            pattern = f"[{pattern_field} = '{ioc['value']}']"
        else:
            pattern = f"[{pattern_field} = '{ioc['value']}']"

        indicator_id = f"indicator--{uuid.uuid4()}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": now,
            "modified": now,
            "name": f"{ioc['type'].upper()}: {ioc['value']}",
            "description": f"Extracted by SPY-THREAT-HUNT V2 — classification: {ioc['classification']}",
            "indicator_types": ["malicious-activity"] if ioc["classification"] == "malicious" else ["anomalous-activity"],
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ioc.get("extracted_at", now),
            "labels": ioc.get("tags", []),
        })

    return json.dumps({
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }, indent=2)


EXPORTERS = {"csv": to_csv, "json": to_json, "stix": to_stix_bundle}
