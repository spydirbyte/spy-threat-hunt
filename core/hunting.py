"""
SPY-THREAT-HUNT V2 :: hunt query forge
Turns a list of IOC values into ready-to-paste detection queries for the
platform of your choice — Splunk, KQL (Sentinel/Defender), Sigma, YARA,
Elastic DSL, Wazuh.
"""
import json
import uuid
from datetime import datetime, timezone


def _ts():
    return datetime.now(timezone.utc).isoformat()


def _esc(v: str) -> str:
    return v.replace('"', '\\"')


TIME_MAP = {"1d": "1d", "7d": "7d", "14d": "14d", "30d": "30d", "90d": "90d"}


# ---------------------------------------------------------------------- Splunk
def splunk_query(type_, values, time_range=None):
    if not values:
        return None
    tc = f"earliest=-{TIME_MAP.get(time_range, '7d')} latest=now " if time_range else ""
    lst = " ".join(f'"{_esc(v)}"' for v in values)
    q, desc = None, None

    if type_ in ("ip", "ipv6"):
        q = (f'{tc}index=* (src_ip IN ({lst}) OR dest_ip IN ({lst}) OR src IN ({lst}) OR dst IN ({lst}))\n'
             f'| stats count by _time, src_ip, dest_ip, index, sourcetype\n| sort -count')
        desc = f"Splunk: Hunt for {len(values)} suspicious IP(s) in network traffic"
    elif type_ in ("domain", "hostname"):
        q = (f'{tc}index=* (dns.query IN ({lst}) OR query IN ({lst}) OR url IN ({lst}) OR domain IN ({lst}))\n'
             f'| eval ioc_match=coalesce(dns.query, query, url, domain)\n'
             f'| stats count by _time, src, ioc_match, index, sourcetype\n| sort -count')
        desc = f"Splunk: Hunt for {len(values)} domain/hostname IOC(s) in DNS and proxy logs"
    elif type_ == "url":
        q = (f'{tc}index=* (url IN ({lst}) OR request_url IN ({lst}))\n'
             f'| stats count by _time, src_ip, url, status, index\n| sort -count')
        desc = f"Splunk: Hunt for {len(values)} malicious URL(s) in proxy/web logs"
    elif type_ == "sha256":
        q = (f'{tc}index=* (sha256 IN ({lst}) OR file_hash IN ({lst}) OR hash IN ({lst}))\n'
             f'| stats count by _time, file_name, file_path, sha256, host, user\n| sort -count')
        desc = f"Splunk: Hunt for {len(values)} SHA256 file hash(es) in endpoint telemetry"
    elif type_ == "sha1":
        q = (f'{tc}index=* (sha1 IN ({lst}) OR file_hash IN ({lst}))\n'
             f'| stats count by _time, file_name, sha1, host, user\n| sort -count')
        desc = f"Splunk: Hunt for {len(values)} SHA1 hash(es)"
    elif type_ == "md5":
        q = (f'{tc}index=* (md5 IN ({lst}) OR file_hash IN ({lst}))\n'
             f'| stats count by _time, file_name, md5, host, user\n| sort -count')
        desc = f"Splunk: Hunt for {len(values)} MD5 hash(es)"
    elif type_ == "email":
        q = (f'{tc}index=* (sender IN ({lst}) OR recipient IN ({lst}) OR from IN ({lst}) OR to IN ({lst}))\n'
             f'| stats count by _time, sender, recipient, subject, index\n| sort -count')
        desc = f"Splunk: Hunt for {len(values)} suspicious email address(es)"
    elif type_ == "cve":
        q = (f'{tc}index=* (vulnerability IN ({lst}) OR cve IN ({lst}) OR signature IN ({lst}))\n'
             f'| stats count by _time, host, signature, severity\n| sort -count')
        desc = f"Splunk: Hunt for exploitation attempts of {len(values)} CVE(s)"
    elif type_ == "registry_key":
        clauses = " OR ".join(f'TargetObject="{_esc(v)}*"' for v in values)
        q = (f'{tc}index=* sourcetype=xmlwineventlog EventCode IN (12,13,14) ({clauses})\n'
             f'| stats count by _time, host, TargetObject, Details, EventCode\n| sort -count')
        desc = f"Splunk: Hunt for {len(values)} registry key IOC(s) via Windows Event Logs"
    else:
        return None

    return {"platform": "splunk", "query": q, "description": desc, "iocType": type_, "iocValues": values}


# ---------------------------------------------------------------------- Sigma
def sigma_rule(type_, values):
    if not values:
        return None
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    logsource, detection, desc = None, None, None

    if type_ in ("ip", "ipv6"):
        logsource = "logsource:\n    category: network_connection"
        items = "\n".join(f"            - '{v}'" for v in values)
        detection = f"detection:\n    selection:\n        dst_ip|contains:\n{items}\n    condition: selection"
        desc = f"SIGMA: Network connection to {len(values)} known-malicious IP(s)"
    elif type_ in ("domain", "hostname"):
        logsource = "logsource:\n    category: dns"
        items = "\n".join(f"            - '{v}'" for v in values)
        detection = f"detection:\n    selection:\n        dns.question.name|contains:\n{items}\n    condition: selection"
        desc = f"SIGMA: DNS lookup for {len(values)} malicious domain(s)"
    elif type_ in ("sha256", "sha1", "md5"):
        logsource = "logsource:\n    category: process_creation\n    product: windows"
        algo = type_.upper()
        items = "\n".join(f"            - '{algo}={v}'" for v in values)
        detection = f"detection:\n    selection:\n        Hashes|contains:\n{items}\n    condition: selection"
        desc = f"SIGMA: Process creation with {len(values)} known-malicious {algo} hash(es)"
    elif type_ == "registry_key":
        logsource = "logsource:\n    category: registry_event\n    product: windows"
        items = "\n".join(f"            - '{v}'" for v in values)
        detection = f"detection:\n    selection:\n        TargetObject|startswith:\n{items}\n    condition: selection"
        desc = f"SIGMA: Registry modification of {len(values)} suspicious key(s)"
    else:
        return None

    rule_id = str(uuid.uuid4())
    q = (f"title: IOC Hunt — {type_.upper()} Indicators\nid: {rule_id}\nstatus: experimental\n"
         f"description: {desc}\nreferences:\n    - 'IOC extracted on {ts}'\nauthor: SPY-THREAT-HUNT V2\n"
         f"date: {ts}\ntags:\n    - attack.threat_hunting\n    - ioc\n{logsource}\n{detection}\n"
         f"falsepositives:\n    - Unknown\nlevel: high")
    return {"platform": "sigma", "query": q, "description": desc, "iocType": type_, "iocValues": values}


# ------------------------------------------------------------------------ KQL
def kql_query(type_, values, time_range=None):
    if not values:
        return None
    tw = f"\n     | where TimeGenerated >= ago({TIME_MAP.get(time_range, '7d')})" if time_range else ""
    vl = ", ".join(f'"{_esc(v)}"' for v in values)
    ts = _ts()
    q, desc = None, None

    if type_ in ("ip", "ipv6"):
        q = (f"// Generated {ts}\nlet ioc_ips = dynamic([{vl}]);\nunion\n"
             f"    (DeviceNetworkEvents{tw}\n     | where RemoteIP in (ioc_ips) or LocalIP in (ioc_ips)\n"
             f"     | project TimeGenerated, DeviceName, LocalIP, RemoteIP, RemotePort, InitiatingProcessFileName, ActionType),\n"
             f"    (CommonSecurityLog{tw}\n     | where SourceIP in (ioc_ips) or DestinationIP in (ioc_ips)\n"
             f"     | project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, DestinationPort, Activity),\n"
             f"    (SigninLogs{tw}\n     | where IPAddress in (ioc_ips)\n"
             f"     | project TimeGenerated, UserPrincipalName, IPAddress, Location, ResultType)\n| order by TimeGenerated desc")
        desc = f"KQL (Sentinel/Defender): Hunt for {len(values)} IP IOC(s) across network and sign-in logs"
    elif type_ in ("domain", "hostname"):
        q = (f"// Generated {ts}\nlet ioc_domains = dynamic([{vl}]);\nunion\n"
             f"    (DeviceNetworkEvents{tw}\n     | where RemoteUrl has_any (ioc_domains) or RemoteIP has_any (ioc_domains)\n"
             f"     | project TimeGenerated, DeviceName, RemoteUrl, RemoteIP, InitiatingProcessFileName),\n"
             f"    (DnsEvents{tw}\n     | where Name in~ (ioc_domains)\n"
             f"     | project TimeGenerated, Computer, Name, IPAddresses),\n"
             f"    (DeviceEvents{tw}\n     | where RemoteUrl has_any (ioc_domains)\n"
             f"     | project TimeGenerated, DeviceName, RemoteUrl, InitiatingProcessFileName)\n| order by TimeGenerated desc")
        desc = f"KQL: Hunt for {len(values)} domain IOC(s) in DNS and network events"
    elif type_ == "sha256":
        q = (f"// Generated {ts}\nlet ioc_hashes = dynamic([{vl}]);\nunion\n"
             f"    (DeviceFileEvents{tw}\n     | where SHA256 in (ioc_hashes)\n"
             f"     | project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, InitiatingProcessAccountName),\n"
             f"    (DeviceProcessEvents{tw}\n     | where SHA256 in (ioc_hashes)\n"
             f"     | project TimeGenerated, DeviceName, FileName, FolderPath, SHA256, AccountName)\n| order by TimeGenerated desc")
        desc = f"KQL: Hunt for {len(values)} SHA256 file hash(es) in Defender ATP telemetry"
    elif type_ == "md5":
        q = (f"// Generated {ts}\nlet ioc_hashes = dynamic([{vl}]);\nDeviceFileEvents{tw}\n"
             f"| where MD5 in (ioc_hashes)\n"
             f"| project TimeGenerated, DeviceName, FileName, FolderPath, MD5, InitiatingProcessAccountName, ActionType\n"
             f"| order by TimeGenerated desc")
        desc = f"KQL: Hunt for {len(values)} MD5 hash(es) in file events"
    elif type_ == "email":
        q = (f"// Generated {ts}\nlet ioc_emails = dynamic([{vl}]);\nunion\n"
             f"    (EmailEvents{tw}\n     | where SenderFromAddress in~ (ioc_emails) or RecipientEmailAddress in~ (ioc_emails)\n"
             f"     | project TimeGenerated, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes, DeliveryAction)\n"
             f"| order by TimeGenerated desc")
        desc = f"KQL: Hunt for {len(values)} email address IOC(s) in email events"
    elif type_ == "cve":
        q = (f"// Generated {ts}\nlet ioc_cves = dynamic([{vl}]);\nSecurityAlert{tw}\n"
             f"| where Entities has_any (ioc_cves) or ExtendedProperties has_any (ioc_cves)\n"
             f"| project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Entities\n| order by TimeGenerated desc")
        desc = f"KQL: Hunt for exploitation activity related to {len(values)} CVE(s)"
    elif type_ == "registry_key":
        q = (f"// Generated {ts}\nlet ioc_keys = dynamic([{vl}]);\nDeviceRegistryEvents{tw}\n"
             f"| where RegistryKey has_any (ioc_keys) or PreviousRegistryKey has_any (ioc_keys)\n"
             f"| project TimeGenerated, DeviceName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, "
             f"InitiatingProcessFileName, InitiatingProcessAccountName\n| order by TimeGenerated desc")
        desc = f"KQL: Hunt for {len(values)} registry key IOC(s) in Defender registry events"
    else:
        return None

    return {"platform": "kql", "query": q, "description": desc, "iocType": type_, "iocValues": values}


# --------------------------------------------------------------------- Elastic
def elastic_query(type_, values):
    if not values:
        return None
    q, desc = None, None
    if type_ in ("ip", "ipv6"):
        q = json.dumps({"query": {"bool": {"should": [
            {"terms": {"source.ip": values}}, {"terms": {"destination.ip": values}},
            {"terms": {"client.ip": values}}, {"terms": {"server.ip": values}},
        ], "minimum_should_match": 1}},
            "aggs": {"by_host": {"terms": {"field": "host.name", "size": 20}}}}, indent=2)
        desc = f"Elastic DSL: Hunt for {len(values)} IP IOC(s) in network logs"
    elif type_ in ("domain", "hostname"):
        q = json.dumps({"query": {"bool": {"should": [
            {"terms": {"dns.question.name": values}}, {"terms": {"url.domain": values}},
            {"terms": {"destination.domain": values}},
        ], "minimum_should_match": 1}}}, indent=2)
        desc = f"Elastic DSL: Hunt for {len(values)} domain IOC(s)"
    elif type_ == "sha256":
        q = json.dumps({"query": {"bool": {"should": [
            {"terms": {"file.hash.sha256": values}}, {"terms": {"process.hash.sha256": values}},
        ], "minimum_should_match": 1}}}, indent=2)
        desc = f"Elastic DSL: Hunt for {len(values)} SHA256 hash(es)"
    elif type_ == "url":
        q = json.dumps({"query": {"terms": {"url.full": values}}}, indent=2)
        desc = f"Elastic DSL: Hunt for {len(values)} URL IOC(s)"
    elif type_ == "email":
        q = json.dumps({"query": {"bool": {"should": [
            {"terms": {"source.user.email": values}}, {"terms": {"destination.user.email": values}},
        ], "minimum_should_match": 1}}}, indent=2)
        desc = f"Elastic DSL: Hunt for {len(values)} email IOC(s)"
    else:
        return None
    return {"platform": "elastic", "query": q, "description": desc, "iocType": type_, "iocValues": values}


# ---------------------------------------------------------------------- Wazuh
def wazuh_query(type_, values, time_range=None):
    if not values:
        return None
    tf = f" AND timestamp:[now-{TIME_MAP.get(time_range, '7d')} TO now]" if time_range else ""

    def lucene_or(field, vals):
        return " OR ".join(f'{field}:"{_esc(v)}"' for v in vals)

    if type_ in ("ip", "ipv6"):
        q = (f"// Wazuh Dashboard — Security Events (Lucene)\n"
             f"({lucene_or('data.srcip', values)} OR {lucene_or('data.dstip', values)}){tf}\n\n"
             f"// Wazuh API — WQL filter (GET /events)\n// q=data.srcip~{','.join(values)}")
        desc = f"Wazuh: Hunt for {len(values)} IP IOC(s) in security events"
    elif type_ in ("domain", "hostname"):
        q = (f"// Wazuh Dashboard — Security Events (Lucene)\n"
             f"({lucene_or('data.dns.question.name', values)} OR {lucene_or('data.url', values)}){tf}")
        desc = f"Wazuh: Hunt for {len(values)} domain IOC(s)"
    elif type_ in ("sha256", "sha1", "md5"):
        q = (f"// Wazuh Dashboard — File Integrity Monitoring / Syscheck\n"
             f"({lucene_or('syscheck.' + type_, values)}){tf}")
        desc = f"Wazuh: Hunt for {len(values)} {type_.upper()} hash(es) via FIM/syscheck"
    else:
        return None
    return {"platform": "wazuh", "query": q, "description": desc, "iocType": type_, "iocValues": values}


# ----------------------------------------------------------------------- YARA
def yara_rule(type_, iocs):
    file_types = {"sha256", "sha1", "md5", "domain", "url", "ip", "email"}
    if type_ not in file_types or not iocs:
        return None

    ts = datetime.now(timezone.utc).strftime("%Y%m%d")
    rule_name = f"IOC_{type_.upper()}_{ts}"
    strings, condition, desc = "", "", ""

    if type_ in ("md5", "sha1", "sha256"):
        conds = " or\n        ".join(f'hash.{type_}(0, filesize) == "{i["value"]}"' for i in iocs)
        condition = f"    {conds}"
        desc = f"YARA: {type_.upper()} hash match for {len(iocs)} indicator(s) — requires the hash module"
    elif type_ in ("domain", "url", "ip"):
        lines = []
        for idx, i in enumerate(iocs):
            esc = i["value"].replace("\\", "\\\\").replace('"', '\\"')
            lines.append(f'    $ioc_{idx} = "{esc}" nocase')
        strings = "\n".join(lines)
        condition = "    any of ($ioc_*)"
        desc = f"YARA: String match for {len(iocs)} network indicator(s) in file content"
    elif type_ == "email":
        lines = [f'    $email_{idx} = "{i["value"].replace(chr(34), chr(92)+chr(34))}" nocase' for idx, i in enumerate(iocs)]
        strings = "\n".join(lines)
        condition = "    any of ($email_*)"
        desc = f"YARA: String match for {len(iocs)} email IOC(s)"

    values = [i["value"] for i in iocs]
    q = (f'import "hash"\n\nrule {rule_name}\n{{\n    meta:\n        description = "{desc}"\n'
         f'        author = "SPY-THREAT-HUNT V2"\n        date = "{datetime.now(timezone.utc).date()}"\n'
         f'        type = "{type_}"\n        ioc_count = "{len(iocs)}"\n'
         f'{f"\\n    strings:\\n{strings}" if strings else ""}\n\n    condition:\n{condition}\n}}')
    return {"platform": "yara", "query": q, "description": desc, "iocType": type_, "iocValues": values}


PLATFORM_FUNCS = {
    "splunk": lambda t, v, iocs, tr: splunk_query(t, v, tr),
    "sigma": lambda t, v, iocs, tr: sigma_rule(t, v),
    "kql": lambda t, v, iocs, tr: kql_query(t, v, tr),
    "elastic": lambda t, v, iocs, tr: elastic_query(t, v),
    "wazuh": lambda t, v, iocs, tr: wazuh_query(t, v, tr),
    "yara": lambda t, v, iocs, tr: yara_rule(t, iocs),
}


def generate(platform, type_, iocs, time_range=None):
    values = [i["value"] for i in iocs]
    fn = PLATFORM_FUNCS.get(platform)
    if not fn:
        return None
    return fn(type_, values, iocs, time_range)
