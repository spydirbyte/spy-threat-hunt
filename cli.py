#!/usr/bin/env python3
"""
SPY-THREAT-HUNT V2
Developed by SPYDIRBYTE — idea created by hAckDHD

CLI usage:
    python cli.py serve                     # launch the web UI
    python cli.py paste < intel.txt         # extract IOCs from stdin
    python cli.py extract report.pdf        # extract from a file
    python cli.py list --class=malicious    # list stored IOCs
    python cli.py hunt --platform=splunk    # generate hunt queries
    python cli.py report exec               # executive report
    python cli.py report analyst            # analyst report
"""
import argparse
import json
import sys

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from core import storage, extractor, classifier, hunting, reporting

BANNER = r"""
  ███████╗██████╗ ██╗   ██╗      ████████╗██╗  ██╗██████╗ ███████╗ █████╗ ████████╗
  ██╔════╝██╔══██╗╚██╗ ██╔╝      ╚══██╔══╝██║  ██║██╔══██╗██╔════╝██╔══██╗╚══██╔══╝
  ███████╗██████╔╝ ╚████╔╝ █████╗   ██║   ███████║██████╔╝█████╗  ███████║   ██║
  ╚════██║██╔═══╝   ╚██╔╝  ╚════╝   ██║   ██╔══██║██╔══██╗██╔══╝  ██╔══██║   ██║
  ███████║██║        ██║           ██║   ██║  ██║██║  ██║███████╗██║  ██║   ██║
  ╚══════╝╚═╝        ╚═╝           ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝   ╚═╝
                  H U N T   V 2   ::   by SPYDIRBYTE   ::   idea by hAckDHD
"""


def cmd_serve(args):
    from app import create_app
    app = create_app()
    print(BANNER)
    print(f"  >> web UI live at http://127.0.0.1:{args.port}\n")
    app.run(host="127.0.0.1", port=args.port, debug=False)


def cmd_paste(args):
    text = sys.stdin.read()
    _run_extraction(text, source="manual")


def cmd_extract(args):
    path = args.target
    if path.startswith("http://") or path.startswith("https://"):
        import urllib.request
        req = urllib.request.Request(path, headers={"User-Agent": "SPY-THREAT-HUNT/2.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            html = resp.read().decode("utf-8", errors="ignore")
        import re
        text = re.sub(r"<[^>]+>", " ", html)
        _run_extraction(text, source="scraper", source_url=path)
    else:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        _run_extraction(text, source="file", source_file=path)


def _run_extraction(text, source="manual", source_url=None, source_file=None):
    result = extractor.extract(text, source=source, source_url=source_url, source_file=source_file)
    iocs = [i.to_dict() for i in result["iocs"]]
    for i in iocs:
        i["classification"] = classifier.classify_heuristic(i)
    inserted_ids = storage.bulk_upsert(iocs)
    inserted = len(inserted_ids)
    print(f"  Extracted {len(iocs)} IOC(s), {inserted} new, {len(iocs) - inserted} duplicate(s).")
    for t, c in sorted(result["stats"]["by_type"].items(), key=lambda x: -x[1]):
        print(f"    {t:14s} {c}")


def cmd_list(args):
    types = args.type.split(",") if args.type else None
    classes = [args.__dict__["class"]] if args.__dict__.get("class") else None
    iocs = storage.list_iocs(type_=types, classification=classes, limit=args.limit)
    for i in iocs:
        print(f"[{i['classification']:10s}] {i['type']:14s} {i['value']}")
    print(f"\n  {len(iocs)} indicator(s)")


def cmd_hunt(args):
    types = args.type.split(",") if args.type else None
    iocs = storage.list_iocs(type_=types, limit=2000)
    if not iocs:
        print("  No IOCs stored yet. Run `extract` or `paste` first.")
        return
    grouped = {}
    for i in iocs:
        grouped.setdefault(i["type"], []).append(i)
    for type_, group in grouped.items():
        q = hunting.generate(args.platform, type_, group, args.time_range)
        if q:
            print(f"\n{'=' * 70}\n  {q['description']}\n{'=' * 70}")
            print(q["query"])


def cmd_report(args):
    iocs = storage.list_iocs(limit=5000)
    if args.kind == "exec":
        rep = reporting.executive_report(iocs)
    else:
        rep = reporting.analyst_report(iocs)
    print(json.dumps(rep, indent=2, default=str))


def main():
    parser = argparse.ArgumentParser(prog="spy-threat-hunt", description="SPY-THREAT-HUNT V2 CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_serve = sub.add_parser("serve", help="launch the web UI")
    p_serve.add_argument("--port", type=int, default=8847)
    p_serve.set_defaults(func=cmd_serve)

    p_paste = sub.add_parser("paste", help="extract IOCs from stdin")
    p_paste.set_defaults(func=cmd_paste)

    p_extract = sub.add_parser("extract", help="extract IOCs from a file or URL")
    p_extract.add_argument("target")
    p_extract.set_defaults(func=cmd_extract)

    p_list = sub.add_parser("list", help="list stored IOCs")
    p_list.add_argument("--type", default=None)
    p_list.add_argument("--class", dest="class", default=None)
    p_list.add_argument("--limit", type=int, default=200)
    p_list.set_defaults(func=cmd_list)

    p_hunt = sub.add_parser("hunt", help="generate hunt queries")
    p_hunt.add_argument("--platform", default="splunk",
                         choices=["splunk", "sigma", "kql", "elastic", "wazuh", "yara"])
    p_hunt.add_argument("--type", default=None)
    p_hunt.add_argument("--time-range", default=None, choices=["1d", "7d", "14d", "30d", "90d"])
    p_hunt.set_defaults(func=cmd_hunt)

    p_report = sub.add_parser("report", help="generate a report")
    p_report.add_argument("kind", choices=["exec", "analyst"])
    p_report.set_defaults(func=cmd_report)

    storage.migrate()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
