# SPY-THREAT-HUNT V2

A local-first tool for turning threat intel into something you can actually
act on: paste in a report, get back structured indicators, run them through
a reputation check if you want, and spit out ready-to-paste detection
queries for whatever SIEM or EDR you're running.

No cloud backend, no account, no telemetry. It's a Flask app that runs on
your own box and writes to a SQLite file in your home directory. That's it.

![status](https://img.shields.io/badge/status-active-brightgreen)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-MIT-lightgrey)

---

## Why this exists

Most of the time spent on IOC triage isn't analysis, it's typing — pulling
indicators out of a PDF by hand, un-defanging `hxxp://evil[.]com` back into
a real URL, then writing the same `index=* src_ip IN (...)` Splunk query
for the fifth time this week. This tool automates that part so you can
spend the time on the part that actually needs a human.

## What it does

- **Pulls indicators out of raw text.** IPs, IPv6, domains, URLs, MD5/SHA1/SHA256
  hashes, email addresses, CVE IDs, Windows registry keys, and suspicious
  filenames. Handles common obfuscation (`hxxp://`, `[.]`, `(dot)`, `[at]`)
  automatically.
- **Ingests from three sources**: paste text directly, point it at a URL to
  scrape, or upload a file (`.txt`, `.csv`, `.log`, `.json`, `.html`, `.pdf`,
  `.docx`).
- **Classifies heuristically** — flags known-bad TLDs, DGA-looking domains
  (high entropy, low vowel ratio), and IP ranges commonly tied to bulletproof
  hosting, before you've enriched anything.
- **Enriches on demand** against VirusTotal, AbuseIPDB, and Shodan if you
  drop API keys into `.env`. Works fine without them too — the AbuseIPDB
  check falls back to the public lookup page if you don't have a key.
- **Tags MITRE ATT&CK techniques** heuristically based on indicator type and
  classification, and rolls it up into a coverage view.
- **Generates hunt queries** for Splunk, Sigma, KQL (Sentinel/Defender),
  Elastic DSL, Wazuh, and YARA — built from whatever's sitting in your
  ledger, optionally scoped to a time range.
- **Exports** to CSV, plain JSON, or a STIX 2.1 bundle for handing off to
  other tooling.
- **Reports** — one click for an executive-facing brief (severity, business
  impact, recommendations) or an analyst-facing one (hypotheses, detection
  opportunities, full query set).

Everything above lives in `core/` as plain, dependency-light Python modules,
so if you just want the extraction logic or the query generators without
the web UI, you can import them directly.

## Getting it running

```bash
git clone https://github.com/<spydirbyte>/spy-threat-hunt.git
cd spy-threat-hunt
python3 -m venv venv
source venv/bin/activate      # venv\Scripts\activate on Windows
pip install -r requirements.txt
python cli.py serve
```

Open `http://127.0.0.1:8847`.

If your system Python is externally managed (Kali, Debian 12+, recent
Ubuntu) and `pip install` refuses to run, that's what the venv above is
for — don't `--break-system-packages` unless you know you want to.

### Optional: enrichment API keys

```bash
cp .env.example .env
```

Fill in whichever of `VT_API_KEY`, `ABUSEIPDB_API_KEY`, or `SHODAN_API_KEY`
you have. All optional, all independent — the tool doesn't require any of
them to function.

## Using it

The web UI has four tabs: **Extract**, **Ledger**, **Hunt Forge**, and
**Reports**. There's a guided walkthrough built into the app the first time
you open it (click the `?` in the bottom-left corner to replay it), and a
more detailed write-up in [TUTORIAL.md](TUTORIAL.md) if you'd rather read
than click through.

Short version:

1. Paste a report / scrape a URL / upload a file in **Extract**.
2. Review and reclassify what came out in **Ledger** — search, filter,
   tag, set TLP, enrich, whitelist false positives.
3. Select what you want (or leave nothing selected to use everything) and
   generate detection queries in **Hunt Forge**.
4. Pull a report in **Reports** when you need to write something up.

## CLI

```bash
python cli.py serve                          # launch the web UI
echo "1.2.3.4 evil.com" | python cli.py paste # extract from stdin
python cli.py extract report.pdf              # extract from a file or URL
python cli.py list --class=malicious          # list stored IOCs
python cli.py hunt --platform=sigma           # print hunt queries
python cli.py report exec                     # executive report (JSON)
python cli.py report analyst                  # analyst report (JSON)
```

## Project layout

```
core/
  patterns.py     regex + heuristic definitions per IOC type
  extractor.py    extraction engine — defang, dedupe, normalize
  classifier.py   heuristic malicious/suspicious scoring
  enrichment.py   VirusTotal / AbuseIPDB / Shodan lookups
  attack.py       MITRE ATT&CK technique tagging
  hunting.py      per-platform hunt query generators
  export.py       CSV / JSON / STIX bundle export
  storage.py      local SQLite persistence
  reporting.py    executive + analyst report builders
app.py            Flask routes / API
cli.py            command-line entrypoint
templates/        page shell
static/           CSS + JS for the UI
```

Data lives in `~/.spy-threat-hunt/iocs.db` by default. Override with the
`SPYHUNT_DATA_DIR` env var if you want it somewhere else — useful if you're
running multiple engagements and want separate ledgers.

## Notes on the heuristics

The classifier and ATT&CK tagging are both intentionally conservative —
they're meant to prioritize your attention, not replace it. A domain
flagged "suspicious" because it scored high on entropy isn't confirmed
malicious, and a technique tag on a hash isn't a confirmed TTP. Treat both
as a starting point for investigation, same as you would a YARA hit or a
sigma rule firing.

## Contributing

Issues and PRs welcome. If you're adding a new hunt platform, follow the
existing pattern in `core/hunting.py` — a function that takes `(type,
values, ...)` and returns a `{platform, query, description, iocType,
iocValues}` dict, then register it in `PLATFORM_FUNCS`.

## License

MIT — see [LICENSE](LICENSE).

---

Built by **SPYDIRBYTE**. Original concept and lazy_threat_hunt groundwork
by **hAckDHD**.
