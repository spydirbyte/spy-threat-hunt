# Tutorial

A walkthrough of SPY-THREAT-HUNT V2, tab by tab. The app also has a
built-in guided tour (click the `?` button, bottom-left) that covers the
same ground in less detail — this doc is for when you want the full
picture, or you're setting it up for someone else on your team.

## 1. Getting data in — the Extract tab

There are three ways to get indicators into the ledger:

**Paste text.** Drop in a threat report, an email, a Slack message, a raw
list of IPs — whatever you've got. The extractor runs a defang pass first,
so `hxxp://evil[.]com`, `bad(dot)ru`, and `user[at]domain.com` all get
normalized back to their real form before pattern matching runs. Then it
pulls out every IOC type it recognizes: IPs, IPv6, domains, URLs, MD5/SHA1/
SHA256 hashes, email addresses, CVE IDs, Windows registry keys, and
suspicious filenames (`.exe`, `.dll`, `.ps1`, and so on).

There's an "include bare hostnames" checkbox — off by default, because
single-word hostnames without a dot produce a lot of noise (`server`,
`workstation-04` type stuff). Turn it on if you're specifically hunting for
internal hostname references.

**Scrape a URL.** Paste a link to a threat report page and it'll fetch and
extract from the rendered text. Useful for vendor blog posts you don't want
to copy-paste by hand.

**Upload a file.** Supports `.txt`, `.csv`, `.log`, `.json`, `.html`,
`.pdf`, and `.docx`. PDF and docx text extraction is best-effort — scanned
image-only PDFs won't have extractable text, since there's no OCR step.

After extraction, you'll see a summary (how many found, how many were new
vs. duplicates, breakdown by type) and the results appear in the Live Feed
panel on the right, most recent first.

## 2. Reviewing what you found — the Ledger tab

Everything you've ever extracted lives here, deduplicated by value + type
(so the same IP extracted from three different reports is one row, not
three).

- **Search** filters by substring match on the value.
- **Type / classification filters** narrow the table down.
- **Classification dropdown** on each row lets you override the heuristic
  call — if something's flagged "suspicious" and you know it's actually
  fine, change it to "external" or "unknown" right there.
- **Checkboxes + bulk actions** at the bottom let you tag a batch of
  indicators, set a TLP label (white/green/amber/red), mark a group as
  whitelisted ("external"), or kick off enrichment.
- **Enrich Selected** hits VirusTotal / AbuseIPDB / Shodan for whichever
  indicators you've checked, if you've got API keys configured (see below).
  Results feed back into the classification automatically — a high
  reputation score bumps something to "malicious."
- **Export** (top right of the toolbar) gives you CSV, plain JSON, or a
  STIX 2.1 bundle. If you've got a selection checked, it exports just
  those; otherwise it exports everything currently matching your filters.

### Setting up enrichment

Enrichment is entirely optional. Copy `.env.example` to `.env` and fill in
whichever keys you have:

```
VT_API_KEY=your_virustotal_key
ABUSEIPDB_API_KEY=your_abuseipdb_key
SHODAN_API_KEY=your_shodan_key
```

You don't need all three — the tool merges whatever comes back and takes
the highest reputation score across providers. If you don't have an
AbuseIPDB key, IP checks still work by reading the public check page
instead of the API (slower, less detail, but no key required).

## 3. Generating detection queries — the Hunt Forge tab

This is where indicators turn into something you can paste into your SIEM.

1. If you selected specific rows in the Ledger, Hunt Forge will use just
   those (you'll see a note confirming how many). Otherwise it uses
   everything in your ledger.
2. Pick a platform: Splunk, Sigma, KQL, Elastic, Wazuh, or YARA. Not every
   IOC type maps to every platform — YARA, for instance, only makes sense
   for hashes and network strings, not CVEs.
3. Optionally scope to a time range (last 1/7/14/30/90 days) — this adds
   the appropriate `earliest=`/`ago()`/timestamp filter for platforms that
   support it.
4. Click **Forge Queries**. Each result shows the query, a description of
   what it's hunting for, and a copy button.

The queries are grouped by IOC type — if your selection has both IPs and
hashes, you'll get one query block for the IP hunt and a separate one for
the hash hunt, since they usually hit different log sources.

## 4. Writing it up — the Reports tab

Two report types, both generated from your current full ledger (not
affected by Ledger tab selections):

- **Executive Report** — severity rating, business impact estimate, a
  timeline of the most recent indicators, and a short list of
  recommendations. Written for someone who needs the summary, not the
  query syntax.
- **Analyst Report** — indicator counts by type, threat-actor hypotheses
  (pattern-matched from what's in your ledger — e.g. "domain + IP
  correlation suggests active C2 infrastructure"), detection opportunities,
  and a count of how many hunt queries are available across platforms.
- **MITRE ATT&CK Coverage** — click "Analyze Techniques" underneath the two
  reports to see a frequency-sorted grid of ATT&CK technique IDs your
  current ledger touches on, based on indicator type and classification.
  This is a heuristic suggestion, not a confirmed mapping — use it to
  prioritize what to look into, not as a finished assessment.

## Command line

Everything the web UI does is also available from `cli.py`, if you'd
rather script it or run it in a pipeline:

```bash
python cli.py serve                          # launch the web UI
echo "1.2.3.4 evil.com" | python cli.py paste # extract from stdin
python cli.py extract report.pdf              # extract from a file or URL
python cli.py list --class=malicious          # list stored IOCs
python cli.py hunt --platform=sigma           # print hunt queries to stdout
python cli.py report exec                     # executive report, as JSON
python cli.py report analyst                  # analyst report, as JSON
```

## Where your data lives

Everything's in a single SQLite file at `~/.spy-threat-hunt/iocs.db`. To
point it somewhere else (say, a separate ledger per engagement), set
`SPYHUNT_DATA_DIR` before launching:

```bash
SPYHUNT_DATA_DIR=~/cases/acme-2026 python cli.py serve
```

There's no built-in multi-user or auth layer — this is meant to run
locally on one analyst's machine. If you need to share results, use the
export feature.
