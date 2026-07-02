"""
SPY-THREAT-HUNT V2 :: storage layer
Local SQLite DB — no cloud, no accounts, data stays on disk.
"""
import json
import os
import sqlite3
from pathlib import Path
from typing import List, Optional

DATA_DIR = Path(os.environ.get("SPYHUNT_DATA_DIR", Path.home() / ".spy-threat-hunt"))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "iocs.db"


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def migrate():
    conn = get_conn()
    conn.execute("""CREATE TABLE IF NOT EXISTS iocs (
        id TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        type TEXT NOT NULL,
        classification TEXT NOT NULL DEFAULT 'unknown',
        source TEXT NOT NULL,
        source_url TEXT,
        source_file TEXT,
        extracted_at TEXT NOT NULL,
        enriched_at TEXT,
        enrichment TEXT,
        tags TEXT NOT NULL DEFAULT '[]',
        notes TEXT,
        tlp TEXT,
        ignored INTEGER NOT NULL DEFAULT 0,
        hunt_status TEXT NOT NULL DEFAULT 'unconfirmed',
        hunt_name TEXT,
        source_ref TEXT
    )""")
    conn.execute("""CREATE TABLE IF NOT EXISTS sources (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        ref_id TEXT UNIQUE NOT NULL,
        type TEXT NOT NULL,
        label TEXT NOT NULL,
        detail TEXT,
        created_at TEXT NOT NULL
    )""")
    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_iocs_value_type ON iocs(value, type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_classification ON iocs(classification)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_extracted_at ON iocs(extracted_at)")
    # migration-safe additions for DBs created before these columns existed
    existing_cols = {row["name"] for row in conn.execute("PRAGMA table_info(iocs)")}
    if "hunt_status" not in existing_cols:
        conn.execute("ALTER TABLE iocs ADD COLUMN hunt_status TEXT NOT NULL DEFAULT 'unconfirmed'")
    if "hunt_name" not in existing_cols:
        conn.execute("ALTER TABLE iocs ADD COLUMN hunt_name TEXT")
    if "source_ref" not in existing_cols:
        conn.execute("ALTER TABLE iocs ADD COLUMN source_ref TEXT")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_hunt_status ON iocs(hunt_status)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_iocs_source_ref ON iocs(source_ref)")
    conn.commit()
    conn.close()


def create_source(type_: str, label: str, detail: Optional[str] = None) -> str:
    """Registers a new source (paste/url/file/feed) and returns its short
    reference id, e.g. 'SRC_7'. Every IOC extracted in that batch gets
    tagged with this id so you can trace it back to where it came from."""
    from datetime import datetime, timezone
    conn = get_conn()
    now = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO sources (ref_id, type, label, detail, created_at) VALUES ('', ?, ?, ?, ?)",
        (type_, label, detail, now),
    )
    seq = cur.lastrowid
    ref_id = f"SRC_{seq}"
    conn.execute("UPDATE sources SET ref_id = ? WHERE seq = ?", (ref_id, seq))
    conn.commit()
    conn.close()
    return ref_id


def get_or_create_source(type_: str, label: str, detail: Optional[str] = None) -> str:
    """Same as create_source, but reuses an existing source if one already
    exists for this exact (type, detail) — or (type, label) when there's no
    detail, e.g. pasted text. Prevents re-pulling the same feed/URL/file from
    minting a fresh SRC_# every time."""
    key = detail if detail else label
    conn = get_conn()
    row = conn.execute(
        "SELECT ref_id FROM sources WHERE type = ? AND COALESCE(detail, label) = ? ORDER BY seq DESC LIMIT 1",
        (type_, key),
    ).fetchone()
    conn.close()
    if row:
        return row["ref_id"]
    return create_source(type_, label, detail)


def filter_new(pairs: List[tuple]) -> List[tuple]:
    """pairs: list of (value, type) tuples. Returns only the ones that are
    NOT already in the ledger — i.e. would actually be new rows if inserted."""
    if not pairs:
        return []
    conn = get_conn()
    new_pairs = []
    for value, type_ in pairs:
        row = conn.execute(
            "SELECT 1 FROM iocs WHERE value = ? AND type = ?", (value, type_)
        ).fetchone()
        if not row:
            new_pairs.append((value, type_))
    conn.close()
    return new_pairs


def list_sources() -> List[dict]:
    conn = get_conn()
    # prune any source that ended up crediting zero indicators — these were
    # created before the get-or-create/filter-new logic existed, or from a
    # batch where everything turned out to be a duplicate
    conn.execute("""
        DELETE FROM sources WHERE ref_id NOT IN (
            SELECT DISTINCT source_ref FROM iocs WHERE source_ref IS NOT NULL
        )
    """)
    conn.commit()
    rows = conn.execute("""
        SELECT s.ref_id, s.type, s.label, s.detail, s.created_at,
               (SELECT COUNT(*) FROM iocs WHERE source_ref = s.ref_id) AS ioc_count
        FROM sources s ORDER BY s.seq DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def _row_to_dict(row) -> dict:
    d = dict(row)
    d["tags"] = json.loads(d.get("tags") or "[]")
    d["enrichment"] = json.loads(d["enrichment"]) if d.get("enrichment") else None
    d["ignored"] = bool(d.get("ignored", 0))
    d["hunt_status"] = d.get("hunt_status") or "unconfirmed"
    return d


def upsert_ioc(ioc: dict) -> bool:
    conn = get_conn()
    existing = conn.execute(
        "SELECT id FROM iocs WHERE value = ? AND type = ?", (ioc["value"], ioc["type"])
    ).fetchone()
    if existing:
        conn.close()
        return False
    conn.execute(
        """INSERT INTO iocs (id, value, type, classification, source, source_url, source_file,
           extracted_at, enriched_at, enrichment, tags, notes, tlp, ignored, hunt_name, source_ref)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            ioc["id"], ioc["value"], ioc["type"], ioc.get("classification", "unknown"),
            ioc.get("source", "manual"), ioc.get("source_url"), ioc.get("source_file"),
            ioc["extracted_at"], ioc.get("enriched_at"),
            json.dumps(ioc["enrichment"]) if ioc.get("enrichment") else None,
            json.dumps(ioc.get("tags", [])), ioc.get("notes"), ioc.get("tlp"),
            int(ioc.get("ignored", False)), ioc.get("hunt_name"), ioc.get("source_ref"),
        ),
    )
    conn.commit()
    conn.close()
    return True


def bulk_upsert(iocs: List[dict]) -> List[str]:
    """Inserts new IOCs, skipping ones that already exist (by value+type).
    Returns the list of ids that were actually newly inserted."""
    inserted_ids = []
    for ioc in iocs:
        if upsert_ioc(ioc):
            inserted_ids.append(ioc["id"])
    return inserted_ids


def list_iocs(
    type_: Optional[List[str]] = None,
    classification: Optional[List[str]] = None,
    search: Optional[str] = None,
    include_ignored: bool = False,
    hunt_status: Optional[List[str]] = None,
    limit: int = 500,
    offset: int = 0,
) -> List[dict]:
    conn = get_conn()
    clauses, args = [], []
    if type_:
        clauses.append(f"type IN ({','.join('?' * len(type_))})")
        args.extend(type_)
    if classification:
        clauses.append(f"classification IN ({','.join('?' * len(classification))})")
        args.extend(classification)
    if hunt_status:
        clauses.append(f"hunt_status IN ({','.join('?' * len(hunt_status))})")
        args.extend(hunt_status)
    if search:
        clauses.append("value LIKE ?")
        args.append(f"%{search}%")
    if not include_ignored:
        clauses.append("ignored = 0")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    rows = conn.execute(
        f"SELECT * FROM iocs {where} ORDER BY extracted_at DESC LIMIT ? OFFSET ?",
        (*args, limit, offset),
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def get_stats() -> dict:
    conn = get_conn()
    total = conn.execute("SELECT COUNT(*) c FROM iocs WHERE ignored = 0").fetchone()["c"]
    by_type = {r["type"]: r["c"] for r in conn.execute(
        "SELECT type, COUNT(*) c FROM iocs WHERE ignored = 0 GROUP BY type")}
    by_class = {r["classification"]: r["c"] for r in conn.execute(
        "SELECT classification, COUNT(*) c FROM iocs WHERE ignored = 0 GROUP BY classification")}
    conn.close()
    return {"total": total, "byType": by_type, "byClassification": by_class}


def update_ioc(ioc_id: str, fields: dict) -> bool:
    if not fields:
        return False
    conn = get_conn()
    sets, args = [], []
    for k, v in fields.items():
        col = {"classification": "classification", "notes": "notes", "tlp": "tlp",
               "ignored": "ignored", "tags": "tags", "enrichment": "enrichment",
               "enriched_at": "enriched_at", "hunt_status": "hunt_status",
               "hunt_name": "hunt_name", "source_ref": "source_ref"}.get(k)
        if not col:
            continue
        if k == "tags":
            v = json.dumps(v)
        if k == "enrichment":
            v = json.dumps(v) if v else None
        if k == "ignored":
            v = int(v)
        sets.append(f"{col} = ?")
        args.append(v)
    if not sets:
        conn.close()
        return False
    args.append(ioc_id)
    conn.execute(f"UPDATE iocs SET {', '.join(sets)} WHERE id = ?", args)
    conn.commit()
    conn.close()
    return True


def delete_ioc(ioc_id: str) -> bool:
    conn = get_conn()
    conn.execute("DELETE FROM iocs WHERE id = ?", (ioc_id,))
    conn.commit()
    conn.close()
    return True


def bulk_update(ids: List[str], fields: dict) -> int:
    count = 0
    for ioc_id in ids:
        if update_ioc(ioc_id, fields):
            count += 1
    return count


def get_by_ids(ids: List[str]) -> List[dict]:
    if not ids:
        return []
    conn = get_conn()
    rows = conn.execute(
        f"SELECT * FROM iocs WHERE id IN ({','.join('?' * len(ids))})", ids
    ).fetchall()
    conn.close()
    return [_row_to_dict(r) for r in rows]


def clear_all():
    conn = get_conn()
    conn.execute("DELETE FROM iocs")
    conn.commit()
    conn.close()
