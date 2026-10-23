"""SQLite database management for AURALERT case files, evidence, and events.

Implements migrations, WAL mode for concurrent access, foreign-key cascading,
and thread-safe connection pooling.
"""

import hashlib
import json
import os
import random
import re
import secrets
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_DB_PATH = "./data/auralert.db"

PHONETIC_WORDS = [
    "shield",
    "falcon",
    "bravo",
    "tiger",
    "aurora",
    "delta",
    "eagle",
    "harbor",
    "zenith",
    "apex",
    "beacon",
    "citadel",
]


MAX_ID_ATTEMPTS = 50


def generate_speakable_case_id() -> str:
    """Generate a short, voice-speakable Case ID (e.g. shield-482)."""
    word = random.choice(PHONETIC_WORDS)
    num = random.randint(100, 999)
    return f"{word}-{num}"


def get_db_path() -> str:
    """Resolve database path from DB_PATH env var or default."""
    path_str = os.getenv("DB_PATH", DEFAULT_DB_PATH)
    if path_str != ":memory:":
        db_file = Path(path_str).resolve()
        db_file.parent.mkdir(parents=True, exist_ok=True)
        return str(db_file)
    return path_str


def get_connection() -> sqlite3.Connection:
    """Create a configured SQLite connection with WAL mode and foreign keys enabled."""
    db_path = get_db_path()
    conn = sqlite3.connect(db_path, timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    # Configure SQLite pragmas for safety and concurrency
    if db_path != ":memory:":
        conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@contextmanager
def db_session() -> Generator[sqlite3.Connection, None, None]:
    """Context manager for atomic database operations."""
    conn = get_connection()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def run_migrations(conn: sqlite3.Connection) -> None:
    """Execute schema creation and migrations."""
    schema_sql = """
    CREATE TABLE IF NOT EXISTS cases (
        id TEXT PRIMARY KEY,
        title TEXT,
        region TEXT NOT NULL DEFAULT 'IN',
        status TEXT NOT NULL DEFAULT 'open',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evidence (
        id TEXT NOT NULL,
        case_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        content TEXT NOT NULL,
        analysis_json TEXT,
        created_at TEXT NOT NULL,
        PRIMARY KEY (case_id, id),
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        description TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS safe_words (
        contact_name TEXT PRIMARY KEY COLLATE NOCASE,
        relationship TEXT NOT NULL DEFAULT 'Family',
        salt TEXT NOT NULL,
        hash_val TEXT NOT NULL,
        hint TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS threat_indicators (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        case_id TEXT NOT NULL,
        indicator_type TEXT NOT NULL,
        indicator_value TEXT NOT NULL,
        raw_value TEXT NOT NULL,
        threat_category TEXT,
        risk_score INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_evidence_case_id ON evidence(case_id);
    CREATE INDEX IF NOT EXISTS idx_events_case_id ON events(case_id);
    CREATE INDEX IF NOT EXISTS idx_indicators_lookup ON threat_indicators(indicator_type, indicator_value);
    CREATE INDEX IF NOT EXISTS idx_indicators_case ON threat_indicators(case_id);
    """
    conn.executescript(schema_sql)


def init_db() -> None:
    """Initialize database tables and indexes."""
    with db_session() as conn:
        run_migrations(conn)


def create_case(
    title: str | None = None,
    region: str = "IN",
    case_id: str | None = None,
) -> dict[str, Any]:
    """Create a new case record and log initial event.

    Auto-generated speakable IDs are retried on collision so that opening a case can
    never fail just because a random ID was already taken. An explicitly supplied
    case_id that already exists still raises sqlite3.IntegrityError.
    """
    now = datetime.now(UTC).isoformat()
    clean_title = (title or "Suspected Scam Incident").strip()
    clean_region = (region or "IN").upper().strip()
    explicit_id = (case_id or "").lower().strip() or None
    attempts = 1 if explicit_id else MAX_ID_ATTEMPTS

    for attempt in range(attempts):
        cid = explicit_id or generate_speakable_case_id()
        try:
            with db_session() as conn:
                conn.execute(
                    """
                    INSERT INTO cases (id, title, region, status, created_at, updated_at)
                    VALUES (?, ?, ?, 'open', ?, ?)
                    """,
                    (cid, clean_title, clean_region, now, now),
                )
                conn.execute(
                    """
                    INSERT INTO events (case_id, event_type, description, timestamp)
                    VALUES (?, 'case_opened', ?, ?)
                    """,
                    (cid, f"Case opened with title '{clean_title}'", now),
                )
        except sqlite3.IntegrityError:
            if explicit_id or attempt == attempts - 1:
                raise
            continue
        return {
            "id": cid,
            "title": clean_title,
            "region": clean_region,
            "status": "open",
            "created_at": now,
        }
    raise RuntimeError("Could not allocate a unique case id")  # pragma: no cover


def insert_evidence(
    case_id: str,
    kind: str,
    content: str,
    analysis: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Insert a piece of evidence linked to a case."""
    now = datetime.now(UTC).isoformat()
    cid = case_id.lower().strip()

    with db_session() as conn:
        # Verify case exists
        row = conn.execute("SELECT id FROM cases WHERE id = ?", (cid,)).fetchone()
        if not row:
            raise ValueError(f"Case '{case_id}' does not exist.")

        # Determine evidence ID
        count_row = conn.execute(
            "SELECT COUNT(*) as count FROM evidence WHERE case_id = ?",
            (cid,),
        ).fetchone()
        next_num = (count_row["count"] if count_row else 0) + 1
        ev_id = f"ev-{next_num}"

        analysis_str = json.dumps(analysis) if analysis else None

        conn.execute(
            """
            INSERT INTO evidence (id, case_id, kind, content, analysis_json, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (ev_id, cid, kind, content, analysis_str, now),
        )

        # Log timeline event
        snippet = content[:50] + ("..." if len(content) > 50 else "")
        conn.execute(
            """
            INSERT INTO events (case_id, event_type, description, timestamp)
            VALUES (?, 'evidence_added', ?, ?)
            """,
            (cid, f"Added {kind} evidence ({ev_id}): {snippet}", now),
        )

        # Update case updated_at
        conn.execute(
            "UPDATE cases SET updated_at = ? WHERE id = ?",
            (now, cid),
        )

    return {
        "id": ev_id,
        "case_id": cid,
        "kind": kind,
        "content": content,
        "analysis": analysis,
        "created_at": now,
    }


def fetch_case(case_id: str) -> dict[str, Any] | None:
    """Fetch full case record with evidence items and timeline events."""
    cid = case_id.lower().strip()
    with db_session() as conn:
        case_row = conn.execute(
            "SELECT * FROM cases WHERE id = ?",
            (cid,),
        ).fetchone()
        if not case_row:
            return None

        evidence_rows = conn.execute(
            "SELECT * FROM evidence WHERE case_id = ? ORDER BY created_at ASC",
            (cid,),
        ).fetchall()

        event_rows = conn.execute(
            "SELECT * FROM events WHERE case_id = ? ORDER BY timestamp ASC",
            (cid,),
        ).fetchall()

    evidence_list = []
    for r in evidence_rows:
        analysis_obj = json.loads(r["analysis_json"]) if r["analysis_json"] else None
        evidence_list.append(
            {
                "evidence_id": r["id"],
                "kind": r["kind"],
                "content": r["content"],
                "analysis": analysis_obj,
                "created_at": r["created_at"],
            }
        )

    timeline_list = [
        {
            "event_type": e["event_type"],
            "description": e["description"],
            "timestamp": e["timestamp"],
        }
        for e in event_rows
    ]

    return {
        "case_id": case_row["id"],
        "title": case_row["title"],
        "region": case_row["region"],
        "status": case_row["status"],
        "created_at": case_row["created_at"],
        "updated_at": case_row["updated_at"],
        "evidence": evidence_list,
        "timeline": timeline_list,
    }


def delete_case(case_id: str) -> bool:
    """Internal function to delete a case and all associated evidence/events (cascading)."""
    cid = case_id.lower().strip()
    with db_session() as conn:
        cursor = conn.execute("DELETE FROM cases WHERE id = ?", (cid,))
        return cursor.rowcount > 0


# ============================================================================
# FAMILY SAFE-WORD MANAGEMENT
# ============================================================================


def save_safe_word(
    contact_name: str,
    safe_word: str,
    relationship: str = "Family",
    hint: str | None = None,
) -> dict[str, Any]:
    """Store or update a salted SHA-256 hash of a secret family safe word.

    Never stores safe words in cleartext to protect family privacy.
    """
    clean_name = contact_name.strip()
    clean_rel = relationship.strip() or "Family"
    clean_word = safe_word.strip().lower()
    clean_hint = (hint or "").strip() or None
    now = datetime.now(UTC).isoformat()

    salt = secrets.token_hex(16)
    hash_val = hashlib.sha256((salt + clean_word).encode("utf-8")).hexdigest()

    with db_session() as conn:
        conn.execute(
            """
            INSERT INTO safe_words (contact_name, relationship, salt, hash_val, hint, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(contact_name) DO UPDATE SET
                relationship = excluded.relationship,
                salt = excluded.salt,
                hash_val = excluded.hash_val,
                hint = excluded.hint,
                updated_at = excluded.updated_at
            """,
            (clean_name, clean_rel, salt, hash_val, clean_hint, now, now),
        )

    return {
        "contact_name": clean_name,
        "relationship": clean_rel,
        "hint": clean_hint,
        "created_at": now,
        "status": "active",
    }


def check_safe_word(contact_name: str, candidate_word: str) -> dict[str, Any]:
    """Verify whether a candidate safe word matches the registered family contact's secret."""
    clean_name = contact_name.strip()
    candidate_norm = (candidate_word or "").strip().lower()

    with db_session() as conn:
        row = conn.execute(
            "SELECT contact_name, relationship, salt, hash_val, hint FROM safe_words WHERE contact_name = ? COLLATE NOCASE",
            (clean_name,),
        ).fetchone()

    if not row:
        return {
            "found": False,
            "matched": False,
            "contact_name": clean_name,
            "relationship": "Unknown",
            "hint": None,
        }

    salt = row["salt"]
    expected_hash = row["hash_val"]
    candidate_hash = hashlib.sha256((salt + candidate_norm).encode("utf-8")).hexdigest()
    is_match = secrets.compare_digest(candidate_hash, expected_hash)

    return {
        "found": True,
        "matched": is_match,
        "contact_name": row["contact_name"],
        "relationship": row["relationship"],
        "hint": row["hint"],
    }


def list_safe_words() -> list[dict[str, Any]]:
    """List registered safe-word contacts without exposing secret hashes."""
    with db_session() as conn:
        rows = conn.execute(
            "SELECT contact_name, relationship, hint, created_at, updated_at FROM safe_words ORDER BY contact_name ASC"
        ).fetchall()

    return [
        {
            "contact_name": r["contact_name"],
            "relationship": r["relationship"],
            "hint": r["hint"],
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }
        for r in rows
    ]


def delete_safe_word(contact_name: str) -> bool:
    """Remove a registered family safe-word contact."""
    with db_session() as conn:
        cursor = conn.execute(
            "DELETE FROM safe_words WHERE contact_name = ? COLLATE NOCASE",
            (contact_name.strip(),),
        )
        return cursor.rowcount > 0


# ============================================================================
# REPEAT-OFFENDER MEMORY & THREAT INDICATORS
# ============================================================================


def normalize_indicator(indicator_type: str, raw_value: str) -> str:
    """Normalize phone numbers, UPI IDs, domains, and URLs for robust cross-case matching."""
    val = raw_value.strip()
    if indicator_type == "phone":
        digits = re.sub(r"\D", "", val)
        # Canonicalize 10-digit Indian / US numbers if prefixed with 91 or 1 or leading 0
        if len(digits) == 12 and digits.startswith("91"):
            return digits[-10:]
        if len(digits) == 11 and (digits.startswith("0") or digits.startswith("1")):
            return digits[-10:]
        return digits
    elif indicator_type == "upi_id":
        return val.lower()
    elif indicator_type in ("domain", "url"):
        candidate = (
            val if (val.startswith("http://") or val.startswith("https://")) else f"http://{val}"
        )
        parsed = urlparse(candidate)
        host = (parsed.netloc or parsed.path).split("/")[0].split(":")[0].lower()
        return re.sub(r"^www\.", "", host)
    return val.lower()


def extract_indicators_from_text(text: str) -> list[dict[str, str]]:
    """Extract candidate phones, UPI IDs, and URLs/domains from text."""
    if not text:
        return []

    results: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    # 1. Phone numbers: 10-digit mobile or international formats
    phone_pattern = r"(?:\+?\d{1,3}[-.\s]?)?(?:\d{5}[-.\s]?\d{5}|\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b[6-9]\d{9}\b)"
    for match in re.finditer(phone_pattern, text):
        raw = match.group(0).strip()
        digits = re.sub(r"\D", "", raw)
        if len(digits) >= 10:
            norm = normalize_indicator("phone", raw)
            if ("phone", norm) not in seen:
                seen.add(("phone", norm))
                results.append({"type": "phone", "raw": raw, "normalized": norm})

    # 2. UPI IDs (e.g. user@okaxis, fraud@paytm, support@ybl)
    upi_pattern = r"\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b"
    for match in re.finditer(upi_pattern, text):
        raw = match.group(0).strip()
        # Verify UPI context or recognized payment domain
        lower_raw = raw.lower()
        if (
            any(
                handle in lower_raw
                for handle in (
                    "@okaxis",
                    "@okhdfc",
                    "@oksbi",
                    "@okicici",
                    "@paytm",
                    "@ibl",
                    "@ybl",
                    "@axl",
                    "@upi",
                    "@postbank",
                    "@apl",
                    "@barodampay",
                )
            )
            or "upi" in text.lower()
        ):
            norm = normalize_indicator("upi_id", raw)
            if ("upi_id", norm) not in seen:
                seen.add(("upi_id", norm))
                results.append({"type": "upi_id", "raw": raw, "normalized": norm})

    # 3. URLs and Domains
    url_pattern = r"https?://[^\s<>\"']+|www\.[^\s<>\"']+|[a-zA-Z0-9.-]+\.(?:top|xyz|live|fit|online|info|pw|site|club|work|vip|click|rest|link|buzz|icu|sbs|monster)[^\s<>\"']*"
    for match in re.finditer(url_pattern, text):
        raw = match.group(0).strip()
        norm_domain = normalize_indicator("domain", raw)
        if norm_domain and ("domain", norm_domain) not in seen:
            seen.add(("domain", norm_domain))
            results.append({"type": "domain", "raw": raw, "normalized": norm_domain})

    return results


def index_indicators_for_case(
    case_id: str,
    text: str,
    threat_category: str | None = None,
    risk_score: int = 0,
) -> list[dict[str, Any]]:
    """Extract and index threat indicators for a case file to enable repeat-offender memory."""
    cid = case_id.lower().strip()
    extracted = extract_indicators_from_text(text)
    if not extracted:
        return []

    now = datetime.now(UTC).isoformat()
    inserted: list[dict[str, Any]] = []

    with db_session() as conn:
        for item in extracted:
            itype = item["type"]
            norm_val = item["normalized"]
            raw_val = item["raw"]

            # Avoid duplicate indicator for same case
            existing = conn.execute(
                """
                SELECT id FROM threat_indicators
                WHERE case_id = ? AND indicator_type = ? AND indicator_value = ?
                """,
                (cid, itype, norm_val),
            ).fetchone()

            if not existing:
                conn.execute(
                    """
                    INSERT INTO threat_indicators (case_id, indicator_type, indicator_value, raw_value, threat_category, risk_score, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        cid,
                        itype,
                        norm_val,
                        raw_val,
                        threat_category or "general_fraud",
                        risk_score,
                        now,
                    ),
                )
                inserted.append(item)

    return inserted


def find_repeat_offenders(
    indicator_value: str,
    indicator_type: str = "auto",
    exclude_case_id: str | None = None,
) -> dict[str, Any]:
    """Search for repeat offender intelligence across cases by phone, UPI ID, or domain."""
    raw = indicator_value.strip()
    clean_exclude = (exclude_case_id or "").lower().strip()

    # Auto-detect type if requested
    detected_type = indicator_type.lower()
    if detected_type == "auto":
        if "@" in raw:
            detected_type = "upi_id"
        elif any(tld in raw.lower() for tld in (".", "http://", "https://")) and not re.match(
            r"^[\d.\s+-]+$", raw
        ):
            detected_type = "domain"
        else:
            detected_type = "phone"

    norm_val = normalize_indicator(detected_type, raw)

    with db_session() as conn:
        query = """
        SELECT
            ti.indicator_type,
            ti.indicator_value,
            ti.raw_value,
            ti.threat_category,
            ti.risk_score,
            ti.created_at,
            c.id AS case_id,
            c.title AS case_title,
            c.region AS case_region,
            c.status AS case_status
        FROM threat_indicators ti
        JOIN cases c ON ti.case_id = c.id
        WHERE ti.indicator_type = ? AND ti.indicator_value = ?
        """
        params: list[Any] = [detected_type, norm_val]
        if clean_exclude:
            query += " AND ti.case_id != ?"
            params.append(clean_exclude)

        query += " ORDER BY ti.created_at DESC"
        rows = conn.execute(query, tuple(params)).fetchall()

    if not rows:
        return {
            "found": False,
            "indicator": raw,
            "indicator_type": detected_type,
            "normalized_value": norm_val,
            "match_count": 0,
            "earlier_cases": [],
            "summary": f"No previous cases found matching {detected_type} '{raw}'.",
            "is_repeat_offender": False,
        }

    # Deduplicate by case_id
    cases_seen: dict[str, dict[str, Any]] = {}
    for r in rows:
        cid = r["case_id"]
        if cid not in cases_seen:
            cases_seen[cid] = {
                "case_id": cid,
                "title": r["case_title"],
                "region": r["case_region"],
                "status": r["case_status"],
                "category": r["threat_category"],
                "risk_score": r["risk_score"],
                "logged_at": r["created_at"],
            }

    earlier_cases = list(cases_seen.values())
    match_count = len(earlier_cases)
    is_repeat = match_count > 0

    case_refs = ", ".join(f"#{c['case_id']}" for c in earlier_cases[:3])
    if match_count == 1:
        summary = f"This {detected_type} appeared in 1 earlier case ({case_refs})."
    else:
        summary = f"This {detected_type} appeared in {match_count} earlier cases ({case_refs}). Repeat offender detected!"

    return {
        "found": True,
        "indicator": raw,
        "indicator_type": detected_type,
        "normalized_value": norm_val,
        "match_count": match_count,
        "earlier_cases": earlier_cases,
        "summary": summary,
        "is_repeat_offender": is_repeat,
    }


def export_all_threat_indicators() -> dict[str, Any]:
    """Export all accumulated threat indicators in standardized Cyber Threat Intelligence (CTI) JSON."""
    with db_session() as conn:
        rows = conn.execute(
            """
            SELECT
                ti.indicator_type,
                ti.indicator_value,
                ti.raw_value,
                ti.threat_category,
                ti.risk_score,
                ti.created_at,
                ti.case_id,
                c.region
            FROM threat_indicators ti
            LEFT JOIN cases c ON ti.case_id = c.id
            ORDER BY ti.created_at ASC
            """
        ).fetchall()

    # Aggregate by (indicator_type, indicator_value)
    aggregated: dict[tuple[str, str], dict[str, Any]] = {}
    for r in rows:
        key = (r["indicator_type"], r["indicator_value"])
        if key not in aggregated:
            aggregated[key] = {
                "indicator_type": r["indicator_type"],
                "indicator_value": r["indicator_value"],
                "sample_raw_value": r["raw_value"],
                "first_seen": r["created_at"],
                "last_seen": r["created_at"],
                "occurrence_count": 0,
                "associated_cases": set(),
                "threat_categories": set(),
                "regions": set(),
                "max_risk_score": 0,
            }
        rec = aggregated[key]
        rec["occurrence_count"] += 1
        rec["last_seen"] = r["created_at"]
        if r["case_id"]:
            rec["associated_cases"].add(r["case_id"])
        if r["threat_category"]:
            rec["threat_categories"].add(r["threat_category"])
        if r["region"]:
            rec["regions"].add(r["region"])
        rec["max_risk_score"] = max(rec["max_risk_score"], r["risk_score"] or 0)

    indicators_list = []
    for rec in aggregated.values():
        max_risk = rec["max_risk_score"]
        if max_risk >= 80:
            threat_level = "CRITICAL"
        elif max_risk >= 50 or rec["indicator_type"] in ("upi_id", "domain"):
            threat_level = "HIGH"
        elif max_risk >= 20 or len(rec["associated_cases"]) > 0:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        indicators_list.append(
            {
                "indicator_type": rec["indicator_type"],
                "indicator_value": rec["indicator_value"],
                "sample_raw_value": rec["sample_raw_value"],
                "first_seen": rec["first_seen"],
                "last_seen": rec["last_seen"],
                "occurrence_count": rec["occurrence_count"],
                "is_repeat_offender": rec["occurrence_count"] > 1,
                "threat_level": threat_level,
                "max_risk_score": max_risk,
                "threat_categories": sorted(rec["threat_categories"]),
                "associated_cases": sorted(rec["associated_cases"]),
                "regions": sorted(rec["regions"]),
            }
        )

    # Sort so highest occurrence and risk come first
    indicators_list.sort(key=lambda x: (x["occurrence_count"], x["max_risk_score"]), reverse=True)

    return {
        "feed_name": "AURALERT Cyber Threat Intelligence Feed",
        "feed_version": "1.0",
        "format": "STIX-compatible CTI Indicators",
        "generated_at": datetime.now(UTC).isoformat(),
        "total_unique_indicators": len(indicators_list),
        "total_repeat_offenders": sum(1 for i in indicators_list if i["is_repeat_offender"]),
        "indicators": indicators_list,
    }
