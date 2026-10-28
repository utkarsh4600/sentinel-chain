"""
Thread-safe SQLite Database Layer for Sentinel Chain.
Handles schema migrations, WAL mode, indexing, and automatic dataset seeding.
"""

import sqlite3
import json
import logging
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from .config import DB_PATH, SEED_DATA_PATH

logger = logging.getLogger("sentinel.db")

_local = threading.local()

def get_connection() -> sqlite3.Connection:
    """Get or create a thread-local SQLite connection."""
    if not hasattr(_local, "conn") or _local.conn is None:
        DB_PATH.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        # Enable write-ahead logging for high concurrency
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        _local.conn = conn
    return _local.conn

def execute_query(sql: str, params: Tuple = ()) -> List[Dict[str, Any]]:
    """Execute a SELECT query and return a list of dictionaries."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(sql, params)
    rows = cur.fetchall()
    return [dict(row) for row in rows]

def execute_one(sql: str, params: Tuple = ()) -> Optional[Dict[str, Any]]:
    """Execute a SELECT query and return a single dictionary row or None."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(sql, params)
    row = cur.fetchone()
    return dict(row) if row else None

def execute_commit(sql: str, params: Tuple = ()) -> int:
    """Execute an INSERT, UPDATE, or DELETE query and commit."""
    conn = get_connection()
    cur = conn.cursor()
    cur.execute(sql, params)
    conn.commit()
    return cur.lastrowid

def execute_many(sql: str, params_list: List[Tuple]) -> int:
    """Execute batch operations in a single transaction."""
    conn = get_connection()
    cur = conn.cursor()
    cur.executemany(sql, params_list)
    conn.commit()
    return cur.rowcount

def init_db():
    """Create all required tables, indexes, and seed initial records if empty."""
    conn = get_connection()
    cur = conn.cursor()

    cur.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'Analyst',
        status TEXT NOT NULL DEFAULT 'active',
        last_active TEXT,
        mfa_enabled INTEGER NOT NULL DEFAULT 0,
        mfa_secret TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS threats (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        source TEXT NOT NULL,
        source_ip TEXT,
        target_asset TEXT,
        country TEXT,
        attack_type TEXT,
        status TEXT NOT NULL DEFAULT 'open',
        detected_at TEXT NOT NULL,
        ai_confidence INTEGER DEFAULT 50,
        mitre_technique TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_threats_status ON threats(status);
    CREATE INDEX IF NOT EXISTS idx_threats_severity ON threats(severity);
    CREATE INDEX IF NOT EXISTS idx_threats_detected_at ON threats(detected_at);

    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        assigned_to TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        affected_assets_json TEXT,
        description TEXT,
        mitre_techniques_json TEXT,
        ai_recommendation TEXT,
        blockchain_verified INTEGER DEFAULT 0,
        evidence_record_id TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
    CREATE INDEX IF NOT EXISTS idx_incidents_severity ON incidents(severity);

    CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        block_number INTEGER NOT NULL,
        tx_hash TEXT NOT NULL,
        incident_id TEXT NOT NULL,
        validator TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        verified INTEGER DEFAULT 1,
        digital_signature TEXT NOT NULL,
        prev_block_hash TEXT,
        data_hash TEXT,
        payload_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id);
    CREATE INDEX IF NOT EXISTS idx_evidence_block ON evidence(block_number);

    CREATE TABLE IF NOT EXISTS blocks (
        block_number INTEGER PRIMARY KEY,
        block_hash TEXT UNIQUE NOT NULL,
        prev_hash TEXT NOT NULL,
        merkle_root TEXT NOT NULL,
        validator TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        tx_count INTEGER DEFAULT 1,
        signature TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS assets (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        ip_address TEXT,
        owner TEXT,
        location TEXT,
        risk_score INTEGER DEFAULT 0,
        last_seen TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);

    CREATE TABLE IF NOT EXISTS alerts (
        id TEXT PRIMARY KEY,
        time TEXT NOT NULL,
        severity TEXT NOT NULL,
        source TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'open',
        created_at TEXT
    );

    CREATE TABLE IF NOT EXISTS soc_team (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        role TEXT NOT NULL,
        title TEXT,
        shift TEXT DEFAULT 'Day',
        incidents_resolved INTEGER DEFAULT 0,
        avg_response_time TEXT DEFAULT '8m',
        score INTEGER DEFAULT 85,
        email TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        ip TEXT NOT NULL,
        result TEXT NOT NULL DEFAULT 'success',
        audit_hash TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_logs(timestamp);

    CREATE TABLE IF NOT EXISTS compliance (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        full_name TEXT NOT NULL,
        status TEXT NOT NULL,
        score INTEGER NOT NULL,
        controls_passed INTEGER NOT NULL,
        controls_total INTEGER NOT NULL,
        last_audit TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        type TEXT NOT NULL,
        generated_at TEXT NOT NULL,
        generated_by TEXT NOT NULL,
        size_kb INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS iocs (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        value TEXT NOT NULL,
        threat_level TEXT NOT NULL,
        source TEXT NOT NULL,
        first_seen TEXT NOT NULL,
        tags_json TEXT
    );

    CREATE TABLE IF NOT EXISTS cves (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        cvss_score REAL NOT NULL,
        affected_product TEXT NOT NULL,
        published TEXT NOT NULL,
        exploit_available INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS ai_analyses (
        id TEXT PRIMARY KEY,
        model TEXT NOT NULL,
        target TEXT NOT NULL,
        verdict TEXT NOT NULL,
        confidence INTEGER NOT NULL,
        timestamp TEXT NOT NULL,
        top_features_json TEXT
    );
    """)
    conn.commit()

    # Seed if tables are empty
    seed_if_empty()

def seed_if_empty():
    """Populate database from seed_data.json if threats table is empty."""
    conn = get_connection()
    count = execute_one("SELECT count(*) as cnt FROM threats")["cnt"]
    if count > 0:
        return

    if not SEED_DATA_PATH.exists():
        logger.warning("Seed data file not found at %s", SEED_DATA_PATH)
        return

    with open(SEED_DATA_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    # 1. Users
    from .auth import hash_password
    default_salt, default_hash = hash_password("Sentinel@2026!")
    users = data.get("users", [])
    for u in users:
        execute_commit(
            """INSERT OR IGNORE INTO users 
            (id, name, email, password_hash, password_salt, role, status, last_active, mfa_enabled, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                u["id"], u["name"], u["email"], default_hash, default_salt,
                u.get("role", "Analyst"), u.get("status", "active"),
                u.get("lastActive", ""), 1 if u.get("mfaEnabled") else 0,
                "2026-01-01T00:00:00Z"
            )
        )

    # 2. Threats
    for t in data.get("threats", []):
        execute_commit(
            """INSERT OR IGNORE INTO threats 
            (id, title, severity, source, source_ip, target_asset, country, attack_type, status, detected_at, ai_confidence, mitre_technique)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                t["id"], t["title"], t["severity"], t["source"],
                t.get("sourceIp"), t.get("targetAsset"), t.get("country"),
                t.get("attackType"), t.get("status", "open"), t["detectedAt"],
                t.get("aiConfidence", 50), t.get("mitreTechnique")
            )
        )

    # 3. Incidents
    for inc in data.get("incidents", []):
        execute_commit(
            """INSERT OR IGNORE INTO incidents 
            (id, title, severity, status, assigned_to, created_at, updated_at, affected_assets_json, description, mitre_techniques_json, ai_recommendation, blockchain_verified, evidence_record_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                inc["id"], inc["title"], inc["severity"], inc.get("status", "open"),
                inc.get("assignedTo"), inc["createdAt"], inc.get("updatedAt", inc["createdAt"]),
                json.dumps(inc.get("affectedAssets", [])), inc.get("description", ""),
                json.dumps(inc.get("mitreTechniques", [])), inc.get("aiRecommendation", ""),
                1 if inc.get("blockchainVerified") else 0, inc.get("evidenceRecordId")
            )
        )

    # 4. Evidence
    for ev in data.get("evidence", []):
        execute_commit(
            """INSERT OR IGNORE INTO evidence 
            (id, block_number, tx_hash, incident_id, validator, timestamp, verified, digital_signature, prev_block_hash, data_hash, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ev["id"], ev["blockNumber"], ev["txHash"], ev["incidentId"],
                ev["validator"], ev["timestamp"], 1 if ev.get("verified") else 0,
                ev.get("digitalSignature", ""), "", "", "{}"
            )
        )

    # 5. Assets
    for ast in data.get("assets", []):
        execute_commit(
            """INSERT OR IGNORE INTO assets 
            (id, name, type, status, ip_address, owner, location, risk_score, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                ast["id"], ast["name"], ast["type"], ast.get("status", "active"),
                ast.get("ipAddress"), ast.get("owner"), ast.get("location"),
                ast.get("riskScore", 0), ast.get("lastSeen")
            )
        )

    # 6. Alerts
    for alt in data.get("alerts", []):
        execute_commit(
            """INSERT OR IGNORE INTO alerts 
            (id, time, severity, source, message, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                alt["id"], alt["time"], alt["severity"], alt["source"],
                alt["message"], alt.get("status", "open"), "2026-07-30T05:00:00Z"
            )
        )

    # 7. SOC Team
    for sc in data.get("soc", []):
        execute_commit(
            """INSERT OR IGNORE INTO soc_team 
            (id, name, role, title, shift, incidents_resolved, avg_response_time, score, email)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                f"SOC-{sc['name'].lower().replace(' ', '-')}", sc["name"], "Analyst",
                "Tier 2 Security Analyst", "Day", sc.get("resolved", 0),
                sc.get("avgResponse", "8m"), sc.get("score", 90),
                f"{sc['name'].lower().replace(' ', '.')}@sentinelchain.io"
            )
        )

    # 8. Audit Logs
    for aud in data.get("audit", []):
        execute_commit(
            """INSERT OR IGNORE INTO audit_logs 
            (id, actor, action, target, timestamp, ip, result, audit_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                aud["id"], aud["actor"], aud["action"], aud["target"],
                aud["timestamp"], aud["ip"], aud.get("result", "success"), ""
            )
        )

    # 9. Compliance
    for cp in data.get("compliance", []):
        execute_commit(
            """INSERT OR IGNORE INTO compliance 
            (id, name, full_name, status, score, controls_passed, controls_total, last_audit)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                cp["id"], cp["name"], cp["fullName"], cp["status"],
                cp["score"], cp["controlsPassed"], cp["controlsTotal"], cp["lastAudit"]
            )
        )

    # 10. Reports
    for rp in data.get("reports", []):
        execute_commit(
            """INSERT OR IGNORE INTO reports 
            (id, title, type, generated_at, generated_by, size_kb)
            VALUES (?, ?, ?, ?, ?, ?)""",
            (
                rp["id"], rp["title"], rp["type"], rp["generatedAt"],
                rp["generatedBy"], rp["sizeKb"]
            )
        )

    # 11. IOCs
    for ioc in data.get("iocs", []):
        execute_commit(
            """INSERT OR IGNORE INTO iocs 
            (id, type, value, threat_level, source, first_seen, tags_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                ioc["id"], ioc["type"], ioc["value"], ioc["threatLevel"],
                ioc["source"], ioc["firstSeen"], json.dumps(ioc.get("tags", []))
            )
        )

    # 12. CVEs
    for cv in data.get("cves", []):
        execute_commit(
            """INSERT OR IGNORE INTO cves 
            (id, title, severity, cvss_score, affected_product, published, exploit_available)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                cv["id"], cv["title"], cv["severity"], cv["cvssScore"],
                cv["affectedProduct"], cv["published"], 1 if cv.get("exploitAvailable") else 0
            )
        )

    # 13. AI Analysis
    for ai in data.get("ai_analysis", []):
        execute_commit(
            """INSERT OR IGNORE INTO ai_analyses 
            (id, model, target, verdict, confidence, timestamp, top_features_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                ai["id"], ai["model"], ai["target"], ai["verdict"],
                ai["confidence"], ai["timestamp"], json.dumps(ai.get("topFeatures", []))
            )
        )

    # Build initial cryptographic blockchain blocks from evidence records
    from .blockchain import initialize_ledger
    initialize_ledger()
