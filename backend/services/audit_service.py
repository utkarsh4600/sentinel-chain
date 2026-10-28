"""Audit Service for Sentinel Chain immutable event logging."""

import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from ..database import execute_commit, execute_query, execute_one

def log_audit_event(
    actor: str,
    action: str,
    target: str,
    ip: str = "127.0.0.1",
    result: str = "success"
) -> Dict[str, Any]:
    """Record an audit trail event with tamper-evident cryptographic hash."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    
    last_row = execute_one("SELECT id FROM audit_logs ORDER BY rowid DESC LIMIT 1")
    if last_row and last_row["id"].startswith("AUD-"):
        try:
            num = int(last_row["id"].replace("AUD-", "")) + 1
        except ValueError:
            num = 1010
    else:
        num = 1010
    aud_id = f"AUD-{num}"

    payload = f"{aud_id}:{actor}:{action}:{target}:{timestamp}:{ip}:{result}"
    audit_hash = "0x" + hashlib.sha256(payload.encode("utf-8")).hexdigest()

    execute_commit(
        """INSERT INTO audit_logs 
        (id, actor, action, target, timestamp, ip, result, audit_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (aud_id, actor, action, target, timestamp, ip, result, audit_hash)
    )

    return {
        "id": aud_id,
        "actor": actor,
        "action": action,
        "target": target,
        "timestamp": timestamp,
        "ip": ip,
        "result": result,
        "auditHash": audit_hash
    }

def get_audit_logs(limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
    """Retrieve audit events in reverse chronological order."""
    rows = execute_query(
        "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        (limit, offset)
    )
    return [
        {
            "id": r["id"],
            "actor": r["actor"],
            "action": r["action"],
            "target": r["target"],
            "timestamp": r["timestamp"],
            "ip": r["ip"],
            "result": r["result"],
            "auditHash": r.get("audit_hash", "")
        }
        for r in rows
    ]
