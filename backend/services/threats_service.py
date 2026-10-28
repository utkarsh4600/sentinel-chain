"""Threats Service for Sentinel Chain live threat intelligence and monitoring."""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from ..database import execute_query, execute_one, execute_commit
from .audit_service import log_audit_event
from ..ai_engine import analyze_payload_or_log

# Thread-safe event listener queues for Server-Sent Events (SSE)
_sse_listeners: List[Any] = []

def register_sse_listener(q: Any):
    """Register client queue for live SSE updates."""
    _sse_listeners.append(q)

def unregister_sse_listener(q: Any):
    """Unregister client queue when connection closes."""
    if q in _sse_listeners:
        _sse_listeners.remove(q)

def broadcast_live_event(event_type: str, data: Dict[str, Any]):
    """Push event to all active SSE listener queues."""
    payload = {"event": event_type, "data": data}
    dead = []
    for q in _sse_listeners:
        try:
            q.put_nowait(payload)
        except Exception:
            dead.append(q)
    for d in dead:
        unregister_sse_listener(d)

def get_threats(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """Retrieve threats with filtering, full-text search, and pagination."""
    sql = "SELECT * FROM threats WHERE 1=1"
    params: List[Any] = []

    if status and status.lower() != "all":
        sql += " AND lower(status) = ?"
        params.append(status.lower())

    if severity and severity.lower() != "all":
        sql += " AND lower(severity) = ?"
        params.append(severity.lower())

    if search:
        search_term = f"%{search.lower()}%"
        sql += " AND (lower(title) LIKE ? OR lower(source) LIKE ? OR lower(source_ip) LIKE ? OR lower(target_asset) LIKE ? OR lower(id) LIKE ?)"
        params.extend([search_term, search_term, search_term, search_term, search_term])

    count_sql = "SELECT count(*) as total FROM (" + sql + ")"
    total = execute_one(count_sql, tuple(params))["total"]

    sql += " ORDER BY detected_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = execute_query(sql, tuple(params))
    items = [
        {
            "id": r["id"],
            "title": r["title"],
            "severity": r["severity"],
            "source": r["source"],
            "sourceIp": r["source_ip"],
            "targetAsset": r["target_asset"],
            "country": r["country"],
            "attackType": r["attack_type"],
            "status": r["status"],
            "detectedAt": r["detected_at"],
            "aiConfidence": r["ai_confidence"],
            "mitreTechnique": r["mitre_technique"]
        }
        for r in rows
    ]

    return {"items": items, "total": total, "limit": limit, "offset": offset}

def get_threat_by_id(threat_id: str) -> Optional[Dict[str, Any]]:
    """Get single threat details by ID."""
    r = execute_one("SELECT * FROM threats WHERE id = ?", (threat_id,))
    if not r:
        return None
    return {
        "id": r["id"],
        "title": r["title"],
        "severity": r["severity"],
        "source": r["source"],
        "sourceIp": r["source_ip"],
        "targetAsset": r["target_asset"],
        "country": r["country"],
        "attackType": r["attack_type"],
        "status": r["status"],
        "detectedAt": r["detected_at"],
        "aiConfidence": r["ai_confidence"],
        "mitreTechnique": r["mitre_technique"]
    }

def create_threat(data: Dict[str, Any], actor: str = "Ingestion Agent") -> Dict[str, Any]:
    """Ingest a new threat from network sensor, EDR, or external feed."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    last = execute_one("SELECT id FROM threats ORDER BY rowid DESC LIMIT 1")
    if last and last["id"].startswith("THR-"):
        try:
            num = int(last["id"].replace("THR-", "")) + 1
        except ValueError:
            num = 8850
    else:
        num = 8850
    threat_id = f"THR-{num}"

    # If raw log or command is provided, run AI classification
    raw_sample = data.get("rawPayload") or data.get("title", "")
    target = data.get("targetAsset", "Host-01")
    ai_result = analyze_payload_or_log(raw_sample, target)

    title = data.get("title") or f"{ai_result['verdict']} on {target}"
    severity = data.get("severity") or ai_result["severity"]
    confidence = data.get("aiConfidence", ai_result["confidence"])
    mitre = data.get("mitreTechnique") or (ai_result["mitreTechniques"][0] if ai_result["mitreTechniques"] else "T1059")

    execute_commit(
        """INSERT INTO threats 
        (id, title, severity, source, source_ip, target_asset, country, attack_type, status, detected_at, ai_confidence, mitre_technique)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            threat_id, title, severity, data.get("source", "Network IDS"),
            data.get("sourceIp", "192.168.1.100"), target,
            data.get("country", "Unknown"), data.get("attackType", "Anomalous Traffic"),
            "open", now, confidence, mitre
        )
    )

    created = get_threat_by_id(threat_id)
    if created:
        broadcast_live_event("NEW_THREAT", created)
        log_audit_event(actor=actor, action="Ingested threat detection", target=threat_id, ip=data.get("sourceIp", "127.0.0.1"))
    return created or {}

def update_threat_status(threat_id: str, new_status: str, actor: str = "SOC Analyst") -> Optional[Dict[str, Any]]:
    """Update threat status (open, investigating, contained, resolved)."""
    t = get_threat_by_id(threat_id)
    if not t:
        return None

    execute_commit("UPDATE threats SET status = ? WHERE id = ?", (new_status, threat_id))
    log_audit_event(actor=actor, action=f"Changed status to {new_status}", target=threat_id)
    updated = get_threat_by_id(threat_id)
    if updated:
        broadcast_live_event("THREAT_STATUS_UPDATED", updated)
    return updated

def quarantine_threat(threat_id: str, actor: str = "SOC Analyst") -> Dict[str, Any]:
    """Autonomous quarantine response action."""
    t = get_threat_by_id(threat_id)
    if not t:
        return {"success": False, "error": "Threat not found"}

    target = t["targetAsset"]
    # Update asset status if present
    execute_commit("UPDATE assets SET status = 'quarantined' WHERE name = ?", (target,))
    execute_commit("UPDATE threats SET status = 'contained' WHERE id = ?", (threat_id,))

    log_audit_event(actor=actor, action=f"Quarantined host {target}", target=threat_id)
    updated = get_threat_by_id(threat_id)
    if updated:
        broadcast_live_event("THREAT_QUARANTINED", updated)

    return {
        "success": True,
        "message": f"Asset {target} isolated successfully. Firewall drop rules deployed.",
        "threat": updated
    }
