"""Incidents Service for Sentinel Chain incident management & response lifecycle."""

import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from ..database import execute_query, execute_one, execute_commit
from .audit_service import log_audit_event
from ..blockchain import anchor_evidence

def get_incidents(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """List incidents with filtering and search."""
    sql = "SELECT * FROM incidents WHERE 1=1"
    params: List[Any] = []

    if status and status.lower() != "all":
        sql += " AND lower(status) = ?"
        params.append(status.lower())

    if severity and severity.lower() != "all":
        sql += " AND lower(severity) = ?"
        params.append(severity.lower())

    if search:
        search_term = f"%{search.lower()}%"
        sql += " AND (lower(title) LIKE ? OR lower(id) LIKE ? OR lower(assigned_to) LIKE ? OR lower(description) LIKE ?)"
        params.extend([search_term, search_term, search_term, search_term])

    count_sql = "SELECT count(*) as total FROM (" + sql + ")"
    total = execute_one(count_sql, tuple(params))["total"]

    sql += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = execute_query(sql, tuple(params))
    items = []
    for r in rows:
        try:
            affected_assets = json.loads(r["affected_assets_json"]) if r["affected_assets_json"] else []
        except Exception:
            affected_assets = []
        try:
            mitre_techniques = json.loads(r["mitre_techniques_json"]) if r["mitre_techniques_json"] else []
        except Exception:
            mitre_techniques = []

        items.append({
            "id": r["id"],
            "title": r["title"],
            "severity": r["severity"],
            "status": r["status"],
            "assignedTo": r["assigned_to"],
            "createdAt": r["created_at"],
            "updatedAt": r["updated_at"],
            "affectedAssets": affected_assets,
            "description": r["description"],
            "mitreTechniques": mitre_techniques,
            "aiRecommendation": r["ai_recommendation"],
            "blockchainVerified": bool(r["blockchain_verified"]),
            "evidenceRecordId": r["evidence_record_id"]
        })

    return {"items": items, "total": total, "limit": limit, "offset": offset}

def get_incident_by_id(incident_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full incident details including linked blockchain evidence."""
    r = execute_one("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    if not r:
        return None

    try:
        affected_assets = json.loads(r["affected_assets_json"]) if r["affected_assets_json"] else []
    except Exception:
        affected_assets = []
    try:
        mitre_techniques = json.loads(r["mitre_techniques_json"]) if r["mitre_techniques_json"] else []
    except Exception:
        mitre_techniques = []

    # Get linked evidence details if exists
    evidence_detail = None
    if r["evidence_record_id"]:
        from .evidence_service import get_evidence_by_id
        evidence_detail = get_evidence_by_id(r["evidence_record_id"])

    return {
        "id": r["id"],
        "title": r["title"],
        "severity": r["severity"],
        "status": r["status"],
        "assignedTo": r["assigned_to"],
        "createdAt": r["created_at"],
        "updatedAt": r["updated_at"],
        "affectedAssets": affected_assets,
        "description": r["description"],
        "mitreTechniques": mitre_techniques,
        "aiRecommendation": r["ai_recommendation"],
        "blockchainVerified": bool(r["blockchain_verified"]),
        "evidenceRecordId": r["evidence_record_id"],
        "evidenceDetail": evidence_detail
    }

def create_incident(data: Dict[str, Any], actor: str = "SOC Incident Commander") -> Dict[str, Any]:
    """Create a new incident ticket and optionally anchor evidence to the ledger."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    last = execute_one("SELECT id FROM incidents ORDER BY rowid DESC LIMIT 1")
    if last and last["id"].startswith("INC-"):
        try:
            num = int(last["id"].replace("INC-", "")) + 1
        except ValueError:
            num = 1030
    else:
        num = 1030
    inc_id = f"INC-{num}"

    affected_assets = data.get("affectedAssets", [])
    mitre_techniques = data.get("mitreTechniques", ["T1059 - Command and Scripting Interpreter"])

    execute_commit(
        """INSERT INTO incidents 
        (id, title, severity, status, assigned_to, created_at, updated_at, affected_assets_json, description, mitre_techniques_json, ai_recommendation, blockchain_verified, evidence_record_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            inc_id, data["title"], data.get("severity", "medium"),
            data.get("status", "open"), data.get("assignedTo", "Riya Singh"),
            now, now, json.dumps(affected_assets),
            data.get("description", ""), json.dumps(mitre_techniques),
            data.get("aiRecommendation", "Perform live triage and contain affected endpoint."),
            0, None
        )
    )

    # If anchorToBlockchain flag is requested, immediately commit evidence block
    if data.get("anchorToBlockchain", True):
        ev = anchor_evidence(
            incident_id=inc_id,
            validator="Org1-Peer0",
            payload={"title": data["title"], "affectedAssets": affected_assets, "severity": data.get("severity")}
        )
        execute_commit(
            "UPDATE incidents SET blockchain_verified = 1, evidence_record_id = ? WHERE id = ?",
            (ev["id"], inc_id)
        )

    log_audit_event(actor=actor, action=f"Created incident {inc_id}", target=inc_id)
    return get_incident_by_id(inc_id) or {}

def update_incident(incident_id: str, updates: Dict[str, Any], actor: str = "SOC Analyst") -> Optional[Dict[str, Any]]:
    """Update incident status, assigned analyst, or details."""
    inc = get_incident_by_id(incident_id)
    if not inc:
        return None

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    new_status = updates.get("status", inc["status"])
    new_assigned = updates.get("assignedTo", inc["assignedTo"])
    new_desc = updates.get("description", inc["description"])
    new_severity = updates.get("severity", inc["severity"])

    execute_commit(
        """UPDATE incidents 
        SET status = ?, assigned_to = ?, description = ?, severity = ?, updated_at = ? 
        WHERE id = ?""",
        (new_status, new_assigned, new_desc, new_severity, now, incident_id)
    )

    log_audit_event(actor=actor, action=f"Updated incident status to {new_status}", target=incident_id)
    return get_incident_by_id(incident_id)

def execute_incident_action(incident_id: str, action: str, actor: str = "SOC Analyst") -> Dict[str, Any]:
    """Execute rapid containment or forensic workflow for an incident."""
    inc = get_incident_by_id(incident_id)
    if not inc:
        return {"success": False, "error": "Incident not found"}

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    if action == "anchor_evidence":
        ev = anchor_evidence(
            incident_id=incident_id,
            validator="Org1-Peer0",
            payload={"incident": incident_id, "assets": inc["affectedAssets"], "action": "forensic_anchor"}
        )
        return {"success": True, "message": f"Forensics committed to block #{ev['blockNumber']}", "evidence": ev}

    elif action == "isolate_hosts":
        for ast in inc["affectedAssets"]:
            execute_commit("UPDATE assets SET status = 'isolated' WHERE name = ?", (ast,))
        execute_commit("UPDATE incidents SET status = 'contained', updated_at = ? WHERE id = ?", (now, incident_id))
        log_audit_event(actor=actor, action="Executed host network isolation", target=incident_id)
        return {"success": True, "message": f"Successfully isolated assets: {', '.join(inc['affectedAssets'])}"}

    elif action == "resolve_incident":
        execute_commit("UPDATE incidents SET status = 'resolved', updated_at = ? WHERE id = ?", (now, incident_id))
        log_audit_event(actor=actor, action="Resolved incident ticket", target=incident_id)
        return {"success": True, "message": f"Incident {incident_id} marked as resolved."}

    return {"success": False, "error": f"Unknown action '{action}'"}
