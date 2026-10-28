"""Assets Service for infrastructure monitoring and isolation management."""

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from ..database import execute_query, execute_one, execute_commit
from .audit_service import log_audit_event

def get_assets(
    status: Optional[str] = None,
    asset_type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """List monitored assets with status filter and search."""
    sql = "SELECT * FROM assets WHERE 1=1"
    params: List[Any] = []

    if status and status.lower() != "all":
        sql += " AND lower(status) = ?"
        params.append(status.lower())

    if asset_type and asset_type.lower() != "all":
        sql += " AND lower(type) = ?"
        params.append(asset_type.lower())

    if search:
        search_term = f"%{search.lower()}%"
        sql += " AND (lower(name) LIKE ? OR lower(ip_address) LIKE ? OR lower(owner) LIKE ? OR lower(location) LIKE ?)"
        params.extend([search_term, search_term, search_term, search_term])

    count_sql = "SELECT count(*) as total FROM (" + sql + ")"
    total = execute_one(count_sql, tuple(params))["total"]

    sql += " ORDER BY risk_score DESC, name ASC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = execute_query(sql, tuple(params))
    items = [
        {
            "id": r["id"],
            "name": r["name"],
            "type": r["type"],
            "status": r["status"],
            "ipAddress": r["ip_address"],
            "owner": r["owner"],
            "location": r["location"],
            "riskScore": r["risk_score"],
            "lastSeen": r["last_seen"]
        }
        for r in rows
    ]

    return {"items": items, "total": total, "limit": limit, "offset": offset}

def get_asset_by_id(asset_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve details for a single asset."""
    r = execute_one("SELECT * FROM assets WHERE id = ?", (asset_id,))
    if not r:
        return None
    return {
        "id": r["id"],
        "name": r["name"],
        "type": r["type"],
        "status": r["status"],
        "ipAddress": r["ip_address"],
        "owner": r["owner"],
        "location": r["location"],
        "riskScore": r["risk_score"],
        "lastSeen": r["last_seen"]
    }

def update_asset_status(asset_id: str, new_status: str, actor: str = "SOC Analyst") -> Optional[Dict[str, Any]]:
    """Update asset status (e.g., active, compromised, isolated, offline)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    execute_commit("UPDATE assets SET status = ?, last_seen = ? WHERE id = ?", (new_status, now, asset_id))
    log_audit_event(actor=actor, action=f"Updated asset status to {new_status}", target=asset_id)
    return get_asset_by_id(asset_id)

def create_asset(data: Dict[str, Any], actor: str = "Asset Discovery Agent") -> Dict[str, Any]:
    """Register a newly discovered IT/OT asset."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    last = execute_one("SELECT id FROM assets ORDER BY rowid DESC LIMIT 1")
    if last and last["id"].startswith("AST-"):
        try:
            num = int(last["id"].replace("AST-", "")) + 1
        except ValueError:
            num = 11
    else:
        num = 11
    asset_id = f"AST-{num:03d}"

    execute_commit(
        """INSERT INTO assets 
        (id, name, type, status, ip_address, owner, location, risk_score, last_seen)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            asset_id, data["name"], data.get("type", "server"),
            data.get("status", "active"), data.get("ipAddress", "10.0.0.1"),
            data.get("owner", "IT Sec"), data.get("location", "Primary Datacenter"),
            data.get("riskScore", 10), now
        )
    )
    log_audit_event(actor=actor, action=f"Registered new asset {data['name']}", target=asset_id)
    return get_asset_by_id(asset_id) or {}
