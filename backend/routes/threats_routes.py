"""Threats API routes for Sentinel Chain."""

from typing import Dict, Any, Tuple
from ..services.threats_service import (
    get_threats,
    get_threat_by_id,
    create_threat,
    update_threat_status,
    quarantine_threat
)

def handle_get_threats(query_params: Dict[str, str]) -> Tuple[Dict[str, Any], int]:
    """List threats with filters."""
    status = query_params.get("status")
    severity = query_params.get("severity")
    search = query_params.get("search")
    limit = int(query_params.get("limit", 50))
    offset = int(query_params.get("offset", 0))

    result = get_threats(status=status, severity=severity, search=search, limit=limit, offset=offset)
    return result, 200

def handle_get_threat_by_id(threat_id: str) -> Tuple[Dict[str, Any], int]:
    """Retrieve single threat."""
    t = get_threat_by_id(threat_id)
    if not t:
        return {"error": f"Threat '{threat_id}' not found"}, 404
    return t, 200

def handle_create_threat(data: Dict[str, Any], actor: str) -> Tuple[Dict[str, Any], int]:
    """Ingest new threat detection."""
    created = create_threat(data, actor=actor)
    return created, 201

def handle_update_threat(threat_id: str, data: Dict[str, Any], actor: str) -> Tuple[Dict[str, Any], int]:
    """Update threat status."""
    new_status = data.get("status")
    if not new_status:
        return {"error": "Field 'status' is required"}, 400
    updated = update_threat_status(threat_id, new_status, actor=actor)
    if not updated:
        return {"error": f"Threat '{threat_id}' not found"}, 404
    return updated, 200

def handle_quarantine_threat(threat_id: str, actor: str) -> Tuple[Dict[str, Any], int]:
    """Quarantine compromised asset linked to threat."""
    res = quarantine_threat(threat_id, actor=actor)
    if not res.get("success"):
        return res, 404
    return res, 200
