"""Incidents API routes for Sentinel Chain."""

from typing import Dict, Any, Tuple
from ..services.incidents_service import (
    get_incidents,
    get_incident_by_id,
    create_incident,
    update_incident,
    execute_incident_action
)

def handle_get_incidents(query_params: Dict[str, str]) -> Tuple[Dict[str, Any], int]:
    """Retrieve list of incidents."""
    status = query_params.get("status")
    severity = query_params.get("severity")
    search = query_params.get("search")
    limit = int(query_params.get("limit", 50))
    offset = int(query_params.get("offset", 0))

    result = get_incidents(status=status, severity=severity, search=search, limit=limit, offset=offset)
    return result, 200

def handle_get_incident_by_id(incident_id: str) -> Tuple[Dict[str, Any], int]:
    """Retrieve single incident details with blockchain linkage."""
    inc = get_incident_by_id(incident_id)
    if not inc:
        return {"error": f"Incident '{incident_id}' not found"}, 404
    return inc, 200

def handle_create_incident(data: Dict[str, Any], actor: str) -> Tuple[Dict[str, Any], int]:
    """Create a new incident ticket."""
    if not data.get("title"):
        return {"error": "Field 'title' is required"}, 400
    created = create_incident(data, actor=actor)
    return created, 201

def handle_update_incident(incident_id: str, data: Dict[str, Any], actor: str) -> Tuple[Dict[str, Any], int]:
    """Update incident properties."""
    updated = update_incident(incident_id, data, actor=actor)
    if not updated:
        return {"error": f"Incident '{incident_id}' not found"}, 404
    return updated, 200

def handle_incident_action(incident_id: str, data: Dict[str, Any], actor: str) -> Tuple[Dict[str, Any], int]:
    """Trigger incident response or forensic workflow."""
    action = data.get("action")
    if not action:
        return {"error": "Field 'action' is required"}, 400
    res = execute_incident_action(incident_id, action, actor=actor)
    if not res.get("success"):
        return res, 400
    return res, 200
