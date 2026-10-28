"""SOC Operations API routes for Sentinel Chain team and scheduling."""

from typing import Dict, Any, Tuple
from ..services.soc_service import (
    get_soc_team,
    get_soc_shifts,
    assign_incident_to_analyst
)

def handle_get_team() -> Tuple[Dict[str, Any], int]:
    """Retrieve SOC analyst team."""
    team = get_soc_team()
    return {"team": team}, 200

def handle_get_shifts() -> Tuple[Dict[str, Any], int]:
    """Retrieve shift schedules."""
    shifts = get_soc_shifts()
    return {"shifts": shifts}, 200

def handle_assign_incident(data: Dict[str, Any], actor: str) -> Tuple[Dict[str, Any], int]:
    """Assign incident to analyst."""
    incident_id = data.get("incidentId")
    analyst_name = data.get("analystName")
    if not incident_id or not analyst_name:
        return {"error": "Fields 'incidentId' and 'analystName' are required"}, 400
    res = assign_incident_to_analyst(incident_id, analyst_name, actor=actor)
    return res, 200
