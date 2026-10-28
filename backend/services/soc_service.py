"""SOC Operations Service for team metrics, shifts, and analyst assignments."""

from typing import Dict, Any, List, Optional
from ..database import execute_query, execute_one, execute_commit
from .audit_service import log_audit_event

def get_soc_team() -> List[Dict[str, Any]]:
    """Retrieve SOC analyst roster and performance scores."""
    rows = execute_query("SELECT * FROM soc_team ORDER BY score DESC")
    return [
        {
            "id": r["id"],
            "name": r["name"],
            "role": r["role"],
            "title": r["title"],
            "shift": r["shift"],
            "incidentsResolved": r["incidents_resolved"],
            "avgResponse": r["avg_response_time"],
            "score": r["score"],
            "email": r["email"]
        }
        for r in rows
    ]

def get_soc_shifts() -> List[Dict[str, Any]]:
    """Return SOC shift rosters."""
    return [
        {"shift": "Day", "hours": "07:00 - 15:00 UTC", "commander": "Riya Singh", "activeAnalysts": 3},
        {"shift": "Swing", "hours": "15:00 - 23:00 UTC", "commander": "John Doe", "activeAnalysts": 2},
        {"shift": "Night", "hours": "23:00 - 07:00 UTC", "commander": "Jane Smith", "activeAnalysts": 2}
    ]

def assign_incident_to_analyst(incident_id: str, analyst_name: str, actor: str = "SOC Lead") -> Dict[str, Any]:
    """Assign incident to specified analyst and increment their workload."""
    execute_commit("UPDATE incidents SET assigned_to = ? WHERE id = ?", (analyst_name, incident_id))
    log_audit_event(actor=actor, action=f"Assigned incident {incident_id} to {analyst_name}", target=incident_id)
    return {"success": True, "incidentId": incident_id, "assignedTo": analyst_name}
