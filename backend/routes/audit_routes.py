"""Audit Logs API routes for Sentinel Chain tamper-evident trail."""

from typing import Dict, Any, Tuple
from ..services.audit_service import get_audit_logs, log_audit_event

def handle_get_audit_logs(query_params: Dict[str, str]) -> Tuple[Dict[str, Any], int]:
    """Retrieve immutable audit logs."""
    limit = int(query_params.get("limit", 50))
    offset = int(query_params.get("offset", 0))
    logs = get_audit_logs(limit=limit, offset=offset)
    return {"logs": logs}, 200

def handle_create_audit_log(data: Dict[str, Any], client_ip: str) -> Tuple[Dict[str, Any], int]:
    """Manually insert an external or sensor audit log."""
    actor = data.get("actor", "Sensor")
    action = data.get("action", "Telemetry Event")
    target = data.get("target", "System")
    result = data.get("result", "success")

    logged = log_audit_event(actor=actor, action=action, target=target, ip=client_ip, result=result)
    return logged, 201
