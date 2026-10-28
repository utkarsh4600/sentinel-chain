"""Compliance & Reports API routes for Sentinel Chain governance."""

from datetime import datetime, timezone
from typing import Dict, Any, Tuple
from ..database import execute_query, execute_commit, execute_one
from ..services.audit_service import log_audit_event

def handle_get_compliance() -> Tuple[Dict[str, Any], int]:
    """Retrieve compliance framework posture scores."""
    rows = execute_query("SELECT * FROM compliance ORDER BY score DESC")
    items = [
        {
            "id": r["id"],
            "name": r["name"],
            "fullName": r["full_name"],
            "status": r["status"],
            "score": r["score"],
            "controlsPassed": r["controls_passed"],
            "controlsTotal": r["controls_total"],
            "lastAudit": r["last_audit"]
        }
        for r in rows
    ]
    return {"frameworks": items}, 200

def handle_get_reports() -> Tuple[Dict[str, Any], int]:
    """Retrieve generated SOC and compliance reports."""
    rows = execute_query("SELECT * FROM reports ORDER BY generated_at DESC")
    items = [
        {
            "id": r["id"],
            "title": r["title"],
            "type": r["type"],
            "generatedAt": r["generated_at"],
            "generatedBy": r["generated_by"],
            "sizeKb": r["size_kb"]
        }
        for r in rows
    ]
    return {"reports": items}, 200

def handle_generate_report(data: Dict[str, Any], actor: str) -> Tuple[Dict[str, Any], int]:
    """Generate a new compliance or incident audit report."""
    title = data.get("title", "SOC Incident Summary Report")
    report_type = data.get("type", "Incident")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    last = execute_one("SELECT id FROM reports ORDER BY rowid DESC LIMIT 1")
    if last and last["id"].startswith("RPT-"):
        try:
            num = int(last["id"].replace("RPT-", "")) + 1
        except ValueError:
            num = 910
    else:
        num = 910
    report_id = f"RPT-{num}"

    execute_commit(
        """INSERT INTO reports (id, title, type, generated_at, generated_by, size_kb)
        VALUES (?, ?, ?, ?, ?, ?)""",
        (report_id, title, report_type, now, actor, 480)
    )

    log_audit_event(actor=actor, action=f"Generated report {report_id}", target=report_id)

    return {
        "id": report_id,
        "title": title,
        "type": report_type,
        "generatedAt": now,
        "generatedBy": actor,
        "sizeKb": 480
    }, 201
