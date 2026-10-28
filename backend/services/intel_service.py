"""Threat Intelligence Service for IOCs, CVEs, and reputation lookups."""

import json
from typing import Dict, Any, List, Optional
from ..database import execute_query, execute_one

def get_iocs(
    threat_level: Optional[str] = None,
    ioc_type: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """Retrieve Indicators of Compromise feed."""
    sql = "SELECT * FROM iocs WHERE 1=1"
    params: List[Any] = []

    if threat_level and threat_level.lower() != "all":
        sql += " AND lower(threat_level) = ?"
        params.append(threat_level.lower())

    if ioc_type and ioc_type.lower() != "all":
        sql += " AND lower(type) = ?"
        params.append(ioc_type.lower())

    if search:
        search_term = f"%{search.lower()}%"
        sql += " AND (lower(value) LIKE ? OR lower(source) LIKE ? OR lower(tags_json) LIKE ?)"
        params.extend([search_term, search_term, search_term])

    count_sql = "SELECT count(*) as total FROM (" + sql + ")"
    total = execute_one(count_sql, tuple(params))["total"]

    sql += " ORDER BY first_seen DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = execute_query(sql, tuple(params))
    items = []
    for r in rows:
        try:
            tags = json.loads(r["tags_json"]) if r["tags_json"] else []
        except Exception:
            tags = []
        items.append({
            "id": r["id"],
            "type": r["type"],
            "value": r["value"],
            "threatLevel": r["threat_level"],
            "source": r["source"],
            "firstSeen": r["first_seen"],
            "tags": tags
        })

    return {"items": items, "total": total, "limit": limit, "offset": offset}

def get_cves(
    severity: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """Retrieve Common Vulnerabilities and Exposures database."""
    sql = "SELECT * FROM cves WHERE 1=1"
    params: List[Any] = []

    if severity and severity.lower() != "all":
        sql += " AND lower(severity) = ?"
        params.append(severity.lower())

    if search:
        search_term = f"%{search.lower()}%"
        sql += " AND (lower(id) LIKE ? OR lower(title) LIKE ? OR lower(affected_product) LIKE ?)"
        params.extend([search_term, search_term, search_term])

    count_sql = "SELECT count(*) as total FROM (" + sql + ")"
    total = execute_one(count_sql, tuple(params))["total"]

    sql += " ORDER BY cvss_score DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = execute_query(sql, tuple(params))
    items = [
        {
            "id": r["id"],
            "title": r["title"],
            "severity": r["severity"],
            "cvssScore": r["cvss_score"],
            "affectedProduct": r["affected_product"],
            "published": r["published"],
            "exploitAvailable": bool(r["exploit_available"])
        }
        for r in rows
    ]

    return {"items": items, "total": total, "limit": limit, "offset": offset}

def lookup_ioc(indicator: str) -> Dict[str, Any]:
    """Check if an IP, domain, or hash matches known malicious intelligence."""
    cleaned = indicator.strip()
    match = execute_one("SELECT * FROM iocs WHERE lower(value) = ?", (cleaned.lower(),))
    if match:
        try:
            tags = json.loads(match["tags_json"]) if match["tags_json"] else []
        except Exception:
            tags = []
        return {
            "found": True,
            "threatLevel": match["threat_level"],
            "reputationScore": 10 if match["threat_level"] == "critical" else 35,
            "type": match["type"],
            "source": match["source"],
            "firstSeen": match["first_seen"],
            "tags": tags,
            "verdict": "Malicious Indicator Confirmed"
        }
    return {
        "found": False,
        "threatLevel": "unknown",
        "reputationScore": 88,
        "indicator": cleaned,
        "verdict": "No active malicious campaigns detected in Sentinel intelligence feed"
    }
