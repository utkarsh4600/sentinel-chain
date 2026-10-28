"""Threat Intelligence API routes for Sentinel Chain IOCs and CVEs."""

from typing import Dict, Any, Tuple
from ..services.intel_service import get_iocs, get_cves, lookup_ioc

def handle_get_iocs(query_params: Dict[str, str]) -> Tuple[Dict[str, Any], int]:
    """Retrieve IOC feed with optional filtering."""
    threat_level = query_params.get("threatLevel")
    ioc_type = query_params.get("type")
    search = query_params.get("search")
    limit = int(query_params.get("limit", 50))
    offset = int(query_params.get("offset", 0))

    result = get_iocs(threat_level=threat_level, ioc_type=ioc_type, search=search, limit=limit, offset=offset)
    return result, 200

def handle_get_cves(query_params: Dict[str, str]) -> Tuple[Dict[str, Any], int]:
    """Retrieve CVE catalog."""
    severity = query_params.get("severity")
    search = query_params.get("search")
    limit = int(query_params.get("limit", 50))
    offset = int(query_params.get("offset", 0))

    result = get_cves(severity=severity, search=search, limit=limit, offset=offset)
    return result, 200

def handle_lookup(data: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    """Perform reputation intelligence lookup on IP, domain, or hash."""
    indicator = data.get("indicator")
    if not indicator:
        return {"error": "Field 'indicator' is required"}, 400
    res = lookup_ioc(indicator)
    return res, 200
