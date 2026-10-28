"""Blockchain Evidence API routes for Sentinel Chain."""

from typing import Dict, Any, Tuple
from ..services.evidence_service import (
    get_evidence_list,
    get_evidence_by_id,
    get_blocks_list
)
from ..blockchain import (
    anchor_evidence,
    verify_evidence_record,
    audit_entire_chain
)
from ..config import VALIDATOR_PEERS

def handle_get_evidence(query_params: Dict[str, str]) -> Tuple[Dict[str, Any], int]:
    """Retrieve list of blockchain evidence records."""
    incident_id = query_params.get("incidentId")
    limit = int(query_params.get("limit", 50))
    offset = int(query_params.get("offset", 0))

    result = get_evidence_list(incident_id=incident_id, limit=limit, offset=offset)
    return result, 200

def handle_get_evidence_by_id(evidence_id: str) -> Tuple[Dict[str, Any], int]:
    """Retrieve single evidence details."""
    ev = get_evidence_by_id(evidence_id)
    if not ev:
        return {"error": f"Evidence record '{evidence_id}' not found"}, 404
    return ev, 200

def handle_anchor_evidence(data: Dict[str, Any], actor: str) -> Tuple[Dict[str, Any], int]:
    """Anchor new forensic evidence to blockchain ledger."""
    incident_id = data.get("incidentId")
    if not incident_id:
        return {"error": "Field 'incidentId' is required"}, 400

    validator = data.get("validator", "Org1-Peer0")
    payload = data.get("payload", {})

    anchored = anchor_evidence(incident_id=incident_id, validator=validator, payload=payload)
    return anchored, 201

def handle_verify_evidence(evidence_id: str) -> Tuple[Dict[str, Any], int]:
    """Perform cryptographic verification of evidence against the ledger."""
    res = verify_evidence_record(evidence_id)
    return res, 200 if res.get("valid") else 400

def handle_audit_chain() -> Tuple[Dict[str, Any], int]:
    """Audit the entire ledger chain from genesis to tip."""
    res = audit_entire_chain()
    return res, 200

def handle_get_blocks(query_params: Dict[str, str]) -> Tuple[Dict[str, Any], int]:
    """Retrieve ledger blocks."""
    limit = int(query_params.get("limit", 20))
    offset = int(query_params.get("offset", 0))
    blocks = get_blocks_list(limit=limit, offset=offset)
    return {"blocks": blocks}, 200

def handle_get_peers() -> Tuple[Dict[str, Any], int]:
    """Retrieve active validator peer nodes."""
    return {"peers": VALIDATOR_PEERS}, 200
