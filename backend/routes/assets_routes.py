"""Assets API routes for Sentinel Chain infrastructure inventory."""

from typing import Dict, Any, Tuple
from ..services.assets_service import (
    get_assets,
    get_asset_by_id,
    create_asset,
    update_asset_status
)

def handle_get_assets(query_params: Dict[str, str]) -> Tuple[Dict[str, Any], int]:
    """Retrieve list of assets."""
    status = query_params.get("status")
    asset_type = query_params.get("type")
    search = query_params.get("search")
    limit = int(query_params.get("limit", 50))
    offset = int(query_params.get("offset", 0))

    result = get_assets(status=status, asset_type=asset_type, search=search, limit=limit, offset=offset)
    return result, 200

def handle_get_asset_by_id(asset_id: str) -> Tuple[Dict[str, Any], int]:
    """Retrieve single asset."""
    ast = get_asset_by_id(asset_id)
    if not ast:
        return {"error": f"Asset '{asset_id}' not found"}, 404
    return ast, 200

def handle_create_asset(data: Dict[str, Any], actor: str) -> Tuple[Dict[str, Any], int]:
    """Register new asset."""
    if not data.get("name"):
        return {"error": "Field 'name' is required"}, 400
    created = create_asset(data, actor=actor)
    return created, 201

def handle_update_asset(asset_id: str, data: Dict[str, Any], actor: str) -> Tuple[Dict[str, Any], int]:
    """Update asset status or properties."""
    new_status = data.get("status")
    if not new_status:
        return {"error": "Field 'status' is required"}, 400
    updated = update_asset_status(asset_id, new_status, actor=actor)
    if not updated:
        return {"error": f"Asset '{asset_id}' not found"}, 404
    return updated, 200

def handle_isolate_asset(asset_id: str, actor: str) -> Tuple[Dict[str, Any], int]:
    """Emergency isolate an asset from the local subnet."""
    updated = update_asset_status(asset_id, "isolated", actor=actor)
    if not updated:
        return {"error": f"Asset '{asset_id}' not found"}, 404
    return {"message": f"Asset '{asset_id}' has been isolated via network VLAN segmentation", "asset": updated}, 200
