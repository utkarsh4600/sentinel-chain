"""AI Defense & Threat Prediction API routes for Sentinel Chain."""

import json
from typing import Dict, Any, Tuple
from ..database import execute_query, execute_commit
from ..ai_engine import analyze_payload_or_log

def handle_get_ai_analyses() -> Tuple[Dict[str, Any], int]:
    """Retrieve pre-computed model analysis and predictions."""
    rows = execute_query("SELECT * FROM ai_analyses ORDER BY rowid ASC")
    items = []
    for r in rows:
        try:
            top_features = json.loads(r["top_features_json"]) if r["top_features_json"] else []
        except Exception:
            top_features = []
        items.append({
            "id": r["id"],
            "model": r["model"],
            "target": r["target"],
            "verdict": r["verdict"],
            "confidence": r["confidence"],
            "timestamp": r["timestamp"],
            "topFeatures": top_features
        })
    return {"analyses": items}, 200

def handle_analyze_sample(data: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    """Analyze a suspicious log line, command line, or binary snippet."""
    sample = data.get("sample", "").strip()
    target = data.get("target", "Monitored-Asset")

    if not sample:
        return {"error": "Field 'sample' containing log or command text is required"}, 400

    result = analyze_payload_or_log(sample_text=sample, target_asset=target)
    return result, 200

def handle_get_ai_models() -> Tuple[Dict[str, Any], int]:
    """Return model inventory and active performance benchmarks."""
    models = [
        {"id": "GNN-01", "name": "GNN Lateral Movement Model", "type": "Graph Neural Network", "accuracy": 98.7, "latency": "14ms", "status": "active"},
        {"id": "XGB-02", "name": "XGBoost Threat Classifier", "type": "Gradient Boosted Trees", "accuracy": 99.1, "latency": "4ms", "status": "active"},
        {"id": "AE-03", "name": "Autoencoder Anomaly Detector", "type": "Deep Autoencoder", "accuracy": 97.4, "latency": "9ms", "status": "active"},
        {"id": "IF-04", "name": "Isolation Forest UEBA", "type": "Ensemble Forest", "accuracy": 96.8, "latency": "6ms", "status": "active"}
    ]
    return {"models": models}, 200
