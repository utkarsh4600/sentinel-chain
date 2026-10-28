"""Configuration settings for Sentinel Chain Backend."""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
FRONTEND_DIR = BASE_DIR / "frontend"

HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 8000))

SECRET_KEY = os.environ.get("SECRET_KEY", "sentinel-chain-post-quantum-sovereign-auth-secret-key-2026")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = int(os.environ.get("JWT_EXPIRATION_HOURS", 24))

DB_PATH = DATA_DIR / "sentinel_chain.db"
SEED_DATA_PATH = DATA_DIR / "seed_data.json"

VALIDATOR_PEERS = [
    {"id": "Org1-Peer0", "name": "Sentinel Validator Node East", "ip": "10.100.1.10", "status": "active"},
    {"id": "Org1-Peer1", "name": "Sentinel Validator Node Central", "ip": "10.100.1.11", "status": "active"},
    {"id": "Org2-Peer0", "name": "Alliance Sovereign Node West", "ip": "10.200.2.20", "status": "active"},
    {"id": "Org2-Peer1", "name": "Alliance Sovereign Node Backup", "ip": "10.200.2.21", "status": "active"}
]

GENESIS_BLOCK_NUMBER = 585220
GENESIS_PREV_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000"
