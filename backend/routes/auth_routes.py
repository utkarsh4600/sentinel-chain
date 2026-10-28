"""Authentication API routes for Sentinel Chain."""

from typing import Dict, Any, Tuple
from ..database import execute_one, execute_commit
from ..auth import (
    hash_password,
    verify_password,
    create_access_token,
    verify_token,
    verify_2fa_otp
)
from ..services.audit_service import log_audit_event

def handle_login(data: Dict[str, Any], client_ip: str) -> Tuple[Dict[str, Any], int]:
    """Process user login and issue JWT token."""
    email = data.get("email", "").strip().lower()
    password = data.get("password", "")

    if not email or not password:
        return {"error": "Email and password are required"}, 400

    user = execute_one("SELECT * FROM users WHERE lower(email) = ?", (email,))
    if not user:
        # Check if email is recognized from seed format or create user on the fly for smooth dev
        log_audit_event(actor=email, action="Failed login attempt - user not found", target="Auth", ip=client_ip, result="failed")
        return {"error": "Invalid email or password"}, 401

    if not verify_password(password, user["password_salt"], user["password_hash"]):
        log_audit_event(actor=email, action="Failed login attempt - incorrect password", target="Auth", ip=client_ip, result="failed")
        return {"error": "Invalid email or password"}, 401

    if user["status"] != "active":
        return {"error": f"Account is {user['status']}. Please contact SOC administrator."}, 403

    token = create_access_token(user["id"], user["email"], user["role"], user["name"])
    log_audit_event(actor=email, action="Successful login", target="Auth", ip=client_ip, result="success")

    return {
        "token": token,
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "mfaEnabled": bool(user["mfa_enabled"]),
            "avatarInitials": (user["name"][0] if user["name"] else "S").upper()
        }
    }, 200

def handle_register(data: Dict[str, Any], client_ip: str) -> Tuple[Dict[str, Any], int]:
    """Register a new SOC analyst or administrator."""
    email = data.get("email", "").strip().lower()
    name = data.get("name", "").strip()
    password = data.get("password", "")
    role = data.get("role", "Analyst")

    if not email or not password or not name:
        return {"error": "Name, email, and password are required"}, 400

    existing = execute_one("SELECT id FROM users WHERE lower(email) = ?", (email,))
    if existing:
        return {"error": "An account with this email already exists"}, 409

    salt, p_hash = hash_password(password)
    user_id = f"USR-{secrets_num():02d}"

    execute_commit(
        """INSERT INTO users 
        (id, name, email, password_hash, password_salt, role, status, last_active, mfa_enabled, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (user_id, name, email, p_hash, salt, role, "active", "Just now", 0, "2026-07-30T00:00:00Z")
    )

    token = create_access_token(user_id, email, role, name)
    log_audit_event(actor=email, action="Registered new user", target=user_id, ip=client_ip)

    return {
        "token": token,
        "user": {
            "id": user_id,
            "name": name,
            "email": email,
            "role": role,
            "mfaEnabled": False,
            "avatarInitials": name[0].upper()
        }
    }, 201

def handle_me(token: str) -> Tuple[Dict[str, Any], int]:
    """Retrieve profile for the authenticated token."""
    payload = verify_token(token)
    if not payload:
        return {"error": "Invalid or expired token"}, 401

    user = execute_one("SELECT * FROM users WHERE id = ?", (payload["sub"],))
    if not user:
        return {"error": "User account no longer exists"}, 404

    return {
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"],
            "role": user["role"],
            "status": user["status"],
            "mfaEnabled": bool(user["mfa_enabled"]),
            "avatarInitials": (user["name"][0] if user["name"] else "S").upper()
        }
    }, 200

def handle_verify_2fa(data: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
    """Validate two-factor verification code."""
    code = str(data.get("code", "")).strip()
    user_id = data.get("userId", "USR-01")
    if verify_2fa_otp(user_id, code):
        return {"valid": True, "message": "2FA verification succeeded"}, 200
    return {"valid": False, "error": "Invalid 2FA code"}, 400

def secrets_num() -> int:
    """Helper to get next incremental user index."""
    row = execute_one("SELECT count(*) as cnt FROM users")
    return (row["cnt"] if row else 8) + 1
