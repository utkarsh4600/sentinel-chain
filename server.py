"""
Sentinel Chain Enterprise REST API & Web Application Server.
High-concurrency, zero-dependency multi-threaded server delivering:
- Cryptographic SHA-256 Blockchain Evidence Ledger
- Autonomous AI Cyber Defense Engine
- Real-Time Server-Sent Events (SSE) Threat Stream
- SPA Frontend Asset Delivery with React Router fallback
- Interactive API Documentation & Testing Dashboard
"""

import os
import sys
import json
import queue
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from pathlib import Path
from typing import Dict, Any, Optional

# Ensure UTF-8 console output
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure project root is in sys.path
BASE_DIR = Path(__file__).resolve().parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.config import HOST, PORT, FRONTEND_DIR
from backend.database import init_db, execute_one
from backend.docs_html import get_api_docs_html

# Import Route Handlers
from backend.routes.auth_routes import handle_login, handle_register, handle_me, handle_verify_2fa
from backend.routes.dashboard_routes import (
    handle_dashboard_stats, handle_threat_trend, handle_attack_types,
    handle_geo_threats, handle_alerts
)
from backend.routes.threats_routes import (
    handle_get_threats, handle_get_threat_by_id, handle_create_threat,
    handle_update_threat, handle_quarantine_threat
)
from backend.routes.incidents_routes import (
    handle_get_incidents, handle_get_incident_by_id, handle_create_incident,
    handle_update_incident, handle_incident_action
)
from backend.routes.blockchain_routes import (
    handle_get_evidence, handle_get_evidence_by_id, handle_anchor_evidence,
    handle_verify_evidence, handle_audit_chain, handle_get_blocks, handle_get_peers
)
from backend.routes.ai_routes import handle_get_ai_analyses, handle_analyze_sample, handle_get_ai_models
from backend.routes.assets_routes import (
    handle_get_assets, handle_get_asset_by_id, handle_create_asset,
    handle_update_asset, handle_isolate_asset
)
from backend.routes.soc_routes import handle_get_team, handle_get_shifts, handle_assign_incident
from backend.routes.intel_routes import handle_get_iocs, handle_get_cves, handle_lookup
from backend.routes.reports_routes import handle_get_compliance, handle_get_reports, handle_generate_report
from backend.routes.audit_routes import handle_get_audit_logs, handle_create_audit_log
from backend.services.threats_service import register_sse_listener, unregister_sse_listener

START_TIME = time.time()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Multi-threaded HTTP Server for simultaneous client requests."""
    daemon_threads = True


class SentinelRequestHandler(BaseHTTPRequestHandler):
    """High-performance request router for APIs, SSE, and SPA static assets."""

    def _set_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")

    def _send_json(self, data: Any, status_code: int = 200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(body)

    def _send_file(self, filepath: Path, content_type: str):
        if not filepath.exists():
            # Fallback to SPA index.html for unknown client-side routes
            fallback = FRONTEND_DIR / "index.html"
            if fallback.exists():
                return self._send_file(fallback, "text/html; charset=utf-8")
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            return

        with open(filepath, "rb") as f:
            content = f.read()

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self._set_cors_headers()
        self.end_headers()
        self.wfile.write(content)

    def _parse_body(self) -> Dict[str, Any]:
        """Safely parse JSON body from incoming POST/PATCH."""
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                return {}
            raw = self.rfile.read(length).decode("utf-8")
            return json.loads(raw)
        except Exception:
            return {}

    def _get_auth_token(self) -> str:
        """Extract Bearer token from Authorization header."""
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            return auth[7:].strip()
        return ""

    def do_OPTIONS(self):
        """Handle CORS preflight requests."""
        self.send_response(204)
        self._set_cors_headers()
        self.end_headers()

    def do_GET(self):
        """Route GET requests to API handlers or static files."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        query = dict(urllib.parse.parse_qsl(parsed.query))
        client_ip = self.client_address[0]

        # 1. API Health Check
        if path == "/api/health":
            latest_b = execute_one("SELECT block_number FROM blocks ORDER BY block_number DESC LIMIT 1")
            return self._send_json({
                "status": "healthy",
                "service": "Sentinel Chain Cyber Defense Platform",
                "uptimeSeconds": round(time.time() - START_TIME, 1),
                "latestBlock": latest_b["block_number"] if latest_b else 0,
                "version": "3.8.0"
            })

        # 2. Interactive API Explorer & Documentation
        if path in ("/api/docs", "/api"):
            html = get_api_docs_html().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self._set_cors_headers()
            self.end_headers()
            return self.wfile.write(html)

        # 3. Server-Sent Events (SSE) Stream for Live Threats
        if path == "/api/threats/stream":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self._set_cors_headers()
            self.end_headers()

            q = queue.Queue(maxsize=100)
            register_sse_listener(q)
            try:
                # Send initial handshake ping
                init_msg = json.dumps({"event": "CONNECTED", "message": "Subscribed to Sentinel Live Threat Stream"})
                self.wfile.write(f"data: {init_msg}\n\n".encode("utf-8"))
                self.wfile.flush()

                while True:
                    try:
                        item = q.get(timeout=25.0)
                        msg = json.dumps(item)
                        self.wfile.write(f"data: {msg}\n\n".encode("utf-8"))
                        self.wfile.flush()
                    except queue.Empty:
                        # Keep-alive heartbeat
                        self.wfile.write(b": heartbeat\n\n")
                        self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                unregister_sse_listener(q)
            return

        # 4. Auth & User Profile
        if path == "/api/auth/me":
            token = self._get_auth_token()
            res, code = handle_me(token)
            return self._send_json(res, code)

        # 5. Dashboard Routes
        if path == "/api/dashboard/stats":
            res, code = handle_dashboard_stats()
            return self._send_json(res, code)
        if path == "/api/dashboard/threat-trend":
            res, code = handle_threat_trend()
            return self._send_json(res, code)
        if path == "/api/dashboard/attack-types":
            res, code = handle_attack_types()
            return self._send_json(res, code)
        if path == "/api/dashboard/geo-threats":
            res, code = handle_geo_threats()
            return self._send_json(res, code)
        if path == "/api/dashboard/alerts":
            res, code = handle_alerts()
            return self._send_json(res, code)

        # 6. Threats Routes
        if path == "/api/threats":
            res, code = handle_get_threats(query)
            return self._send_json(res, code)
        if path.startswith("/api/threats/"):
            threat_id = path.replace("/api/threats/", "")
            res, code = handle_get_threat_by_id(threat_id)
            return self._send_json(res, code)

        # 7. Incidents Routes
        if path == "/api/incidents":
            res, code = handle_get_incidents(query)
            return self._send_json(res, code)
        if path.startswith("/api/incidents/"):
            inc_id = path.replace("/api/incidents/", "")
            res, code = handle_get_incident_by_id(inc_id)
            return self._send_json(res, code)

        # 8. Blockchain Routes
        if path == "/api/blockchain/evidence":
            res, code = handle_get_evidence(query)
            return self._send_json(res, code)
        if path.startswith("/api/blockchain/evidence/"):
            ev_id = path.replace("/api/blockchain/evidence/", "")
            res, code = handle_get_evidence_by_id(ev_id)
            return self._send_json(res, code)
        if path == "/api/blockchain/blocks":
            res, code = handle_get_blocks(query)
            return self._send_json(res, code)
        if path == "/api/blockchain/audit-chain":
            res, code = handle_audit_chain()
            return self._send_json(res, code)
        if path == "/api/blockchain/peers":
            res, code = handle_get_peers()
            return self._send_json(res, code)

        # 9. AI Routes
        if path == "/api/ai/analysis":
            res, code = handle_get_ai_analyses()
            return self._send_json(res, code)
        if path == "/api/ai/models":
            res, code = handle_get_ai_models()
            return self._send_json(res, code)

        # 10. Assets Routes
        if path == "/api/assets":
            res, code = handle_get_assets(query)
            return self._send_json(res, code)
        if path.startswith("/api/assets/"):
            ast_id = path.replace("/api/assets/", "")
            res, code = handle_get_asset_by_id(ast_id)
            return self._send_json(res, code)

        # 11. SOC Operations
        if path == "/api/soc/team":
            res, code = handle_get_team()
            return self._send_json(res, code)
        if path == "/api/soc/shifts":
            res, code = handle_get_shifts()
            return self._send_json(res, code)

        # 12. Threat Intelligence
        if path == "/api/intel/iocs":
            res, code = handle_get_iocs(query)
            return self._send_json(res, code)
        if path == "/api/intel/cves":
            res, code = handle_get_cves(query)
            return self._send_json(res, code)

        # 13. Reports & Compliance
        if path == "/api/compliance":
            res, code = handle_get_compliance()
            return self._send_json(res, code)
        if path == "/api/reports":
            res, code = handle_get_reports()
            return self._send_json(res, code)

        # 14. Audit Logs
        if path == "/api/audit-logs":
            res, code = handle_get_audit_logs(query)
            return self._send_json(res, code)

        # 15. Frontend SPA & Static Asset Delivery
        if path == "/api-bridge.js":
            return self._send_file(FRONTEND_DIR / "api-bridge.js", "application/javascript")

        if path.startswith("/assets/"):
            asset_file = FRONTEND_DIR / path.lstrip("/")
            mime = "text/css" if path.endswith(".css") else "application/javascript"
            return self._send_file(asset_file, mime)

        # Client-side SPA Route Fallback (index.html)
        index_file = FRONTEND_DIR / "index.html"
        return self._send_file(index_file, "text/html; charset=utf-8")

    def do_POST(self):
        """Route POST requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        body = self._parse_body()
        client_ip = self.client_address[0]
        actor = self.headers.get("X-Actor", "SOC Analyst")

        if path == "/api/auth/login":
            res, code = handle_login(body, client_ip)
            return self._send_json(res, code)

        if path == "/api/auth/register":
            res, code = handle_register(body, client_ip)
            return self._send_json(res, code)

        if path == "/api/auth/verify-2fa":
            res, code = handle_verify_2fa(body)
            return self._send_json(res, code)

        if path == "/api/threats":
            res, code = handle_create_threat(body, actor=actor)
            return self._send_json(res, code)

        if path.endswith("/quarantine") and "/api/threats/" in path:
            threat_id = path.replace("/api/threats/", "").replace("/quarantine", "")
            res, code = handle_quarantine_threat(threat_id, actor=actor)
            return self._send_json(res, code)

        if path == "/api/incidents":
            res, code = handle_create_incident(body, actor=actor)
            return self._send_json(res, code)

        if path.endswith("/actions") and "/api/incidents/" in path:
            inc_id = path.replace("/api/incidents/", "").replace("/actions", "")
            res, code = handle_incident_action(inc_id, body, actor=actor)
            return self._send_json(res, code)

        if path == "/api/blockchain/anchor":
            res, code = handle_anchor_evidence(body, actor=actor)
            return self._send_json(res, code)

        if path.startswith("/api/blockchain/verify/"):
            ev_id = path.replace("/api/blockchain/verify/", "")
            res, code = handle_verify_evidence(ev_id)
            return self._send_json(res, code)

        if path == "/api/ai/analyze-sample":
            res, code = handle_analyze_sample(body)
            return self._send_json(res, code)

        if path == "/api/assets":
            res, code = handle_create_asset(body, actor=actor)
            return self._send_json(res, code)

        if path.endswith("/isolate") and "/api/assets/" in path:
            ast_id = path.replace("/api/assets/", "").replace("/isolate", "")
            res, code = handle_isolate_asset(ast_id, actor=actor)
            return self._send_json(res, code)

        if path == "/api/soc/assign":
            res, code = handle_assign_incident(body, actor=actor)
            return self._send_json(res, code)

        if path == "/api/intel/lookup":
            res, code = handle_lookup(body)
            return self._send_json(res, code)

        if path == "/api/reports/generate":
            res, code = handle_generate_report(body, actor=actor)
            return self._send_json(res, code)

        if path == "/api/audit-logs":
            res, code = handle_create_audit_log(body, client_ip)
            return self._send_json(res, code)

        self._send_json({"error": f"POST endpoint '{path}' not found"}, 404)

    def do_PATCH(self):
        """Route PATCH requests."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        body = self._parse_body()
        actor = self.headers.get("X-Actor", "SOC Analyst")

        if path.startswith("/api/threats/"):
            threat_id = path.replace("/api/threats/", "")
            res, code = handle_update_threat(threat_id, body, actor=actor)
            return self._send_json(res, code)

        if path.startswith("/api/incidents/"):
            inc_id = path.replace("/api/incidents/", "")
            res, code = handle_update_incident(inc_id, body, actor=actor)
            return self._send_json(res, code)

        if path.startswith("/api/assets/"):
            ast_id = path.replace("/api/assets/", "")
            res, code = handle_update_asset(ast_id, body, actor=actor)
            return self._send_json(res, code)

        self._send_json({"error": f"PATCH endpoint '{path}' not found"}, 404)


def run_server():
    """Initialize database and start multi-threaded HTTP server."""
    print("=" * 65)
    print("🛡️  SENTINEL CHAIN — ENTERPRISE POST-QUANTUM DEFENSE SERVER")
    print("=" * 65)
    print("[*] Initializing SQLite Database & Blockchain Ledger...")
    init_db()

    server_address = (HOST, PORT)
    httpd = ThreadedHTTPServer(server_address, SentinelRequestHandler)

    display_host = "localhost" if HOST in ("0.0.0.0", "127.0.0.1") else HOST
    print(f"[✓] Database:       Ready (data/sentinel_chain.db)")
    print(f"[✓] REST API:       http://{display_host}:{PORT}/api")
    print(f"[✓] API Explorer:   http://{display_host}:{PORT}/api/docs")
    print(f"[✓] Web Platform:   http://{display_host}:{PORT}/")
    print(f"[✓] Live Stream:    http://{display_host}:{PORT}/api/threats/stream (SSE)")
    print("=" * 65)
    print("[*] Server is running. Press Ctrl+C to terminate.")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Gracefully stopping Sentinel Chain server...")
        httpd.server_close()
        print("[✓] Server stopped.")


if __name__ == "__main__":
    run_server()
