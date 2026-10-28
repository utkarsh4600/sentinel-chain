/**
 * Sentinel Chain Backend API Bridge & Real-Time Sync Client.
 * Automatically connects the Netlify React SPA to the Python REST & SSE Backend.
 */

(function () {
  console.log("🛡️ [Sentinel Chain] Initializing Backend API Bridge...");

  const API_BASE = window.location.origin;

  // Global API helper
  window.SentinelAPI = {
    async getHealth() {
      const res = await fetch(`${API_BASE}/api/health`);
      return res.json();
    },
    async getDashboardStats() {
      const res = await fetch(`${API_BASE}/api/dashboard/stats`);
      return res.json();
    },
    async getThreats(params = {}) {
      const q = new URLSearchParams(params).toString();
      const res = await fetch(`${API_BASE}/api/threats?${q}`);
      return res.json();
    },
    async createThreat(data) {
      const res = await fetch(`${API_BASE}/api/threats`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
      });
      return res.json();
    },
    async getIncidents(params = {}) {
      const q = new URLSearchParams(params).toString();
      const res = await fetch(`${API_BASE}/api/incidents?${q}`);
      return res.json();
    },
    async getEvidence(params = {}) {
      const q = new URLSearchParams(params).toString();
      const res = await fetch(`${API_BASE}/api/blockchain/evidence?${q}`);
      return res.json();
    },
    async anchorEvidence(incidentId, payload = {}) {
      const res = await fetch(`${API_BASE}/api/blockchain/anchor`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ incidentId, payload })
      });
      return res.json();
    },
    async verifyEvidence(evidenceId) {
      const res = await fetch(`${API_BASE}/api/blockchain/verify/${evidenceId}`, { method: "POST" });
      return res.json();
    },
    async auditChain() {
      const res = await fetch(`${API_BASE}/api/blockchain/audit-chain`);
      return res.json();
    },
    async analyzeSample(sample, target = "Monitored-Asset") {
      const res = await fetch(`${API_BASE}/api/ai/analyze-sample`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sample, target })
      });
      return res.json();
    }
  };

  // Render high-tech floating backend status pill
  function injectStatusPill() {
    const pill = document.createElement("div");
    pill.id = "sentinel-backend-pill";
    pill.innerHTML = `
      <div style="position:fixed;bottom:20px;right:20px;z-index:99999;display:flex;align-items:center;gap:10px;background:rgba(15,23,42,0.92);border:1px solid rgba(56,189,248,0.4);border-radius:999px;padding:8px 16px;box-shadow:0 10px 30px rgba(0,0,0,0.6);backdrop-filter:blur(8px);font-family:'Space Grotesk',sans-serif;font-size:12px;color:#f8fafc;">
        <span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:#10b981;box-shadow:0 0 10px #10b981;animation:pulse 2s infinite;"></span>
        <span style="font-weight:600;letter-spacing:0.02em;">Backend API Online</span>
        <span style="color:#64748b;">|</span>
        <a href="/api/docs" target="_blank" style="color:#38bdf8;text-decoration:none;font-weight:600;display:flex;align-items:center;gap:4px;">
          REST Docs &amp; Explorer &rarr;
        </a>
      </div>
    `;
    document.body.appendChild(pill);
  }

  // Connect Server-Sent Events (SSE) for live threats
  function connectSSE() {
    try {
      const eventSource = new EventSource(`${API_BASE}/api/threats/stream`);
      eventSource.onmessage = function (event) {
        try {
          const parsed = JSON.parse(event.data);
          console.log("⚡ [Sentinel Live Stream] Event received:", parsed);
        } catch (e) {}
      };
      eventSource.onerror = function () {
        // Auto-reconnect managed by EventSource
      };
    } catch (e) {
      console.warn("SSE connection skipped or unsupported");
    }
  }

  window.addEventListener("DOMContentLoaded", () => {
    injectStatusPill();
    connectSSE();
  });
})();
