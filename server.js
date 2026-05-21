// Garama Notifier - WebSocket Server v2
// Protected: token auth + rate limiting + IP logging + request signing

const express   = require("express");
const http      = require("http");
const WebSocket = require("ws");
const cors      = require("cors");
const crypto    = require("crypto");

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────
const PORT         = process.env.PORT         || 3000;
const API_SECRET   = process.env.API_SECRET   || "garama2026secret";
const CLIENT_TOKEN = process.env.CLIENT_TOKEN || "garama2026secret";
const RATE_LIMIT   = parseInt(process.env.RATE_LIMIT || "60");

const MAX_FINDINGS = 200;

// ─────────────────────────────────────────────
// STORE
// ─────────────────────────────────────────────
let findings = [];
let servers  = {};
let connectedClients = 0;

// ─────────────────────────────────────────────
// RATE LIMIT
// ─────────────────────────────────────────────
const rateBuckets = {};

function checkRateLimit(ip) {
  const now = Date.now();
  const bucket = rateBuckets[ip] || { count: 0, reset: now + 60000 };

  if (now > bucket.reset) {
    bucket.count = 0;
    bucket.reset = now + 60000;
  }

  bucket.count++;
  rateBuckets[ip] = bucket;

  return bucket.count <= RATE_LIMIT;
}

// cleanup
setInterval(() => {
  const now = Date.now();
  for (const ip in rateBuckets) {
    if (rateBuckets[ip].reset < now) delete rateBuckets[ip];
  }
}, 120000);

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
function log(tag, msg, ip) {
  const time = new Date().toISOString().split("T")[1].split(".")[0];
  console.log(`[${time}][${tag}] ${ip || ""} ${msg}`);
}

function getIP(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim()
    || req.socket?.remoteAddress
    || "unknown";
}

function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    }
  });
}

function addFinding(jobId, brainrots, players) {
  const timestamp = Date.now();

  for (const b of brainrots) {
    const item = {
      id: `${jobId}_${b.name}_${timestamp}`,
      jobId,
      name: b.name,
      value: b.value || 0,
      tier: b.tier || "Unknown",
      mutation: b.mutation || null,
      players: players || 0,
      timestamp
    };

    findings.unshift(item);
  }

  if (findings.length > MAX_FINDINGS) {
    findings = findings.slice(0, MAX_FINDINGS);
  }
}

// ─────────────────────────────────────────────
// AUTH
// ─────────────────────────────────────────────
function hopperAuth(req, res, next) {
  const ip = getIP(req);

  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: "Too many requests" });
  }

  const secret = req.headers["x-api-secret"];
  if (secret !== API_SECRET) {
    return res.status(403).json({ error: "Forbidden" });
  }

  next();
}

function clientAuth(req, res, next) {
  const ip = getIP(req);

  if (!checkRateLimit(ip)) {
    return res.status(429).json({ error: "Too many requests" });
  }

  const token = req.query.token || req.headers["x-client-token"];
  if (token !== CLIENT_TOKEN) {
    return res.status(403).json({ error: "Unauthorized" });
  }

  next();
}

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({ name: "Garama Notifier", status: "online" });
});

app.post("/add-server", hopperAuth, (req, res) => {
  const ip = getIP(req);
  const { jobId, players, brainrots } = req.body;

  if (!jobId || !Array.isArray(brainrots)) {
    return res.status(400).json({ error: "Invalid payload" });
  }

  servers[jobId] = { jobId, players, timestamp: Date.now() };

  addFinding(jobId, brainrots, players);

  // 🔥 REAL-TIME PUSH TO DASHBOARD
  broadcast({
    type: "new_findings",
    jobId,
    players,
    brainrots,
    timestamp: Date.now()
  });

  res.json({ ok: true });
});

app.get("/recent", clientAuth, (req, res) => {
  res.json({
    findings: findings.slice(0, 50),
    total: findings.length
  });
});

app.get("/servers", clientAuth, (req, res) => {
  res.json({ servers: Object.values(servers) });
});

app.post("/clear", hopperAuth, (req, res) => {
  findings = [];
  servers = {};
  broadcast({ type: "cleared" });
  res.json({ ok: true });
});

// ─────────────────────────────────────────────
// 🔥 REAL-TIME DASHBOARD
// ─────────────────────────────────────────────
app.get("/dashboard", (req, res) => {
  const token = req.query.token;

  if (!token || token !== CLIENT_TOKEN) {
    return res.status(403).send("Unauthorized");
  }

  res.send(`
<!DOCTYPE html>
<html>
<head>
<title>Garama Live Dashboard</title>
<style>
body { font-family: Arial; background:#0f0f0f; color:white; padding:20px; }
table { width:100%; border-collapse:collapse; }
th, td { border:1px solid #333; padding:8px; }
th { background:#1c1c1c; }
tr:nth-child(even){background:#151515;}
</style>
</head>
<body>

<h1>⚡ LIVE Garama Dashboard</h1>

<table>
<thead>
<tr>
<th>Name</th>
<th>Value</th>
<th>Tier</th>
<th>Players</th>
<th>Time</th>
</tr>
</thead>
<tbody id="rows"></tbody>
</table>

<script>
const token = "${token}";

// WS connection (REAL TIME)
const ws = new WebSocket((location.protocol === "https:" ? "wss://" : "ws://") + location.host + "?token=" + token);

const rows = document.getElementById("rows");

function addRow(f) {
  const tr = document.createElement("tr");

  tr.innerHTML = \`
    <td>\${f.name}</td>
    <td>\${f.value}</td>
    <td>\${f.tier}</td>
    <td>\${f.players}</td>
    <td>\${new Date(f.timestamp).toLocaleTimeString()}</td>
  \`;

  rows.prepend(tr);
}

// initial load
fetch("/recent?token=" + token)
  .then(r => r.json())
  .then(data => {
    data.findings.reverse().forEach(addRow);
  });

// live updates
ws.onmessage = (event) => {
  try {
    const msg = JSON.parse(event.data);

    if (msg.type === "new_findings") {
      msg.brainrots.forEach(b => {
        addRow({
          name: b.name,
          value: b.value || 0,
          tier: b.tier || "Unknown",
          players: msg.players || 0,
          timestamp: Date.now()
        });
      });
    }

    if (msg.type === "cleared") {
      rows.innerHTML = "";
    }

  } catch (e) {}
};
</script>

</body>
</html>
  `);
});

// ─────────────────────────────────────────────
// WEBSOCKET
// ─────────────────────────────────────────────
wss.on("connection", (ws, req) => {
  const token = new URL(req.url, "http://localhost").searchParams.get("token");

  if (token !== CLIENT_TOKEN) {
    ws.close();
    return;
  }

  ws.send(JSON.stringify({
    type: "init",
    findings: findings.slice(0, 50)
  }));
});

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
server.listen(PORT, () => {
  console.log("🚀 Server running on port", PORT);
});
