const express   = require("express");
const http      = require("http");
const WebSocket = require("ws");
const cors      = require("cors");

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocket.Server({ server });

app.use(cors());
app.use(express.json());

// ─────────────────────────────
// CONFIG
// ─────────────────────────────
const PORT = process.env.PORT || 3000;
const CLIENT_TOKEN = process.env.CLIENT_TOKEN || "garama2026secret";

// ─────────────────────────────
// MEMORY STORE
// ─────────────────────────────
let findings = [];
let servers  = {};

// ─────────────────────────────
// BROADCAST
// ─────────────────────────────
function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(msg);
    }
  });
}

// ─────────────────────────────
// ROUTES
// ─────────────────────────────
app.get("/", (req, res) => {
  res.json({ status: "online" });
});

app.post("/add-server", (req, res) => {
  const { jobId, brainrots, players } = req.body;

  if (!jobId || !Array.isArray(brainrots)) {
    return res.status(400).json({ error: "bad request" });
  }

  servers[jobId] = { jobId, players, timestamp: Date.now() };

  const timestamp = Date.now();

  brainrots.forEach(b => {
    findings.unshift({
      jobId,
      name: b.name,
      value: b.value || 0,
      tier: b.tier || "Unknown",
      players: players || 0,
      timestamp
    });
  });

  broadcast({
    type: "new_findings",
    jobId,
    brainrots,
    players,
    timestamp
  });

  res.json({ ok: true });
});

app.get("/recent", (req, res) => {
  res.json({ findings: findings.slice(0, 50) });
});

// ─────────────────────────────
// DASHBOARD (FIXED)
// ─────────────────────────────
app.get("/dashboard", (req, res) => {
  const token = req.query.token;

  if (token !== CLIENT_TOKEN) {
    return res.status(403).send("Unauthorized");
  }

  res.send(`
<!DOCTYPE html>
<html>
<head>
<title>Live Dashboard</title>
<style>
body { background:#0f0f0f; color:white; font-family:Arial; padding:20px; }
table { width:100%; border-collapse:collapse; }
th, td { border:1px solid #333; padding:8px; }
th { background:#1c1c1c; }
tr:nth-child(even){background:#151515;}
</style>
</head>
<body>

<h1>⚡ LIVE DASHBOARD</h1>

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

// WebSocket (REAL TIME)
const ws = new WebSocket(
  (location.protocol === "https:" ? "wss://" : "ws://") +
  location.host +
  "/?token=" + token
);

const rows = document.getElementById("rows");

function addRow(f) {
  const tr = document.createElement("tr");

  // ✅ FIXED TEMPLATE STRING (no syntax errors)
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
fetch("/recent")
  .then(r => r.json())
  .then(data => {
    data.findings.reverse().forEach(addRow);
  });

// live updates
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);

  if (msg.type === "new_findings") {
    msg.brainrots.forEach(b => {
      addRow({
        name: b.name,
        value: b.value,
        tier: b.tier,
        players: msg.players,
        timestamp: Date.now()
      });
    });
  }
};
</script>

</body>
</html>
  `);
});

// ─────────────────────────────
// WEBSOCKET SERVER
// ─────────────────────────────
wss.on("connection", (ws, req) => {
  const url = new URL(req.url, "http://localhost");
  const token = url.searchParams.get("token");

  if (token !== CLIENT_TOKEN) {
    ws.close();
    return;
  }

  ws.isAlive = true;

  ws.on("pong", () => {
    ws.isAlive = true;
  });

  ws.send(JSON.stringify({
    type: "init",
    findings: findings.slice(0, 50)
  }));
});

// heartbeat (prevents Render disconnects)
setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30000);

// ─────────────────────────────
// START SERVER
// ─────────────────────────────
server.listen(PORT, () => {
  console.log("🚀 Server running on port", PORT);
});
