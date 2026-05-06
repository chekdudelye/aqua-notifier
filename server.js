/**
 * ╔═══════════════════════════════════════════════════════╗
 * ║           AQUA NOTIFIER - WebSocket Server            ║
 * ║   Receives scan data from hoppers, serves to clients  ║
 * ╚═══════════════════════════════════════════════════════╝
 */

const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const cors = require("cors");

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(cors());
app.use(express.json());

// ─────────────────────────────────────────────
// CONFIG
// ─────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
const API_SECRET = process.env.API_SECRET || "ae55e3445f7e585c6295c103f0f5c245fa7275aa4bea8b9bfbffbf6e7ca6e719";
const MAX_FINDINGS = 200; // Max entries kept in memory

// ─────────────────────────────────────────────
// IN-MEMORY STORE
// ─────────────────────────────────────────────
let findings = [];        // All recent brainrot findings
let servers = {};         // jobId -> { players, maxPlayers, brainrots, timestamp }
let connectedClients = 0;

// ─────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────
function log(tag, msg) {
  const time = new Date().toISOString().split("T")[1].split(".")[0];
  console.log(`[${time}][${tag}] ${msg}`);
}

function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(msg);
    }
  });
}

function addFinding(jobId, brainrots, players) {
  const timestamp = Date.now();
  for (const b of brainrots) {
    const entry = {
      id: `${jobId}_${b.name}_${timestamp}`,
      job_id: jobId,
      jobId: jobId,
      name: b.name,
      value: b.value || 0,
      tier: b.tier || "Unknown",
      mutation: b.mutation || null,
      traits: b.traits || [],
      players: players || 0,
      timestamp,
    };
    findings.unshift(entry);
  }
  // Trim
  if (findings.length > MAX_FINDINGS) {
    findings = findings.slice(0, MAX_FINDINGS);
  }
}

// ─────────────────────────────────────────────
// AUTH MIDDLEWARE (optional for add-server)
// ─────────────────────────────────────────────
function authMiddleware(req, res, next) {
  const secret = req.headers["x-api-secret"];
  if (secret && secret !== API_SECRET) {
    return res.status(403).json({ error: "Forbidden" });
  }
  next();
}

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────

/** Health check */
app.get("/", (req, res) => {
  res.json({
    name: "Aqua Notifier",
    status: "online",
    clients: connectedClients,
    findings: findings.length,
    servers: Object.keys(servers).length,
  });
});

/**
 * POST /add-server
 * Called by the hopper when it finds brainrots.
 * Body: { jobId, players, brainrots: [{name, value, tier, mutation, traits}], timestamp, vps }
 */
app.post("/add-server", authMiddleware, (req, res) => {
  const { jobId, players, brainrots, vps } = req.body;

  if (!jobId || !Array.isArray(brainrots) || brainrots.length === 0) {
    return res.status(400).json({ error: "Missing jobId or brainrots" });
  }

  log("ADD", `JobID=${jobId} | VPS=${vps || "?"} | Brainrots=${brainrots.length} | Players=${players || 0}`);

  // Store server
  servers[jobId] = {
    jobId,
    players: players || 0,
    brainrots,
    vps: vps || "unknown",
    timestamp: Date.now(),
  };

  // Store individual findings
  addFinding(jobId, brainrots, players);

  // Broadcast to all connected WebSocket clients (auto-joiners)
  broadcast({
    type: "new_findings",
    jobId,
    players,
    brainrots,
    timestamp: Date.now(),
  });

  res.json({ ok: true, received: brainrots.length });
});

/**
 * GET /recent
 * Polled by Aqua Notifier UI to get latest findings.
 * Returns format compatible with the existing Aqua Notifier polling code.
 */
app.get("/recent", (req, res) => {
  const limit = parseInt(req.query.limit) || 50;
  res.json({
    findings: findings.slice(0, limit),
    // Also expose as 'logs' for compatibility
    logs: findings.slice(0, limit),
    total: findings.length,
    timestamp: Date.now(),
  });
});

/**
 * GET /servers
 * Returns all active servers with brainrots (for dashboard).
 */
app.get("/servers", (req, res) => {
  const active = Object.values(servers)
    .filter((s) => Date.now() - s.timestamp < 5 * 60 * 1000) // last 5 min
    .sort((a, b) => b.timestamp - a.timestamp);
  res.json({ servers: active, count: active.length });
});

/**
 * POST /clear
 * Clears all stored findings (for admin use).
 */
app.post("/clear", authMiddleware, (req, res) => {
  findings = [];
  servers = {};
  log("CLEAR", "All findings cleared");
  broadcast({ type: "cleared" });
  res.json({ ok: true });
});

// ─────────────────────────────────────────────
// WEBSOCKET
// ─────────────────────────────────────────────
wss.on("connection", (ws, req) => {
  connectedClients++;
  const ip = req.socket.remoteAddress;
  log("WS", `Client connected | IP=${ip} | Total=${connectedClients}`);

  // Send current findings on connect
  ws.send(JSON.stringify({
    type: "init",
    findings: findings.slice(0, 50),
    servers: Object.values(servers).filter((s) => Date.now() - s.timestamp < 5 * 60 * 1000),
    timestamp: Date.now(),
  }));

  ws.on("message", (raw) => {
    try {
      const msg = JSON.parse(raw);

      // Client can request latest findings
      if (msg.type === "get_recent") {
        ws.send(JSON.stringify({
          type: "recent",
          findings: findings.slice(0, msg.limit || 50),
        }));
      }

      // Client can send join intent (for tracking)
      if (msg.type === "join_intent") {
        log("JOIN", `Client joining JobID=${msg.jobId}`);
      }

    } catch (e) {
      // ignore parse errors
    }
  });

  ws.on("close", () => {
    connectedClients--;
    log("WS", `Client disconnected | Total=${connectedClients}`);
  });

  ws.on("error", (err) => {
    log("WS_ERR", err.message);
  });
});

// ─────────────────────────────────────────────
// AUTO CLEANUP - remove findings older than 30 min
// ─────────────────────────────────────────────
setInterval(() => {
  const cutoff = Date.now() - 30 * 60 * 1000;
  const before = findings.length;
  findings = findings.filter((f) => f.timestamp > cutoff);
  // Clean stale servers
  for (const [id, s] of Object.entries(servers)) {
    if (Date.now() - s.timestamp > 10 * 60 * 1000) delete servers[id];
  }
  if (before !== findings.length) {
    log("CLEANUP", `Removed ${before - findings.length} old findings`);
  }
}, 60 * 1000);

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
server.listen(PORT, () => {
  log("BOOT", `╔════════════════════════════════════════╗`);
  log("BOOT", `║        AQUA NOTIFIER SERVER            ║`);
  log("BOOT", `║  HTTP + WebSocket running on :${PORT}     ║`);
  log("BOOT", `╚════════════════════════════════════════╝`);
  log("BOOT", `Endpoints:`);
  log("BOOT", `  POST /add-server   <- hopper sends findings here`);
  log("BOOT", `  GET  /recent       <- Aqua Notifier UI polls here`);
  log("BOOT", `  GET  /servers      <- dashboard`);
  log("BOOT", `  WS   ws://...      <- auto-joiner connects here`);
});
