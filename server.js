* Garama Notifier - WebSocket Server v2
 * Protected: token auth + rate limiting + IP logging + request signing
 */

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
// CONFIG  — set these as env vars on Render
// ─────────────────────────────────────────────
const PORT         = process.env.PORT         || 3000;

// Secret the hopper bots use to POST findings
const API_SECRET   = process.env.API_SECRET   || "niggersinlightsass";

// Secret the UI + WS clients use to READ findings
const CLIENT_TOKEN = process.env.CLIENT_TOKEN || "niggersinlightsass";

// Max requests per IP per minute (anti-scrape)
const RATE_LIMIT   = parseInt(process.env.RATE_LIMIT || "60");

const MAX_FINDINGS = 200;

// ─────────────────────────────────────────────
// IN-MEMORY STORE
// ─────────────────────────────────────────────
let findings         = [];
let servers          = {};
let connectedClients = 0;

// ─────────────────────────────────────────────
// RATE LIMITER  (per IP, per minute)
// ─────────────────────────────────────────────
const rateBuckets = {};

function checkRateLimit(ip) {
  const now    = Date.now();
  const bucket = rateBuckets[ip] || { count: 0, reset: now + 60000 };

  if (now > bucket.reset) {
    bucket.count = 0;
    bucket.reset = now + 60000;
  }

  bucket.count++;
  rateBuckets[ip] = bucket;

  return bucket.count <= RATE_LIMIT;
}

// Clean rate buckets every 2 minutes
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
  const ipStr = ip ? ` [${ip}]` : "";
  console.log(`[${time}][${tag}]${ipStr} ${msg}`);
}

function getIP(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0]?.trim()
    || req.socket?.remoteAddress
    || "unknown";
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
    findings.unshift({
      id:        `${jobId}_${b.name}_${timestamp}`,
      job_id:    jobId,
      jobId:     jobId,
      name:      b.name,
      value:     b.value  || 0,
      tier:      b.tier   || "Unknown",
      mutation:  b.mutation || null,
      inDuel:    b.inDuel   || false,
      isCarpet:  b.isCarpet || false,
      players:   players   || 0,
      timestamp,
    });
  }
  if (findings.length > MAX_FINDINGS) findings = findings.slice(0, MAX_FINDINGS);
}

// ─────────────────────────────────────────────
// HMAC request signing check (optional extra layer)
// Hopper sends X-Signature: HMAC-SHA256(body, API_SECRET)
// ─────────────────────────────────────────────
function verifySignature(req, rawBody) {
  const sig = req.headers["x-signature"];
  if (!sig) return true; // signature optional — token is enough
  const expected = crypto
    .createHmac("sha256", API_SECRET)
    .update(rawBody)
    .digest("hex");
  return sig === expected;
}

// ─────────────────────────────────────────────
// AUTH MIDDLEWARES
// ─────────────────────────────────────────────

// For hopper POST routes — checks x-api-secret header
function hopperAuth(req, res, next) {
  const ip = getIP(req);

  if (!checkRateLimit(ip)) {
    log("RATE", `Rate limit hit`, ip);
    return res.status(429).json({ error: "Too many requests" });
  }

  const secret = req.headers["x-api-secret"];
  if (!secret || secret !== API_SECRET) {
    log("AUTH", `Rejected hopper - bad secret`, ip);
    return res.status(403).json({ error: "Forbidden" });
  }
  next();
}

// For UI GET routes — checks ?token= or x-client-token header
function clientAuth(req, res, next) {
  const ip    = getIP(req);

  if (!checkRateLimit(ip)) {
    log("RATE", `Rate limit hit`, ip);
    return res.status(429).json({ error: "Too many requests" });
  }

  const token = req.query.token || req.headers["x-client-token"];
  if (!token || token !== CLIENT_TOKEN) {
    log("AUTH", `Rejected client - bad token`, ip);
    return res.status(403).json({ error: "Unauthorized" });
  }
  next();
}

// ─────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────

/** Health — public, no auth, minimal info */
app.get("/", (req, res) => {
  res.json({ name: "Garama Notifier", status: "online" });
});

/**
 * POST /add-server
 * Called by hopper bots when they find brainrots.
 */
app.post("/add-server", hopperAuth, (req, res) => {
  const ip = getIP(req);
  const { jobId, players, brainrots, vps } = req.body;

  if (!jobId || !Array.isArray(brainrots) || brainrots.length === 0) {
    return res.status(400).json({ error: "Missing jobId or brainrots" });
  }

  log("ADD", `JobID=${jobId} VPS=${vps||"?"} Brainrots=${brainrots.length} Players=${players||0}`, ip);

  servers[jobId] = { jobId, players: players||0, brainrots, vps: vps||"?", timestamp: Date.now() };
  addFinding(jobId, brainrots, players);

  broadcast({ type: "new_findings", jobId, players, brainrots, timestamp: Date.now() });

  res.json({ ok: true, received: brainrots.length });
});

/**
 * GET /recent
 * Polled by Garama Notifier UI.
 */
app.get("/recent", clientAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  res.json({
    findings:  findings.slice(0, limit),
    logs:      findings.slice(0, limit),
    total:     findings.length,
    timestamp: Date.now(),
  });
});

/**
 * GET /servers
 * Active servers (last 5 min).
 */
app.get("/servers", clientAuth, (req, res) => {
  const active = Object.values(servers)
    .filter(s => Date.now() - s.timestamp < 5 * 60 * 1000)
    .sort((a, b) => b.timestamp - a.timestamp);
  res.json({ servers: active, count: active.length });
});

/**
 * POST /clear — admin only
 */
app.post("/clear", hopperAuth, (req, res) => {
  findings = [];
  servers  = {};
  log("CLEAR", "All findings cleared");
  broadcast({ type: "cleared" });
  res.json({ ok: true });
});

// ─────────────────────────────────────────────
// WEBSOCKET  — token required in query string
// Connect: wss://your-url?token=CLIENT_TOKEN
// ─────────────────────────────────────────────
wss.on("connection", (ws, req) => {
  const ip = getIP(req);

  // Rate limit WS connections too
  if (!checkRateLimit(ip)) {
    log("WS", `Rate limit - closing`, ip);
    ws.close(4029, "Too many requests");
    return;
  }

  // Token check
  let token = null;
  try {
    const url = new URL(req.url, "http://localhost");
    token = url.searchParams.get("token");
  } catch(_) {}

  if (!token || token !== CLIENT_TOKEN) {
    log("WS", `Rejected - bad token`, ip);
    ws.close(4003, "Unauthorized");
    return;
  }

  connectedClients++;
  log("WS", `Connected | total=${connectedClients}`, ip);

  // Send current findings on connect
  ws.send(JSON.stringify({
    type:      "init",
    findings:  findings.slice(0, 50),
    timestamp: Date.now(),
  }));

  ws.on("message", (raw) => {
    try {
      const msg = JSON.parse(raw);
      if (msg.type === "get_recent") {
        ws.send(JSON.stringify({ type: "recent", findings: findings.slice(0, msg.limit || 50) }));
      }
    } catch (_) {}
  });

  ws.on("close", () => {
    connectedClients--;
    log("WS", `Disconnected | total=${connectedClients}`, ip);
  });

  ws.on("error", (err) => log("WS_ERR", err.message, ip));
});

// ─────────────────────────────────────────────
// CLEANUP — remove findings older than 30 min
// ─────────────────────────────────────────────
setInterval(() => {
  const cutoff = Date.now() - 30 * 60 * 1000;
  const before = findings.length;
  findings = findings.filter(f => f.timestamp > cutoff);
  for (const [id, s] of Object.entries(servers)) {
    if (Date.now() - s.timestamp > 10 * 60 * 1000) delete servers[id];
  }
  if (before !== findings.length) log("CLEANUP", `Removed ${before - findings.length} old findings`);
}, 60 * 1000);

// ─────────────────────────────────────────────
// START
// ─────────────────────────────────────────────
server.listen(PORT, () => {
  log("BOOT", `Garama Notifier Server running on :${PORT}`);
  log("BOOT", `Rate limit: ${RATE_LIMIT} req/min per IP`);
  log("BOOT", `Endpoints: POST /add-server | GET /recent | GET /servers | WS ws://...`);
})
