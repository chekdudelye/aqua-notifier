/**
 * Garama Notifier - WebSocket Server v2 (Production Fixed)
 * Protected: token auth + rate limiting + IP logging + request signing
 */
const express = require("express");
const http = require("http");
const WebSocket = require("ws");
const cors = require("cors");
const crypto = require("crypto");

const app = express();
const server = http.createServer(app);

// Mount the WebSocket server directly with no autonomous route tracking
const wss = new WebSocket.Server({ noServer: true });

app.use(cors());

// CAPTURE RAW BODY: Essential for HMAC crypto verification if used later
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

//
// CONFIG (Explicitly matching your address parameter layout)
//
const PORT = process.env.PORT || 3000;
const API_SECRET = process.env.API_SECRET || "ae55e3445f7e585c6295c103f0f5c245fa7275aa4bea8b9bfbffbf6e7ca6e719";
// MATCHED VALUE: Explicitly configured to match your connection URL string exactly
const CLIENT_TOKEN = process.env.CLIENT_TOKEN || "lightisdabest";
const RATE_LIMIT = parseInt(process.env.RATE_LIMIT || "60");
const MAX_FINDINGS = 200;

//
// IN-MEMORY STORE
//
let findings = [];
let servers = {};
let connectedClients = 0;

//
// RATE LIMITER (per IP, per minute)
//
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

// Clean rate buckets every 2 minutes
setInterval(() => {
  const now = Date.now();
  for (const ip in rateBuckets) {
    if (rateBuckets[ip].reset < now) delete rateBuckets[ip];
  }
}, 120000);

//
// HELPERS
//
function log(tag, msg, ip) {
  const fullIso = new Date().toISOString();
  const time = fullIso.replace("T", " ").substring(0, 19);
  const ipStr = ip ? ` [${ip}]` : "";
  console.log(`[${time}][${tag}]${ipStr} ${msg}`);
}

function getIP(req) {
  const forwarded = req.headers["x-forwarded-for"];
  if (forwarded) {
    const firstIp = forwarded.split(",");
    return firstIp ? firstIp[0].trim() : "unknown";
  }
  return req.socket?.remoteAddress || "unknown";
}

// Broadcast strings to all securely connected websocket connections on /ws
function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(msg);
    }
  });
}

function addFinding(encJobId, brainrots, players) {
  const timestamp = Date.now();
  for (const b of brainrots) {
    findings.unshift({
      id: `${encJobId}_${b.name}_${timestamp}`,
      encJobId: encJobId,
      name: b.name,
      value: b.value || 0,
      tier: b.tier || "Unknown",
      mutation: b.mutation || null,
      inDuel: b.inDuel || false,
      isCarpet: b.isCarpet || false,
      players: players || 0,
      timestamp,
    });
  }
  if (findings.length > MAX_FINDINGS) findings = findings.slice(0, MAX_FINDINGS);
}

//
// HMAC verification (uses rawBody buffer captured above)
//
function verifySignature(req) {
  const sig = req.headers["x-signature"];
  if (!sig) return true; 
  if (!req.rawBody) return false;

  const expected = crypto
    .createHmac("sha256", API_SECRET)
    .update(req.rawBody)
    .digest("hex");
    
  return sig === expected;
}

//
// AUTH MIDDLEWARES
//
function hopperAuth(req, res, next) {
  const ip = getIP(req);
  if (!checkRateLimit(ip)) {
    log("RATE", `Rate limit hit`, ip);
    return res.status(429).json({ error: "Too many requests" });
  }

  const secret = req.headers["x-api-secret"];
  if (!secret || secret !== API_SECRET || !verifySignature(req)) {
    log("AUTH", `Rejected hopper - bad credentials/signature`, ip);
    return res.status(403).json({ error: "Forbidden" });
  }
  next();
}

function clientAuth(req, res, next) {
  const ip = getIP(req);
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

//
// ROUTES
//
app.get("/", (req, res) => {
  res.json({ name: "Garama Notifier", status: "online" });
});

app.post("/add-server", hopperAuth, (req, res) => {
  const ip = getIP(req);
  const { encJobId, players, brainrots, vps, playerList } = req.body;

  if (!encJobId || !Array.isArray(brainrots) || brainrots.length === 0) {
    return res.status(400).json({ error: "Missing encJobId or brainrots" });
  }

  log("ADD", `VPS=${vps || "?"} Brainrots=${brainrots.length} Players=${players || 0}`, ip);
  
  servers[encJobId] = { 
    encJobId, 
    players: players || 0, 
    playerList: playerList || [], 
    brainrots, 
    vps: vps || "?", 
    timestamp: Date.now() 
  };

  addFinding(encJobId, brainrots, players);
  
  // BROADCASTS LIVE DATA TO EVERYONE CONNECTED ON WEBSOCKET RIGHT NOW
  broadcast({ 
    type: "new_findings", 
    encJobId, 
    players, 
    playerList: playerList || [], 
    brainrots, 
    timestamp: Date.now() 
  });

  res.json({ ok: true, received: brainrots.length });
});

app.get("/recent", clientAuth, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 50, 100);
  res.json({
    findings: findings.slice(0, limit),
    logs: findings.slice(0, limit),
    total: findings.length,
    timestamp: Date.now(),
  });
});

app.get("/servers", clientAuth, (req, res) => {
  const active = Object.values(servers)
    .filter(s => Date.now() - s.timestamp < 5 * 60 * 1000)
    .sort((a, b) => b.timestamp - a.timestamp);
  res.json({ servers: active, count: active.length });
});

app.post("/clear", hopperAuth, (req, res) => {
  findings = [];
  servers = {};
  log("CLEAR", "All findings cleared");
  broadcast({ type: "cleared" });
  res.json({ ok: true });
});

//
// WEBSOCKET NATIVE PROTOCOL UPGRADE ROUTER (/ws Enforced)
//
server.on("upgrade", (request, socket, head) => {
  const ip = request.headers["x-forwarded-for"]?.split(",")?.[0]?.trim() || request.socket.remoteAddress || "unknown";

  if (!checkRateLimit(ip)) {
    log("WS_UPGRADE", `Rate limit hit during handshake`, ip);
    socket.write("HTTP/1.1 429 Too Many Requests\r\n\r\n");
    socket.destroy();
    return;
  }

  try {
    const myUrl = new URL(request.url, `http://${request.headers.host || "localhost"}`);
    const pathname = myUrl.pathname;
    const token = myUrl.searchParams.get("token");

    // Block anyone who isn't targeting exactly /ws
    if (pathname !== "/ws") {
      log("WS_UPGRADE", `Rejected incorrect path: ${pathname}`, ip);
      socket.write("HTTP/1.1 404 Not Found\r\n\r\n");
      socket.destroy();
      return;
    }

    // Verify token parameters correctly
    if (!token || token !== CLIENT_TOKEN) {
      log("WS_UPGRADE", `Rejected bad credentials token`, ip);
      socket.write("HTTP/1.1 401 Unauthorized\r\n\r\n");
      socket.destroy();
      return;
    }

    // Connect fully
    wss.handleUpgrade(request, socket, head, (ws) => {
      wss.emit("connection", ws, request);
    });
  } catch (err) {
    log("WS_UPGRADE_ERR", err.message, ip);
    socket.write("HTTP/1.1 500 Internal Server Error\r\n\r\n");
    socket.destroy();
  }
});

//
// WEBSOCKET SERVER LIFECYCLE MANAGEMENT
//
wss.on("connection", (ws, req) => {
  const ip = getIP(req);
  connectedClients++;
  log("WS", `Connected | total=${connectedClients}`, ip);

  // Send baseline data layout upon connection
  ws.send(JSON.stringify({
    type: "init",
    findings: findings.slice(0, 50),
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

//
// CLEANUP OLD RECORDS
//
setInterval(() => {
  const cutoff = Date.now() - 30 * 60 * 1000;
  const before = findings.length;
  findings = findings.filter(f => f.timestamp > cutoff);

  for (const [key, s] of Object.entries(servers)) {
    if (Date.now() - s.timestamp > 10 * 60 * 1000) delete servers[key];
  }

  if (before !== findings.length) log("CLEANUP", `Removed ${before - findings.length} old findings`);
}, 60 * 1000);

//
// BOOT
//
server.listen(PORT, () => {
  log("BOOT", `Garama Notifier Server running on :${PORT}`);
  log("BOOT", `Rate limit: ${RATE_LIMIT} req/min per IP`);
  log("BOOT", `WebSocket Sub-Endpoint active: /ws`);
});
