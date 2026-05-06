# 💧 Aqua Notifier Server

WebSocket + HTTP relay server. Hoppers send findings here → Aqua Notifier UI polls it to auto-join.

## How It Works

```
[HOPPER4]  →  POST /add-server  →  [AQUA SERVER]  →  GET /recent  →  [AQUA NOTIFIER UI]
                                         ↓
                                   WebSocket broadcast
                                         ↓
                               (future WS auto-joiners)
```

## Deploy to Railway (Free)

1. Create account at https://railway.app
2. New Project → Deploy from GitHub repo (or drag this folder)
3. Set environment variable: `API_SECRET=ae55e3445f7e585c6295c103f0f5c245fa7275aa4bea8b9bfbffbf6e7ca6e719`
4. Railway auto-detects Node.js and runs `npm start`
5. Copy your Railway URL (e.g. `https://aqua-notifier.up.railway.app`)

## Deploy to Render (Free)

1. https://render.com → New Web Service
2. Connect your repo
3. Build command: `npm install`
4. Start command: `node server.js`
5. Add env var `API_SECRET`

## After Deploying

Set `AQUA_SERVER` in BOTH Lua files:

**hopper4_aqua.lua** (line ~50):
```lua
local AQUA_SERVER = "https://your-url.up.railway.app"
```

**aqua_notifier_ui.lua** (line ~20):
```lua
local AQUA_SERVER = "https://your-url.up.railway.app"
```

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | `/` | Health check |
| POST | `/add-server` | Hopper sends findings |
| GET | `/recent` | UI polls for new logs |
| GET | `/servers` | Active servers with targets |
| POST | `/clear` | Clear all findings |
| WS | `ws://...` | Real-time WebSocket |

## Local Testing

```bash
npm install
node server.js
# Server runs on http://localhost:3000
```

Test with curl:
```bash
# Send a fake finding
curl -X POST http://localhost:3000/add-server \
  -H "Content-Type: application/json" \
  -d '{"jobId":"abc123","players":10,"brainrots":[{"name":"Skibidi Toilet","value":500000000,"tier":"300m"}]}'

# Check recent
curl http://localhost:3000/recent
```
