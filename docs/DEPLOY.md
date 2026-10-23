# ScamShield Deployment Guide

ScamShield provides a production-ready, containerized backend serving the MCP Streamable HTTP endpoint (`/mcp`), health monitoring (`/healthz`), simulated Alexa+ brain (`/api/agent`), and simulator web UI (`/web`).

---

## 1. Local Deployment with Docker & Docker Compose

### Prerequisites
- Docker Engine & Docker Compose

### Running Locally
```bash
# Build and run the container with SQLite volume persistence
docker compose up --build -d

# Verify health status
curl http://127.0.0.1:8000/healthz

# Run production smoke test against local container
python scripts/smoke_prod.py http://127.0.0.1:8000

# Stop the container
docker compose down
```

---

## 2. Cloud Deployment: Render (Recommended Free Tier)

Render offers free web service hosting with automatic HTTPS and Docker support.

### Step-by-Step Setup:
1. **Push your repo to GitHub** (public or private).
2. Log in to [dashboard.render.com](https://dashboard.render.com) and click **New + > Web Service**.
3. Connect your GitHub repository `ScamShield`.
4. Configure service settings:
   - **Name:** `scamshield`
   - **Region:** Ohio (US East) or Frankfurt (EU)
   - **Environment:** `Docker` (or `Python 3`)
   - **Branch:** `main` (or `master`)
   - **Plan:** `Free`
5. If using Native Python instead of Docker:
   - **Build Command:** `pip install .`
   - **Start Command:** `uvicorn scamshield.app:app --host 0.0.0.0 --port $PORT`
6. Add **Environment Variables**:
   | Variable | Value | Purpose |
   | :--- | :--- | :--- |
   | `PORT` | `8000` (or leave default assigned by Render) | Server listening port |
   | `ALLOWED_ORIGINS` | `https://your-service.onrender.com,http://localhost:8000` | DNS rebinding protection on `/mcp` |
   | `ALLOWED_HOSTS` | `127.0.0.1,localhost,your-service.onrender.com` | MCP transport host header verification |
   | `DB_PATH` | `/app/data/scamshield.db` (or `./data/scamshield.db`) | SQLite file path |
   | `BEDROCK_MODEL_ID` | `anthropic.claude-3-haiku-20240307-v1:0` | Bedrock model ID |
   | `AWS_REGION` | `us-east-1` | AWS region |
   | `AWS_ACCESS_KEY_ID` | *(Optional, your AWS key)* | For live Bedrock Converse API |
   | `AWS_SECRET_ACCESS_KEY` | *(Optional, your AWS secret)* | For live Bedrock Converse API |
7. Click **Create Web Service**.
8. Once deployed, note your public HTTPS URL (it will look like `https://<your-service-name>.onrender.com`; the exact name depends on what you choose).

> **Note on Free Tier Storage:** Render's free tier uses ephemeral storage, which resets SQLite cases if the instance restarts. For hackathon demos, this is completely acceptable because each demo session opens fresh case files dynamically.

---

## 3. Alternative Cloud Hosts

### Fly.io
```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Launch app configuration
fly launch --name scamshield --no-deploy

# Add persistent volume for SQLite
fly volumes create scamshield_data --size 1

# Set secrets
fly secrets set ALLOWED_ORIGINS="https://scamshield.fly.dev"

# Deploy
fly deploy
```

### Railway
1. Click **New Project > Deploy from GitHub repo**.
2. Railway detects the `Dockerfile` automatically.
3. In service variables, set `PORT=8000` and `ALLOWED_ORIGINS=https://scamshield.up.railway.app`.

---

## 4. Cold-Start Pre-Warming (Crucial for Demo Recording)

Free hosting tiers (such as Render or Fly.io) spin down after 15 minutes of inactivity. A cold start can take 30 to 50 seconds to initialize.

### Pre-Warming Protocol:
1. **5 minutes before recording your video demo**, warm the server:
   ```bash
   curl -I https://your-service.onrender.com/healthz
   ```
2. Verify you get `HTTP/2 200` with `{"status":"ok"}`.
3. Run the smoke script to warm up MCP session memory and the detection engine:
   ```bash
   python scripts/smoke_prod.py https://your-service.onrender.com
   ```
4. **Automated Keep-Alive:** You can set up a free monitor on [UptimeRobot](https://uptimerobot.com) or [Cron-Job.org](https://cron-job.org) pinging `https://your-service.onrender.com/healthz` every 10 minutes during judging.

---

## 5. Verification with MCP Inspector

Judges can connect the official MCP Inspector to verify that ScamShield is a genuine MCP Streamable HTTP server:

```bash
npx @modelcontextprotocol/inspector http://127.0.0.1:8000/mcp
```
*(Or against the deployed URL):*
```bash
npx @modelcontextprotocol/inspector https://your-service.onrender.com/mcp
```

### What You Should See in MCP Inspector:
1. **Connection:** Select transport **Streamable HTTP**.
2. **Server Info:** Name: `ScamShield`, version: `0.1.0`.
3. **Tools Tab:** Displays all 7 registered tools:
   - `analyze_message`
   - `check_link`
   - `open_case`
   - `add_evidence`
   - `get_case`
   - `next_steps`
   - `generate_report`
4. **Testing a Tool:** Click `analyze_message`, enter a sample scam text, and click **Run Tool**. You will see the structured JSON risk assessment and voice-first `speak` response.
