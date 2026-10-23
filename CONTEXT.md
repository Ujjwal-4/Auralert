You are a senior engineer helping a solo student developer ship a hackathon project in about 36 hours. Prefer simple, working, well-tested code over ambitious, half-working code.

# Hackathon
Build, Ship, Shape: Amazon Developer Hackathon 2026 (Devpost: amazonappdev2026.devpost.com). Track: Alexa+.
- Alexa+ track accepts a self-hosted MCP server and/or Agent Skill. MCP server must implement MCP spec 2025-11-25 (or later) over Streamable HTTP (not legacy SSE). A clearly labeled simulated Alexa+ experience is allowed for the demo; the real MCP server must be the backend.
- Judging (4 equal criteria): Technical Implementation, Design, Potential Impact, Quality of the Idea. Optional friction log earns a bonus.
- Submission needs: working project, text description, GitHub repo (public), demo video under 3 minutes (public YouTube/Vimeo, English), product feedback on tools used.
- Mini-challenges I am targeting: AWS Builder (use Amazon Bedrock) and Open Source (public repo, OSI license).
- Hard deadline: 23 Oct 2026, 12:00 PM PT.

# Project: AURALERT for Alexa+
Tagline: Voice-first scam defense tool that listens to suspicious calls, checks family safe words, links repeat-offender indicators, and prepares incident reports.
Target users: everyday people and families, especially elders, who get panicked by scams (fake KYC/OTP, UPI collect requests, "digital arrest" calls, courier/customs scams, fake job offers, gift-card and crypto scams, bank/tech-support impersonation, phishing links).
Primary region: India (helpline 1930, cybercrime.gov.in). Must be region-configurable (IN, US, UK at minimum) to show global scalability.

# Architecture
- Python 3.11+, official MCP Python SDK (FastMCP) served over Streamable HTTP at POST/GET/DELETE /mcp, mounted in a Starlette/FastAPI app.
- Same app serves: /healthz, /api/agent (simulated Alexa+ brain), and static simulator UI from /web.
- State: SQLite (file path from env DB_PATH).
- Simulated Alexa+ brain: Amazon Bedrock Converse API (Claude Haiku-class model, model ID from env BEDROCK_MODEL_ID) that calls the MCP tools over HTTP at runtime. Must have a deterministic rule-based fallback router if Bedrock is unavailable, so the demo never breaks.
- Deploy: Docker + a free host (Render/Fly/Railway). Public HTTPS URL for /mcp.

# MCP tools (keep to these; each returns structured JSON plus a short voice-friendly string field `speak` of at most 2 sentences)
1. analyze_message(text: str, channel: "sms"|"call"|"email"|"whatsapp"|"other" = "other", region: str = "IN")
   -> { verdict: "safe"|"suspicious"|"likely_scam", risk_score: 0-100, category: str, red_flags: [{code, evidence, explanation}], speak: str }
2. check_link(url: str)
   -> { verdict, risk_score, signals: [{code, detail}], normalized_domain: str, speak: str }   (static analysis only; NEVER fetch the URL)
3. open_case(title: str | None, region: str = "IN") -> { case_id, speak }
4. add_evidence(case_id: str, kind: "message"|"link"|"call_note"|"payment", content: str) -> { evidence_id, analysis (if applicable), speak }
5. get_case(case_id: str) -> full case with evidence and timeline
6. next_steps(case_id: str, lost_money: bool = false, payment_method: "upi"|"card"|"bank_transfer"|"crypto"|"gift_card"|"none" = "none")
   -> { urgency: "immediate"|"today"|"later", steps: [{order, action, why, official_channel}], speak }
7. generate_report(case_id: str) -> { markdown: str, speak }  (a complaint-ready summary the user can paste into an official portal)

# Rules and constraints
- Defensive security only. No offensive features, no scam-generation features.
- Never fetch or visit user-supplied URLs (SSRF/malware risk). Analyze them statically.
- Never store real personal data beyond the case text; add a "delete_case" internal function and mention data handling in README.
- Validate the Origin header on /mcp (DNS-rebinding protection per MCP spec) and bind to 127.0.0.1 locally.
- No secrets in git. Use .env and .env.example.
- Official contact data (helplines, portals) lives in data/regions.json and must carry a "verify_before_use" note in README. Do not invent phone numbers.
- Do not invent SDK/API methods. Read current official docs or installed package source when unsure.
- Every module gets tests. Every prompt ends with a runnable check.
- Always label the web UI as "Simulated Alexa+ experience" (not an official Alexa client).

# Repo layout
auralert/
  CONTEXT.md  README.md  LICENSE(MIT)  .env.example  Dockerfile  pyproject.toml
  src/auralert/{server.py, app.py, detection/, cases/, regions.py, agent/}
  data/{scam_patterns.json, regions.json, brands.json}
  web/{index.html, app.js, styles.css}
  tests/  scripts/  docs/{ARCHITECTURE.md, FRICTION-LOG.md, DEVPOST.md, DEMO-SCRIPT.md}