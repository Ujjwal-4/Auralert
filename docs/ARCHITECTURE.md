# Architecture & Technical Deep-Dive: AURALERT for Alexa+

> **Build, Ship, Shape: Amazon Developer Hackathon 2026**  
> **Track:** Alexa+ (Self-Hosted Model Context Protocol Server & Agent Brain)  
> **Mini-Challenges:** AWS Builder (Amazon Bedrock) & Open Source (MIT)

---

## 1. Executive Architecture Overview

AURALERT is a **voice-first defensive cybersecurity system** designed to protect consumers and vulnerable individuals from social engineering, phishing, and financial fraud. It acts as an intelligent intermediary between a voice assistant (Amazon Alexa+) and a suite of defensive cybersecurity tools exposed via the **Model Context Protocol (MCP)** specification (2025-11-25) over **Streamable HTTP**.

```mermaid
flowchart TD
    subgraph ClientLayer ["Client & Interface Layer"]
        User(["👤 User (Voice or Text)"])
        WebUI["Simulated Alexa+ Console (web/)<br/>• Web Speech API (STT / TTS)<br/>• Transparent Tool Call Chips<br/>• Live Risk Gauge & Report Modal"]
    end

    subgraph AgentLayer ["Simulated Alexa+ Brain (/api/agent)"]
        AgentRouter{"Brain Router"}
        BedrockBrain["Amazon Bedrock Brain<br/>(Converse API: Claude Haiku-class)<br/>Dynamic Tool Calling"]
        FallbackRouter["Deterministic Fallback Router<br/>(Intent Extraction & Rule Flow)<br/>Always available"]
        SessionStore[("Ephemeral Session Store<br/>TTL Cache & Turn State")]
    end

    subgraph TransportLayer ["MCP Transport Layer (POST/GET/DELETE /mcp)"]
        StreamableHTTP["Streamable HTTP Transport<br/>• Spec 2025-11-25<br/>• Origin / DNS-Rebinding Protection<br/>• mcp-session-id Lifecycle"]
    end

    subgraph MCPLayer ["AURALERT MCPServer (src/auralert/server.py)"]
        T1["1. analyze_message"]
        T2["2. check_link"]
        T3["3. open_case"]
        T4["4. add_evidence"]
        T5["5. get_case"]
        T6["6. next_steps"]
        T7["7. generate_report"]
    end

    subgraph CoreLayer ["Deterministic Defensive Engines (src/auralert/)"]
        DetectionEngine["Detection Engine (Zero Network IO)<br/>• Levenshtein Typosquatting<br/>• Punycode & IP Host Detector<br/>• 10 Scam Category Regex Matchers<br/>• Hinglish & Benign Discrimination"]
        CaseService["Case Management (cases/service.py)<br/>• SQLite WAL Database<br/>• Speakable IDs ('shield-XXXX')<br/>• Entity Extractor & MD Generator"]
        RegionalDirectory["Regional Directory (regions.py)<br/>• India: 1930 / cybercrime.gov.in<br/>• US: FTC / IC3<br/>• UK: Report Fraud"]
    end

    User <--> WebUI
    WebUI <--> AgentRouter
    AgentRouter --> BedrockBrain
    AgentRouter --> FallbackRouter
    BedrockBrain <--> SessionStore
    FallbackRouter <--> SessionStore
    BedrockBrain -- "JSON-RPC 2.0" --> StreamableHTTP
    FallbackRouter -- "In-Process / HTTP" --> StreamableHTTP
    StreamableHTTP <--> MCPLayer
    MCPLayer --> DetectionEngine
    MCPLayer --> CaseService
    CaseService --> RegionalDirectory
```

---

## 2. MCP Protocol Implementation (Streamable HTTP)

### 2.1 Spec Adherence (2025-11-25)
AURALERT implements the official Model Context Protocol using the Python MCP SDK (`mcp>=2.3.0`). In accordance with the latest protocol updates:
- **Transport:** Streamable HTTP at endpoint `/mcp` mounted into a Starlette / FastAPI ASGI application.
- **Methods:**
  - `POST /mcp`: Handles bidirectional JSON-RPC 2.0 client requests (`tools/list`, `tools/call`, `initialize`, `notifications/initialized`).
  - `GET /mcp`: Provides streamable event responses and protocol session negotiation.
  - `DELETE /mcp`: Gracefully cleans up active protocol sessions.
- **Session Identification:** Returned via `mcp-session-id` HTTP response headers.

### 2.2 DNS-Rebinding and Origin Validation
Per the MCP security recommendations, `OriginValidationMiddleware` intercepts all requests to `/mcp`:
```python
# Allowed Origins: localhost, 127.0.0.1, deployed domain, or empty (same-origin curl / direct clients)
if origin and not is_allowed_origin(origin):
    return Response(content="Forbidden: Invalid Origin", status_code=403)
```
In addition, `TransportSecuritySettings` guards against Host header forgery (`allowed_hosts=["localhost", "127.0.0.1", "testserver"]`).

---

## 3. The 7 Defensive MCP Tools

All 7 tools strictly enforce defensive cybersecurity boundaries. Every tool returns structured JSON with a short, voice-friendly string field (`speak`) limited to **at most 2 calm, actionable sentences**.

| Tool | Inputs | Primary Output | Voice-Friendly `speak` Purpose |
|---|---|---|---|
| `analyze_message` | `text`, `channel`, `region` | `verdict`, `risk_score` (0-100), `category`, `red_flags` | Immediate risk evaluation and primary action ("Hang up", "Do not share OTP"). |
| `check_link` | `url` | `verdict`, `risk_score`, `signals`, `normalized_domain` | Explains domain impersonation, Punycode, or fake login target. |
| `open_case` | `title`, `region` | `case_id` (e.g. `shield-2841`), `status` | Announces case tracking number in speakable phonetic format. |
| `add_evidence` | `case_id`, `kind`, `content` | `evidence_id`, `analysis` | Confirms receipt of message, call note, or suspicious link. |
| `get_case` | `case_id` | `case_id`, `title`, `evidence[]`, `timeline[]` | Returns full incident dossier and state. |
| `next_steps` | `case_id`, `lost_money`, `payment_method` | `urgency` ("immediate"/"today"), `steps[]` | Delivers golden-hour response actions (bank freeze, 1930 portal). |
| `generate_report` | `case_id` | `markdown`, `speak` | Synthesizes an evidence summary ready for police/cybercrime portal. |

---

## 4. Deterministic Rule-Based Detection Engine

### 4.1 Strict Zero-Network I/O Guarantee (No URL fetching)
Most commercial security scanners suffer from Server-Side Request Forgery (SSRF) and malware detonation vulnerabilities when visiting attacker-controlled URLs. AURALERT's detection engine runs **100% locally and offline**. It never makes network calls or DNS lookups on input URLs:
- Verified by automated unit tests monkey-patching `socket.socket` to throw a hard error if any socket connection is attempted during detection.

### 4.2 Link Analysis Pipeline (`link_checker.py`)
1. **URL Normalization & Parsing:** Strips tracking params, normalizes schemes, handles subdomains, ports, and whitespace.
2. **IP Host Detection:** Flags raw IPv4/IPv6 addresses used in SMS phishing (e.g., `http://192.168.1.5/login`).
3. **Punycode / Homoglyph Detection:** Flags IDN homographs targeting Latin lookalikes (`xn--...`).
4. **Levenshtein Typosquatting:** Evaluates edit distance against a curated dataset of over 20 global and Indian financial/technology brands (`brands.json`):
   - Example: `sbi-kyc-verify-portal.top` matches `sbi` (State Bank of India) with suspicious TLD `.top`.
5. **Risky TLD Matching:** Flags high-abuse TLDs (`.top`, `.xyz`, `.club`, `.work`, `.cam`, `.live`, `.loan`).
6. **Credential Harvesting Paths:** Regex checks for `/login`, `/verify`, `/kyc`, `/netbanking`, `/wallet`.

### 4.3 Message Analysis Pipeline (`message_analyzer.py`)
1. **Benign Automated Notification Discrimination:** Automated bank SMS alerts that contain warnings like *"Do NOT share this OTP with anyone"* are recognized as legitimate security notices (`risk_score = 5`, `verdict = "safe"`), preventing annoying false alarms.
2. **10 Curated Threat Categories:**
   - `digital_arrest`: Fake CBI/police video call threats.
   - `upi_collect_request`: PIN-entry deception for "receiving" money.
   - `kyc_otp`: Fake account freeze threats demanding verification.
   - `courier_customs`: Fake FedEx/DHL drug seizure parcels.
   - `gift_card_crypto`: Demands for Apple/Amazon gift cards or Bitcoin ATM deposits.
   - `tech_support`: Fake Microsoft/AnyDesk popups.
   - `fake_job`: High-yield Telegram review/task scams.
   - `bank_impersonation`: Card security traps.
   - `prize_lottery`: KBC / Lucky draw upfront fee scams.
   - `romance_investment`: High-yield bogus trading schemes.
3. **Hinglish Tokenization:** Seamlessly identifies colloquial Hinglish threat markers (`"account band ho jayega"`, `"turant verify karo"`, `"paise bhejo"`, `"kisi ko mat batana"`).
4. **Stable Red Flag Codes:** Emits explainable structured codes (`URGENCY`, `THREAT_OF_ARREST`, `ACCOUNT_SUSPENSION_THREAT`, `OTP_REQUEST`, `UNUSUAL_PAYMENT_METHOD`, `REMOTE_ACCESS_REQUEST`, `SECRECY_REQUEST`).

---

## 5. Case State & Storage (`cases/db.py`)

- **Engine:** SQLite with Write-Ahead Logging (`WAL` mode) for robust concurrency and sub-millisecond writes.
- **Schema:**
  - `cases`: Holds `case_id`, `title`, `region`, `status`, `created_at`, `updated_at`.
  - `evidence`: Compound primary key `(case_id, id)` with foreign key cascade deletion (`ON DELETE CASCADE`).
  - `timeline`: Auditable event trail for all tool operations.
- **Speakable IDs:** Generated via phonetic format `shield-XXXX` (where `XXXX` is a 4-digit number), ensuring that Alexa can read the ID aloud clearly without confusion.
- **Abuse Prevention:** Hard caps enforced at `MAX_EVIDENCE_PER_CASE = 50` and `MAX_CONTENT_LENGTH = 20,000` chars.

---

## 6. Simulated Alexa+ Brain & Fallback Router (`agent/`)

### 6.1 Amazon Bedrock Converse API
When AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) are present, the agent invokes Amazon Bedrock using the Converse API with a Claude Haiku-class model (`anthropic.claude-3-haiku-20240307-v1:0`):
- MCP tool definitions are dynamically converted into Bedrock `toolSpec` JSON schemas via `mcp_to_bedrock_tools()`.
- Bedrock autonomously orchestrates tool calls, parses results, and synthesizes empathetic, voice-first responses.

### 6.2 Deterministic Rule-Based Fallback Router
Hackathon demos and production systems often fail when external cloud LLM APIs experience rate limits, latency spikes, or credential issues. AURALERT solves this with an **automatic zero-downtime fallback router**:
- If Bedrock fails, is disabled, or times out, the request is instantly routed to `handle_fallback_turn()`.
- Fallback router uses heuristic intent detection (URL presence, payment loss keywords, emergency triggers) to invoke MCP tools deterministically.
- Needs no cloud credentials or network, so the demo keeps working if Bedrock or OpenRouter are unavailable. The `brain` field of every response says which provider answered.

---

## 7. Interactive Sequence Diagrams

### 7.1 Urgent Payment Loss Sequence (Golden Hour Intervention)

```mermaid
sequenceDiagram
    autonumber
    actor Victim as 👤 Panicked User
    participant Alexa as 🎙️ Alexa+ Brain
    participant MCP as 🛡️ AURALERT MCP Server
    participant Detection as ⚙️ Detection Engine
    participant DB as 🗄️ SQLite Database
    participant Region as 📍 Regional Directory

    Victim->>Alexa: "I got panicked and sent Rs 15,000 via UPI to fraudster@okaxis!"
    Note over Alexa: Brain identifies urgent financial loss
    Alexa->>MCP: open_case(title="Financial Fraud Loss", region="IN")
    MCP->>DB: INSERT case ('shield-3829')
    DB-->>MCP: case_id: 'shield-3829'
    MCP-->>Alexa: { case_id: "shield-3829" }

    Alexa->>MCP: add_evidence(case_id="shield-3829", kind="payment", content="...")
    MCP->>DB: INSERT evidence
    DB-->>MCP: ok

    Alexa->>MCP: next_steps(case_id="shield-3829", lost_money=true, payment_method="upi")
    MCP->>Region: get_helplines("IN")
    Region-->>MCP: Helpline: 1930, Portal: cybercrime.gov.in
    MCP-->>Alexa: { urgency: "immediate", steps: [Call 1930, Dispute UPI ref], speak: "..." }

    Alexa->>MCP: generate_report(case_id="shield-3829")
    MCP->>DB: SELECT * FROM evidence WHERE case_id='shield-3829'
    DB-->>MCP: evidence records
    MCP-->>Alexa: { markdown: "# CYBERCRIME INCIDENT REPORT..." }

    Alexa-->>Victim: 🗣️ "Because money was involved, contact your bank and helpline 1930 immediately. I have opened case shield-3829 and generated your incident report."
```
