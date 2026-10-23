# Developer Friction Log: Building ScamShield for Alexa+

> **Build, Ship, Shape: Amazon Developer Hackathon 2026**  
> **Track:** Alexa+ (Self-Hosted MCP Server & Agent Brain)  
> **Author:** Solo Student Developer  
> **Date:** October 2026  
> *This friction log documents real developer experience challenges, undocumented SDK behaviors, and architectural workarounds encountered while building with MCP and Bedrock.*

---

## 1. Executive Summary

Building a voice-first cybersecurity agent adhering to the new **Model Context Protocol (MCP) Streamable HTTP specification (2025-11-25)** and integrating with **Amazon Bedrock Converse API** presented several real-world friction points. This document captures those issues, how we debugged them, and actionable recommendations for the MCP and AWS developer tooling teams.

---

## 2. Friction Entries

### Entry 1: MCP Python SDK 2.x Refactoring (`FastMCP` vs `MCPServer`)
- **Component:** `mcp>=2.3.0` Python SDK
- **Severity:** Medium (Developer Ergonomics & Documentation Lag)
- **Problem:**
  Online tutorials, early examples, and third-party guides reference `from mcp.server.fastmcp import FastMCP`. However, in the latest official Python SDK release (`mcp 2.3.0`), the server architecture was refactored: `FastMCP` was superseded by `MCPServer` in `mcp.server.mcpserver`. Furthermore, the mechanism to mount the server under an existing FastAPI/Starlette app shifted to `server.streamable_http_app(...)`.
- **Debugging & Resolution:**
  Inspected the installed wheel source code under `.venv/Lib/site-packages/mcp/server/` to identify the correct class signatures and ASGI factory methods. Updated imports to use `from mcp.server.mcpserver import MCPServer`.
- **Feedback for MCP Team:**
  Provide clear migration guides and deprecation warnings in the MCP SDK documentation when core entry points are refactored.

---

### Entry 2: DNS-Rebinding Protection & `Host: testserver` (HTTP 421 Misdirected Request)
- **Component:** `TransportSecuritySettings` in MCP Streamable HTTP App
- **Severity:** High (Blocked Automated Unit Testing)
- **Problem:**
  When writing in-process integration tests using Starlette's standard `TestClient(app)`, requests to `/mcp` consistently returned `421 Misdirected Request`. The client could not establish a session.
- **Root Cause:**
  The new MCP Streamable HTTP transport implements strict Host header validation to guard against DNS-rebinding attacks. Starlette's `TestClient` defaults to sending `Host: testserver`. Because `testserver` was not in the default allowed host list (`localhost`, `127.0.0.1`), the MCP security middleware rejected the connection.
- **Resolution:**
  Explicitly configured `allowed_hosts=["localhost", "127.0.0.1", "testserver"]` in the server's `TransportSecuritySettings`:
  ```python
  from mcp.server.transport_security import TransportSecuritySettings

  transport_settings = TransportSecuritySettings(
      allowed_hosts=["localhost", "127.0.0.1", "testserver"],
      allowed_origins=[r"https?://(localhost|127\.0\.0\.1)(:\d+)?$"],
  )
  ```
- **Feedback for MCP Team:**
  Add `testserver` to the default allowed hosts when running under test environments, or document this requirement in the testing guide.

---

### Entry 3: Starlette Lifespan & `StreamableHTTPSessionManager` Lifecycle
- **Component:** MCP Server Lifespan Integration
- **Severity:** Medium (Server Startup & Clean Shutdown)
- **Problem:**
  The MCP `streamable_http_app` manages long-lived client sessions via an internal `StreamableHTTPSessionManager`. When mounting the MCP sub-app into a parent FastAPI/Starlette application, failing to execute the sub-app's lifespan context causes session initialization to fail at runtime with `RuntimeError: Session manager not started`.
- **Resolution:**
  Implemented a unified async lifespan context in the parent Starlette app:
  ```python
  @asynccontextmanager
  async def app_lifespan(app: Starlette):
      init_db()
      async with mcp_starlette_app.router.lifespan_context(app):
          yield
  ```
- **Feedback for MCP Team:**
  Document the recommended composite lifespan pattern when mounting an MCP sub-app into larger FastAPI/Starlette microservices.

---

### Entry 4: Compound Primary Key Collision on SQLite Case Evidence
- **Component:** `cases/db.py` SQLite Schema
- **Severity:** Medium (State Corruption)
- **Problem:**
  Each case numbers its evidence sequentially (`ev-1`, `ev-2`, `ev-3`). When the table schema was initially defined with `id TEXT PRIMARY KEY`, creating a second case and adding its first evidence item threw an `IntegrityError: UNIQUE constraint failed: evidence.id`.
- **Resolution:**
  Updated the table definition to use a composite primary key `PRIMARY KEY (case_id, id)` and enabled foreign key cascade deletions (`FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE`).
- **Learning:**
  Human-readable sequential IDs require compound scoping when partitioned across parent entities.

---

### Entry 5: Loopback HTTP Latency vs Headless In-Process Fallback
- **Component:** `agent/mcp_client.py` and `agent/brain.py`
- **Severity:** Medium (Test Execution Speed)
- **Problem:**
  The agent brain is designed to invoke MCP tools over loopback HTTP (`http://127.0.0.1:8000/mcp`) so that it can be deployed independently of the MCP server. However, during automated test runs (`pytest`) where no external Uvicorn server is running on port 8000, standard HTTP connection attempts would hang for 5–10 seconds waiting for TCP connection timeouts.
- **Resolution:**
  Implemented a dual-mode client:
  1. An aggressive connection timeout (`httpx.Timeout(connect=0.15, read=5.0)`).
  2. A cached reachability check: if port 8000 is not listening, the agent instantly falls back to direct in-process tool dispatching.
  This reduced unit test execution time across the test suite from over 2 minutes to under 35 seconds.

---

### Entry 6: Amazon Bedrock Converse API ToolSpec Format Nuances
- **Component:** Amazon Bedrock Converse API Tool Calling
- **Severity:** Low (Schema Transformation)
- **Problem:**
  MCP tool definitions adhere to standard JSON Schema (`{"type": "object", "properties": {...}}`). Bedrock's Converse API expects a specific wrapped structure:
  ```json
  {
    "toolSpec": {
      "name": "analyze_message",
      "description": "...",
      "inputSchema": {
        "json": { "type": "object", "properties": {...} }
      }
    }
  }
  ```
  Passing raw MCP tool schemas directly caused Bedrock parameter validation errors.
- **Resolution:**
  Built a dedicated converter `mcp_to_bedrock_tools()` in `src/scamshield/agent/schemas.py` that strips internal FastMCP metadata and packages the input schema strictly under `inputSchema.json`.

---

### Entry 7: Voice Ergonomics vs Information Overload in Security Alerts
- **Component:** Voice Interface Design (Alexa+)
- **Severity:** Design Challenge
- **Problem:**
  Cybersecurity reports are inherently technical (domain names, Levenshtein distance, IP addresses, legal codes). If Alexa attempts to read all this information aloud, the user experiences cognitive overload and panic.
- **Resolution:**
  Enforced a strict **two-tier information architecture**:
  1. **Voice Tier (`speak` field):** Maximum of 2 short, calm sentences prioritizing immediate physical actions ("Hang up immediately", "Do not share OTP").
  2. **Screen / Visual Tier (`markdown` report & UI state):** Detailed forensic breakdown (red flag codes, evidence snippets, portal links) rendered on the visual console or mobile app.

---

## 3. Conclusion & Recommendations
The combination of MCP Streamable HTTP and Amazon Bedrock Converse API provides an extraordinarily powerful architecture for agentic applications. By documenting these 7 friction points and their resolutions, we hope to accelerate other developers building secure, voice-enabled agents on the Alexa+ platform.
