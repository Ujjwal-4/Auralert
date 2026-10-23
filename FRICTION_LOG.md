# Developer Friction Log: Building AURALERT for Alexa+

> **Build, Ship, Shape: Amazon Developer Hackathon 2026**  
> **Track:** Alexa+ (Self-Hosted MCP Server & Agent Brain)  
> **Documentation Location:** The canonical, continuously updated document is located at [`docs/FRICTION-LOG.md`](docs/FRICTION-LOG.md).

---

Please see [**`docs/FRICTION-LOG.md`**](docs/FRICTION-LOG.md) for the complete 10-entry log covering:
1. **AWS CLI on Windows:** `PATH` environment variable omission & shell restart workaround.
2. **AWS Authentication & Security:** `NoCredentialsError`, critical warnings against root account CLI usage, and step-by-step least-privilege IAM Bedrock policy.
3. **Amazon Bedrock Model Access Gating:** Claude Haiku 4.5 access approval, paid commercial tier barriers, and our 100% offline deterministic heuristic fallback engine.
4. **MCP Python SDK 2.x Architecture:** `FastMCP` refactored to `MCPServer`.
5. **DNS-Rebinding Protection:** `Host: testserver` HTTP 421 resolution in Starlette TestClient.
6. **Starlette Async Lifespan:** `StreamableHTTPSessionManager` session lifecycle.
7. **SQLite Schema Scoping:** Compound primary key on case evidence.
8. **Loopback HTTP Latency vs Headless Fallback:** Sub-millisecond in-process tool dispatch for tests.
9. **Amazon Bedrock Converse API ToolSpec Schemas:** Converting standard MCP schemas to Bedrock format.
10. **Voice Interface Ergonomics:** Two-tier architecture (2-sentence calm spoken advice + deep forensic visual dossier).
