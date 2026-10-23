# Developer Friction Log: Building AURALERT for Alexa+

> **Build, Ship, Shape: Amazon Developer Hackathon 2026**  
> **Track:** Alexa+ (Self-Hosted MCP Server & Agent Brain)  
> **Author:** Solo Student Developer  
> **Date:** October 2026  
> *This friction log documents real developer experience challenges, undocumented SDK behaviors, security risks, and architectural workarounds encountered while building with the Model Context Protocol (MCP) and Amazon Bedrock.*

---

## 1. Executive Summary

Building a voice-first cybersecurity agent adhering to the new **Model Context Protocol (MCP) Streamable HTTP specification (2025-11-25)** and integrating with **Amazon Bedrock Converse API** presented several real-world developer experience challenges. 

These spanned:
1. **Local Tooling & Environment:** AWS CLI path recognition on Windows 11.
2. **Authentication & Cloud Security:** `NoCredentialsError`, accidental root account sign-in risks, and formulating a least-privilege IAM policy.
3. **Model Entitlement & Billing:** Claude Haiku 4.5 access gates on AWS accounts, requiring an offline deterministic heuristic fallback so the app works 100% out-of-the-box.
4. **Protocol & SDK Refactoring:** MCP Python SDK 2.x class refactoring (`MCPServer` vs `FastMCP`) and DNS-rebinding security protection (HTTP 421).
5. **Voice Interface Design:** Two-tier information architecture preventing cognitive overload during high-stress scam calls.

This document details each friction point, root cause, code/config workaround, and actionable feedback for the AWS and MCP product teams.

---

## 2. Friction Entries

### Entry 1: AWS CLI on Windows — `PATH` Environment Variable Omission (`aws` Not Recognized)
- **Component:** AWS CLI v2 Windows Installer (`AWSCLIV2.msi`) & PowerShell
- **Severity:** High (Developer Onboarding Roadblock)
- **Problem:**
  Immediately following standard installation via the official AWS CLI v2 Windows MSI installer, attempting to run `aws` in PowerShell or Command Prompt produced an error:
  ```powershell
  aws : The term 'aws' is not recognized as the name of a cmdlet, function, script file, or operable program.
  ```
- **Root Cause:**
  The installer placed binaries in `C:\Program Files\Amazon\AWSCLIV2\`. While the installer updated the system registry `PATH`, already-running terminal sessions did not inherit the refreshed environment, and in some Windows 11 environments the installer failed to broadcast `WM_SETTINGCHANGE` to existing explorer/shell instances.
- **Workaround & Resolution:**
  1. Ran the direct absolute binary path to verify installation:
     ```powershell
     & "C:\Program Files\Amazon\AWSCLIV2\aws.exe" --version
     ```
  2. Permanently appended the AWS CLI directory to User/System `PATH` via PowerShell:
     ```powershell
     [Environment]::SetEnvironmentVariable("Path", $env:Path + ";C:\Program Files\Amazon\AWSCLIV2\", [EnvironmentVariableTarget]::User)
     ```
  3. Restarted active shell and IDE sessions to reload the updated `PATH`.
- **Feedback for AWS Tooling Team:**
  The Windows MSI installer should explicitly alert users to restart terminal sessions upon completion or provide a one-click session path reload script.

---

### Entry 2: AWS Authentication & Security — `NoCredentialsError` and Dangerous Root Account Usage
- **Component:** AWS CLI Authentication, boto3, & IAM Security Practices
- **Severity:** Critical (Security Vulnerability & Onboarding Friction)
- **Problem:**
  Running commands like `aws bedrock list-inference-profiles` or starting `boto3.client("bedrock-runtime")` initially failed with:
  ```text
  botocore.exceptions.NoCredentialsError: Unable to locate credentials
  ```
  In an effort to authenticate quickly, running interactive setup or logging in via the AWS web console prompted sign-in as the **AWS Root User**.
- **Security Implications & Danger:**
  **Never use the AWS Root Account for CLI operations or application development.** Root access keys grant unrestricted, irrecoverable control over billing, account deletion, user management, and all cloud infrastructure. Storing root keys in `.aws/credentials` or risking accidental commit to GitHub is an extreme vulnerability.
- **Resolution: Least-Privilege IAM Bedrock Setup:**
  1. **Disallowed Root Keys:** Verified no root access keys were created or persisted in `.aws/credentials`.
  2. **Created Dedicated Developer IAM User:** Created an IAM user (e.g., `auralert-bedrock-dev`) with zero management or billing permissions.
  3. **Attached Scoped Least-Privilege Bedrock Policy:** Attached a minimal policy granting only model invocation and profile listing:
     ```json
     {
       "Version": "2012-10-17",
       "Statement": [
         {
           "Sid": "BedrockConverseInvokeOnly",
           "Effect": "Allow",
           "Action": [
             "bedrock:InvokeModel",
             "bedrock:InvokeModelWithResponseStream",
             "bedrock:ListInferenceProfiles"
           ],
           "Resource": "*"
         }
       ]
     }
     ```
  4. Configured the CLI profile specifically with these scoped credentials:
     ```powershell
     aws configure --profile auralert-dev
     ```
- **Feedback for AWS & Bedrock Team:**
  Add a prominent warning banner in the AWS Bedrock Console and CLI quickstart docs against root account usage. Provide an official 1-click CloudFormation / IAM template for a minimal "Bedrock Invoke Only" developer role.

---

### Entry 3: Amazon Bedrock Model Access Gate — Claude Haiku 4.5 Unauthorized & Cost Barrier
- **Component:** Amazon Bedrock Model Access & Billing Entitlements
- **Severity:** High (Runtime Dependency Failure & Cost Barrier)
- **Problem:**
  Attempting to invoke Anthropic Claude 3.5 / 4.5 Haiku via `boto3.client("bedrock-runtime").converse(...)` resulted in:
  ```text
  AccessDeniedException: You don't have access to the model with the specified model ID.
  ```
  In Amazon Bedrock, commercial foundation models like Anthropic Claude Haiku are **gated and paid**. Even with valid AWS credentials, each model requires navigating to the AWS Bedrock Console, submitting a use-case questionnaire, waiting for approval, and having active commercial billing enabled. For student developers, hackathon judges, or open-source contributors without pre-approved paid AWS accounts, the agent would fail completely on startup.
- **Architectural Workaround: Deterministic Heuristic Fallback Engine:**
  To guarantee that AURALERT runs **100% reliably out-of-the-box for any judge or evaluator without requiring an AWS account, credit card, or Bedrock approvals**, we engineered a dual-mode fallback architecture:
  1. **Dynamic Reachability Probe:** On startup and before each LLM turn, `agent_brain` checks if Bedrock credentials and model access are functional.
  2. **Seamless Fallback (`DeterministicFallbackEngine`):** If Bedrock returns `AccessDeniedException`, `NoCredentialsError`, or if `USE_BEDROCK=false`, the agent routes execution to our offline rule-based heuristic engine (`src/auralert/agent/fallback.py`).
  3. **Identical MCP Tool Integration:** The deterministic engine inspects caller queries, checks family safe words, detects coercion, triggers the exact same 17 MCP tools (`verify_sender`, `detect_coercion`, `scan_domain`, `get_emergency_guidance`, `create_case`), and formats structured Alexa+ spoken responses and incident reports.
  4. **Multi-Provider Flexibility:** We also added optional support for alternative inference backends (e.g., OpenRouter / Gemini) configurable via environment variables (`MODEL_PROVIDER`).
- **Feedback for AWS & Bedrock Team:**
  Provide hackathon-specific developer sandbox credits or automatic instant sandbox tier approval for registered Amazon Developer Hackathon accounts so developers are not blocked by commercial gating.

---

### Entry 4: MCP Python SDK 2.x Refactoring (`FastMCP` vs `MCPServer`)
- **Component:** `mcp>=2.3.0` Python SDK
- **Severity:** Medium (Developer Ergonomics & Documentation Lag)
- **Problem:**
  Online tutorials, early examples, and third-party guides reference `from mcp.server.fastmcp import FastMCP`. However, in the latest official Python SDK release (`mcp 2.3.0`), the server architecture was refactored: `FastMCP` was superseded by `MCPServer` in `mcp.server.mcpserver`. Furthermore, the mechanism to mount the server under an existing FastAPI/Starlette app shifted to `server.streamable_http_app(...)`.
- **Debugging & Resolution:**
  Inspected the installed wheel source code under `.venv/Lib/site-packages/mcp/server/` to identify the correct class signatures and ASGI factory methods. Updated imports to use `from mcp.server.mcpserver import MCPServer`.
- **Feedback for MCP Team:**
  Provide clear migration guides and deprecation warnings in the MCP SDK documentation when core entry points are refactored.

---

### Entry 5: DNS-Rebinding Protection & `Host: testserver` (HTTP 421 Misdirected Request)
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

### Entry 6: Starlette Lifespan & `StreamableHTTPSessionManager` Lifecycle
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

### Entry 7: Compound Primary Key Collision on SQLite Case Evidence
- **Component:** `cases/db.py` SQLite Schema
- **Severity:** Medium (State Corruption)
- **Problem:**
  Each case numbers its evidence sequentially (`ev-1`, `ev-2`, `ev-3`). When the table schema was initially defined with `id TEXT PRIMARY KEY`, creating a second case and adding its first evidence item threw an `IntegrityError: UNIQUE constraint failed: evidence.id`.
- **Resolution:**
  Updated the table definition to use a composite primary key `PRIMARY KEY (case_id, id)` and enabled foreign key cascade deletions (`FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE`).
- **Learning:**
  Human-readable sequential IDs require compound scoping when partitioned across parent entities.

---

### Entry 8: Loopback HTTP Latency vs Headless In-Process Fallback
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

### Entry 9: Amazon Bedrock Converse API ToolSpec Format Nuances
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
  Built a dedicated converter `mcp_to_bedrock_tools()` in `src/auralert/agent/schemas.py` that strips internal FastMCP metadata and packages the input schema strictly under `inputSchema.json`.

---

### Entry 10: Voice Ergonomics vs Information Overload in Security Alerts
- **Component:** Voice Interface Design (Alexa+)
- **Severity:** Design Challenge
- **Problem:**
  Cybersecurity reports are inherently technical (domain names, Levenshtein distance, IP addresses, legal codes). If Alexa attempts to read all this information aloud during an active scam call, the user experiences cognitive overload and panic.
- **Resolution:**
  Enforced a strict **two-tier information architecture**:
  1. **Voice Tier (`speak` field):** Maximum of 2 short, calm sentences prioritizing immediate physical actions ("Hang up immediately", "Do not share OTP").
  2. **Screen / Visual Tier (`markdown` report & UI state):** Detailed forensic breakdown (red flag codes, evidence snippets, portal links) rendered on the visual console or mobile app.

---

## 3. Recommended Least-Privilege AWS IAM Setup

To prevent future developers from using root credentials, use the following configuration:

### 1. Create a Scoped IAM Policy (`AuralertBedrockAccess.json`)
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BedrockInferenceOnly",
      "Effect": "Allow",
      "Action": [
        "bedrock:InvokeModel",
        "bedrock:InvokeModelWithResponseStream",
        "bedrock:ListInferenceProfiles"
      ],
      "Resource": "*"
    }
  ]
}
```

### 2. Configure CLI via Named Profile
```powershell
# Create user & attach policy in AWS Console, then run:
aws configure --profile auralert-dev
# AWS Access Key ID: <Your_IAM_User_Key>
# AWS Secret Access Key: <Your_IAM_User_Secret>
# Default region name: us-east-1
# Default output format: json
```

### 3. Run with Named Profile
```powershell
$env:AWS_PROFILE="auralert-dev"
python scripts/check_bedrock.py
```

---

## 4. Conclusion & Product Feedback Summary

| Product | Friction Point | What Helped | Recommendation for Amazon / MCP |
|---|---|---|---|
| **AWS CLI (Windows)** | Binary not on `PATH` after MSI installer | Executed full path, updated user `PATH` | Installer should refresh session PATH or prompt terminal restart |
| **AWS IAM** | `NoCredentials` led to accidental root sign-in | Created scoped IAM developer profile | Display prominent warning against root CLI access; offer 1-click Bedrock policy |
| **Amazon Bedrock** | Claude Haiku 4.5 gated behind paid review | Built deterministic heuristic fallback engine | Provide hackathon sandbox credits & automatic access for developer accounts |
| **MCP Python SDK** | `FastMCP` refactored to `MCPServer` in 2.x | Inspected package wheels | Publish migration guides for SDK architectural changes |
| **MCP Streamable HTTP** | HTTP 421 DNS-rebinding on `Host: testserver` | Added `testserver` to `allowed_hosts` | Include `testserver` in default testing environments |
| **Voice UX (Alexa+)** | Technical forensic overload | Split into 2-sentence voice tier + full screen tier | Alexa+ guidelines should emphasize calm, imperative triage for high-pressure scams |
