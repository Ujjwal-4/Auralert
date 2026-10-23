#!/usr/bin/env bash
# MCP Streamable HTTP Lifecycle Walkthrough (MCP spec 2025-11-25)
# Usage: ./scripts/mcp_lifecycle.sh [http://127.0.0.1:8000]

set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"
MCP_URL="${BASE_URL}/mcp"

echo "=========================================================="
echo "ScamShield MCP Streamable HTTP Lifecycle Walkthrough"
echo "Target: ${MCP_URL}"
echo "=========================================================="

# 0. Health check
echo -e "\n[0/5] Checking /healthz..."
curl -s -f "${BASE_URL}/healthz"
echo ""

# 1. Initialize
echo -e "\n[1/5] Step 1: initialize (protocolVersion: 2025-11-25)..."
INIT_HEADERS=$(mktemp)
INIT_BODY=$(mktemp)

curl -s -D "${INIT_HEADERS}" \
  -X POST "${MCP_URL}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-protocol-version: 2025-11-25" \
  -H "Origin: http://127.0.0.1:8000" \
  -d '{
    "jsonrpc": "2.0",
    "id": "init-1",
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-11-25",
      "capabilities": {},
      "clientInfo": {"name": "curl-walkthrough", "version": "1.0.0"}
    }
  }' > "${INIT_BODY}"

cat "${INIT_BODY}"
echo ""

SESSION_ID=$(grep -i "mcp-session-id:" "${INIT_HEADERS}" | tr -d '\r' | awk '{print $2}')
if [ -z "${SESSION_ID}" ]; then
  echo "Error: Failed to obtain mcp-session-id header."
  rm -f "${INIT_HEADERS}" "${INIT_BODY}"
  exit 1
fi
echo "Obtained mcp-session-id: ${SESSION_ID}"

# 2. Initialized Notification
echo -e "\n[2/5] Step 2: notifications/initialized..."
curl -s -i \
  -X POST "${MCP_URL}" \
  -H "Content-Type: application/json" \
  -H "mcp-session-id: ${SESSION_ID}" \
  -H "mcp-protocol-version: 2025-11-25" \
  -H "Origin: http://127.0.0.1:8000" \
  -d '{
    "jsonrpc": "2.0",
    "method": "notifications/initialized",
    "params": {}
  }' | head -n 10
echo ""

# 3. Tools List
echo -e "\n[3/5] Step 3: tools/list (retrieving all 7 ScamShield tools)..."
curl -s \
  -X POST "${MCP_URL}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: ${SESSION_ID}" \
  -H "mcp-protocol-version: 2025-11-25" \
  -H "Origin: http://127.0.0.1:8000" \
  -d '{
    "jsonrpc": "2.0",
    "id": "list-1",
    "method": "tools/list",
    "params": {}
  }'
echo ""

# 4. Tools Call (analyze_message stub)
echo -e "\n[4/5] Step 4: tools/call (calling analyze_message)..."
curl -s \
  -X POST "${MCP_URL}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: ${SESSION_ID}" \
  -H "mcp-protocol-version: 2025-11-25" \
  -H "Origin: http://127.0.0.1:8000" \
  -d '{
    "jsonrpc": "2.0",
    "id": "call-1",
    "method": "tools/call",
    "params": {
      "name": "analyze_message",
      "arguments": {
        "text": "Your SBI account is blocked today due to pending KYC. Update at once: http://sbi-kyc.top",
        "channel": "sms",
        "region": "IN"
      }
    }
  }'
echo ""

# 5. Clean termination
echo -e "\n[5/5] Step 5: DELETE /mcp (terminating session)..."
curl -s -i \
  -X DELETE "${MCP_URL}" \
  -H "mcp-session-id: ${SESSION_ID}" \
  -H "mcp-protocol-version: 2025-11-25" \
  -H "Origin: http://127.0.0.1:8000" | head -n 8

rm -f "${INIT_HEADERS}" "${INIT_BODY}"
echo -e "\nWalkthrough complete!"
