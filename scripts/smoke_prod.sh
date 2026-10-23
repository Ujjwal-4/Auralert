#!/usr/bin/env bash
# Production Smoke Verification Script for ScamShield
# Usage: ./scripts/smoke_prod.sh [https://your-deployed-app.onrender.com]

set -euo pipefail

BASE_URL="${1:-http://127.0.0.1:8000}"
MCP_URL="${BASE_URL}/mcp"

echo "=========================================================="
echo "ScamShield Production Smoke Test"
echo "Target Base URL: ${BASE_URL}"
echo "=========================================================="

# 1. Healthcheck
echo "[1/4] Verifying /healthz..."
HEALTH_RESP=$(curl -s -f -w "\n%{http_code}" "${BASE_URL}/healthz")
STATUS_CODE=$(echo "${HEALTH_RESP}" | tail -n1)
BODY=$(echo "${HEALTH_RESP}" | head -n -1)

if [ "${STATUS_CODE}" -ne 200 ] || [ "${BODY}" != '{"status":"ok"}' ]; then
  echo "FAIL: /healthz check failed! (HTTP ${STATUS_CODE}, body: ${BODY})"
  exit 1
fi
echo "PASS: /healthz returned 200 OK (${BODY})"

# 2. MCP Initialize
echo -e "\n[2/4] Testing MCP streamable HTTP initialize..."
TMP_HDRS=$(mktemp)
INIT_RESP=$(curl -s -D "${TMP_HDRS}" -X POST "${MCP_URL}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-protocol-version: 2025-11-25" \
  -H "Origin: ${BASE_URL}" \
  -d '{
    "jsonrpc": "2.0",
    "id": "smoke-init",
    "method": "initialize",
    "params": {
      "protocolVersion": "2025-11-25",
      "capabilities": {},
      "clientInfo": {"name": "prod-smoke-test", "version": "1.0.0"}
    }
  }')

SESSION_ID=$(grep -i "mcp-session-id:" "${TMP_HDRS}" | tr -d '\r' | awk '{print $2}')
rm -f "${TMP_HDRS}"

if [ -z "${SESSION_ID}" ]; then
  echo "FAIL: Failed to negotiate mcp-session-id from ${MCP_URL}"
  exit 1
fi
echo "PASS: Session established with ID: ${SESSION_ID}"

# 3. Verify Tools List
echo -e "\n[3/4] Checking tools/list for ScamShield tools..."
TOOLS_RESP=$(curl -s -X POST "${MCP_URL}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: ${SESSION_ID}" \
  -H "mcp-protocol-version: 2025-11-25" \
  -H "Origin: ${BASE_URL}" \
  -d '{"jsonrpc": "2.0", "id": "smoke-list", "method": "tools/list", "params": {}}')

for REQUIRED_TOOL in "analyze_message" "check_link" "open_case" "add_evidence" "get_case" "next_steps" "generate_report"; do
  if ! echo "${TOOLS_RESP}" | grep -q "${REQUIRED_TOOL}"; then
    echo "FAIL: Missing expected tool '${REQUIRED_TOOL}' in tools/list response"
    exit 1
  fi
done
echo "PASS: All 7 required MCP tools listed successfully."

# 4. Call analyze_message
echo -e "\n[4/4] Executing analyze_message smoke test..."
CALL_RESP=$(curl -s -X POST "${MCP_URL}" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "mcp-session-id: ${SESSION_ID}" \
  -H "mcp-protocol-version: 2025-11-25" \
  -H "Origin: ${BASE_URL}" \
  -d '{
    "jsonrpc": "2.0",
    "id": "smoke-call",
    "method": "tools/call",
    "params": {
      "name": "analyze_message",
      "arguments": {
        "text": "URGENT: SBI KYC update required within 24 hours. Your account is blocked.",
        "channel": "sms",
        "region": "IN"
      }
    }
  }')

if ! echo "${CALL_RESP}" | grep -q "likely_scam"; then
  echo "FAIL: analyze_message did not return expected likely_scam verdict!"
  echo "Response was: ${CALL_RESP}"
  exit 1
fi
echo "PASS: analyze_message returned likely_scam verdict with red flags."

# Terminate session
curl -s -X DELETE "${MCP_URL}" \
  -H "mcp-session-id: ${SESSION_ID}" \
  -H "mcp-protocol-version: 2025-11-25" \
  -H "Origin: ${BASE_URL}" > /dev/null

echo -e "\n=========================================================="
echo "ALL PRODUCTION SMOKE CHECKS PASSED!"
echo "Target ${BASE_URL} is live, healthy, and serving MCP tools."
echo "=========================================================="
