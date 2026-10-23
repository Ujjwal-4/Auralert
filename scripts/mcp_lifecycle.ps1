# PowerShell MCP Streamable HTTP Lifecycle Walkthrough
param(
    [string]$BaseUrl = "http://127.0.0.1:8000"
)

$McpUrl = "$BaseUrl/mcp"
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "ScamShield MCP Streamable HTTP Lifecycle Walkthrough" -ForegroundColor Cyan
Write-Host "Target: $McpUrl" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 0. Health check
Write-Host "`n[0/5] Checking /healthz..." -ForegroundColor Yellow
$healthz = Invoke-RestMethod -Uri "$BaseUrl/healthz" -Method Get
Write-Host "Response: $($healthz | ConvertTo-Json)"

# 1. Initialize
Write-Host "`n[1/5] Step 1: initialize (protocolVersion: 2025-11-25)..." -ForegroundColor Yellow
$initBody = @{
    jsonrpc = "2.0"
    id = "init-1"
    method = "initialize"
    params = @{
        protocolVersion = "2025-11-25"
        capabilities = @{}
        clientInfo = @{
            name = "powershell-walkthrough"
            version = "1.0.0"
        }
    }
} | ConvertTo-Json -Depth 5

$initResp = Invoke-WebRequest -Uri $McpUrl -Method Post -Body $initBody -ContentType "application/json" -Headers @{
    "Accept" = "application/json, text/event-stream"
    "mcp-protocol-version" = "2025-11-25"
    "Origin" = "http://127.0.0.1:8000"
}
$sessionId = $initResp.Headers["mcp-session-id"]
Write-Host "Obtained mcp-session-id: $sessionId" -ForegroundColor Green
Write-Host "Body: $($initResp.Content.Substring(0, [System.Math]::Min(140, $initResp.Content.Length)))"

$sessionHeaders = @{
    "Accept" = "application/json, text/event-stream"
    "mcp-session-id" = $sessionId
    "mcp-protocol-version" = "2025-11-25"
    "Origin" = "http://127.0.0.1:8000"
}

# 2. notifications/initialized
Write-Host "`n[2/5] Step 2: notifications/initialized..." -ForegroundColor Yellow
$notifBody = @{
    jsonrpc = "2.0"
    method = "notifications/initialized"
    params = @{}
} | ConvertTo-Json
$null = Invoke-WebRequest -Uri $McpUrl -Method Post -Body $notifBody -ContentType "application/json" -Headers $sessionHeaders
Write-Host "Notification sent."

# 3. tools/list
Write-Host "`n[3/5] Step 3: tools/list (retrieving all 7 tools)..." -ForegroundColor Yellow
$listBody = @{
    jsonrpc = "2.0"
    id = "list-1"
    method = "tools/list"
    params = @{}
} | ConvertTo-Json
$listResp = Invoke-WebRequest -Uri $McpUrl -Method Post -Body $listBody -ContentType "application/json" -Headers $sessionHeaders
Write-Host "Tools retrieved successfully."
Write-Host "Preview: $($listResp.Content.Substring(0, [System.Math]::Min(200, $listResp.Content.Length)))"

# 4. tools/call
Write-Host "`n[4/5] Step 4: tools/call (calling analyze_message)..." -ForegroundColor Yellow
$callBody = @{
    jsonrpc = "2.0"
    id = "call-1"
    method = "tools/call"
    params = @{
        name = "analyze_message"
        arguments = @{
            text = "Your SBI account is blocked today due to pending KYC. Update at once: http://sbi-kyc.top"
            channel = "sms"
            region = "IN"
        }
    }
} | ConvertTo-Json -Depth 5
$callResp = Invoke-WebRequest -Uri $McpUrl -Method Post -Body $callBody -ContentType "application/json" -Headers $sessionHeaders
Write-Host "Tool call response: $($callResp.Content)" -ForegroundColor Green

# 5. Session termination
Write-Host "`n[5/5] Step 5: DELETE /mcp (terminating session)..." -ForegroundColor Yellow
$delResp = Invoke-WebRequest -Uri $McpUrl -Method Delete -Headers $sessionHeaders
Write-Host "Session terminated with code: $($delResp.StatusCode)" -ForegroundColor Green
Write-Host "`nWalkthrough complete!" -ForegroundColor Cyan
