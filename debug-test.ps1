# GoPlus Security MCP Server - Debug Test Script
Write-Host "GoPlus Security MCP Server - Debug Test" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green

# Test 1: Server Status
Write-Host "`n1. Testing Server Status..." -ForegroundColor Yellow
try {
    $response = Invoke-RestMethod -Uri "http://localhost:8081/" -Method GET
    Write-Host "Server Status: $($response.message)" -ForegroundColor Green
    Write-Host "Status: $($response.status)" -ForegroundColor Green
} catch {
    Write-Host "Server Status Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 2: MCP Initialize
Write-Host "`n2. Testing MCP Initialize..." -ForegroundColor Yellow
$initBody = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"clientInfo":{"name":"debug-test-client","version":"1.0.0"}}}'

try {
    $response = Invoke-RestMethod -Uri "http://localhost:8081/mcp" -Method POST -ContentType "application/json" -Body $initBody
    Write-Host "MCP Initialize Success" -ForegroundColor Green
    Write-Host "Protocol Version: $($response.result.protocolVersion)" -ForegroundColor Green
    Write-Host "Server Name: $($response.result.serverInfo.name)" -ForegroundColor Green
} catch {
    Write-Host "MCP Initialize Error: $($_.Exception.Message)" -ForegroundColor Red
}

# Test 3: MCP Tools List
Write-Host "`n3. Testing MCP Tools List..." -ForegroundColor Yellow
$toolsBody = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

try {
    $response = Invoke-RestMethod -Uri "http://localhost:8081/mcp" -Method POST -ContentType "application/json" -Body $toolsBody
    Write-Host "MCP Tools List Success" -ForegroundColor Green
    Write-Host "Available Tools: $($response.result.tools.Count)" -ForegroundColor Green
    foreach ($tool in $response.result.tools) {
        Write-Host "- $($tool.name): $($tool.description)" -ForegroundColor Cyan
    }
} catch {
    Write-Host "MCP Tools List Error: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "`nDebug Test Complete!" -ForegroundColor Green
