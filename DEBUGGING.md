# 🔍 GoPlus Security MCP Server - Debugging Guide

## Status Server ✅

**Server Status**: Running di port 8081  
**MCP Protocol**: Fully functional  
**Tools Available**: 4 security analysis tools  
**Docker Container**: Active and healthy  

## 🛠️ Debugging Tools

### 1. PowerShell Debug Script
```powershell
# Jalankan debug test script
powershell -ExecutionPolicy Bypass -File .\debug-test.ps1
```

**Output yang diharapkan:**
```
GoPlus Security MCP Server - Debug Test
===============================================

1. Testing Server Status...
Server Status: GoPlus Security MCP Server
Status: running

2. Testing MCP Initialize...
MCP Initialize Success
Protocol Version: 2024-11-05
Server Name: GoPlus Security

3. Testing MCP Tools List...
MCP Tools List Success
Available Tools: 4
- rug_pull_detection: Detect potential rug pull risks for a token contract
- phishing_site_detection: Check if a website is a known phishing site
- nft_security_analysis: Analyze NFT contract security
- address_security_analysis: Analyze address security and reputation

Debug Test Complete!
```

### 2. MCP Inspector
```bash
# Install MCP Inspector
npm install -g @modelcontextprotocol/inspector

# Jalankan dengan HTTP transport
mcp-inspector --transport http --server-url http://localhost:8081/mcp --port 3002
```

**Browser akan terbuka di**: `http://localhost:3002`

### 3. Manual Testing dengan curl/PowerShell

#### Test Server Status
```powershell
Invoke-RestMethod -Uri "http://localhost:8081/" -Method GET
```

#### Test MCP Initialize
```powershell
$body = '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{"tools":{}},"clientInfo":{"name":"test-client","version":"1.0.0"}}}'
Invoke-RestMethod -Uri "http://localhost:8081/mcp" -Method POST -ContentType "application/json" -Body $body
```

#### Test Tools List
```powershell
$body = '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
Invoke-RestMethod -Uri "http://localhost:8081/mcp" -Method POST -ContentType "application/json" -Body $body
```

#### Test Tool Call
```powershell
$body = '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"rug_pull_detection","arguments":{"chain_id":"1","address":"0x6B175474E89094C44Da98b954EedeAC495271d0F","api_key":"demo-key"}}}'
Invoke-RestMethod -Uri "http://localhost:8081/mcp" -Method POST -ContentType "application/json" -Body $body
```

## 🐳 Docker Debugging

### Check Container Status
```bash
docker ps
```

### View Container Logs
```bash
docker logs goplus-test
```

### Restart Container
```bash
docker stop goplus-test
docker rm goplus-test
docker run -d -p 8081:8081 --name goplus-test goplus-security-mcp
```

### Rebuild Container
```bash
docker build -t goplus-security-mcp .
```

## 🔧 Common Issues & Solutions

### Issue 1: Port Already in Use
**Error**: `PORT IS IN USE at port 6277`  
**Solution**: 
```bash
# Kill existing processes
taskkill /f /im node.exe
# Or use different port
mcp-inspector --port 3002
```

### Issue 2: ENOENT Error
**Error**: `spawn http://localhost:8081/mcp ENOENT`  
**Solution**: Gunakan `--transport http` flag

### Issue 3: Server Not Responding
**Solution**:
1. Check container status: `docker ps`
2. Check logs: `docker logs goplus-test`
3. Restart container if needed

### Issue 4: MCP Protocol Errors
**Solution**:
1. Verify JSON format
2. Check required fields
3. Use debug script to test

## 📊 Expected Results

### Successful MCP Initialize Response
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "protocolVersion": "2024-11-05",
    "capabilities": {
      "tools": {}
    },
    "serverInfo": {
      "name": "GoPlus Security",
      "version": "0.1.0"
    }
  }
}
```

### Successful Tools List Response
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "tools": [
      {
        "name": "rug_pull_detection",
        "description": "Detect potential rug pull risks for a token contract",
        "inputSchema": {
          "type": "object",
          "properties": {
            "chain_id": {"type": "string", "description": "Blockchain chain ID"},
            "address": {"type": "string", "description": "Token contract address"},
            "api_key": {"type": "string", "description": "GoPlus Security API key"}
          },
          "required": ["chain_id", "address"]
        }
      }
      // ... other tools
    ]
  }
}
```

### Successful Tool Call Response
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Rug Pull Analysis for 0x6B175474E89094C44Da98b954EedeAC495271d0F on chain 1:\nRisk Level: Low\n\nNo specific risk items detected."
      }
    ]
  }
}
```

## 🚀 Next Steps

1. **Test dengan MCP Inspector**: Buka `http://localhost:3002`
2. **Test dengan API Key asli**: Ganti `demo-key` dengan API key GoPlus Security
3. **Deploy ke Smithery**: Push ke GitHub dan deploy via Smithery platform
4. **Integrate dengan AI Apps**: Gunakan server dengan Claude Desktop atau aplikasi AI lainnya

## 📝 Logs Location

- **Docker Logs**: `docker logs goplus-test`
- **MCP Inspector Logs**: Console di browser
- **Debug Script Output**: Terminal output

**Server GoPlus Security MCP siap untuk debugging dan testing!** 🎯
