#!/usr/bin/env python3
"""
GoPlus Security MCP Server - Final Docker Entry Point
"""

import os
import sys
import requests
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from mcp.server.fastmcp import FastMCP
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn

# Configuration schema
class ConfigSchema(BaseModel):
    api_key: str = Field(..., description="GoPlus Security API key for authentication")
    base_url: str = Field(
        default="https://api.gopluslabs.io/api/v1/",
        description="Base URL for GoPlus Security API"
    )
    timeout: int = Field(
        default=30,
        description="Request timeout in seconds",
        ge=5,
        le=300
    )

# Create FastMCP server
mcp_server = FastMCP("GoPlus Security")

def _make_request(api_key: str, base_url: str, timeout: int, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Make a request to the GoPlus Security API."""
    # Use environment variable if api_key is demo-key
    if api_key == "demo-key":
        import os
        api_key = os.getenv("GOPLUS_API_KEY", "demo-key")
    
    url = f"{base_url.rstrip('/')}/{endpoint.lstrip('/')}"
    headers = {
        "accept": "*/*",
        "GOPLUS-API-KEY": api_key
    }
    
    try:
        response = requests.get(url, headers=headers, params=params, timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": f"API request failed: {str(e)}"}
    except Exception as e:
        return {"error": f"Unexpected error: {str(e)}"}

@mcp_server.tool()
def rug_pull_detection(chain_id: str, address: str, api_key: str = "demo-key") -> str:
    """
    Detect potential rug pull risks for a token contract.
    
    Args:
        chain_id: Blockchain chain ID (e.g., "1" for Ethereum, "56" for BSC)
        address: Token contract address to analyze
        api_key: GoPlus Security API key
    """
    result = _make_request(api_key, "https://api.gopluslabs.io/api/v1/", 30, f"rugpull_detecting/{chain_id}", {"address": address})
    
    if "error" in result:
        return f"Error: {result['error']}"
    
    if result.get("code") == 1:
        data = result.get("result", {})
        risk_level = data.get("risk_level", "Unknown")
        risk_items = data.get("risk_items", [])
        
        response = f"Rug Pull Analysis for {address} on chain {chain_id}:\n"
        response += f"Risk Level: {risk_level}\n\n"
        
        if risk_items:
            response += "Risk Items:\n"
            for item in risk_items:
                response += f"- {item.get('name', 'Unknown')}: {item.get('description', 'No description')}\n"
        else:
            response += "No specific risk items detected.\n"
            
        return response
    else:
        return f"Analysis failed: {result.get('message', 'Unknown error')}"

@mcp_server.tool()
def phishing_site_detection(url: str, api_key: str = "demo-key") -> str:
    """
    Check if a website is a known phishing site.
    
    Args:
        url: Website URL to check for phishing risks
        api_key: GoPlus Security API key
    """
    result = _make_request(api_key, "https://api.gopluslabs.io/api/v1/", 30, "phishing_site", {"url": url})
    
    if "error" in result:
        return f"Error: {result['error']}"
    
    if result.get("code") == 1:
        data = result.get("result", {})
        is_phishing = data.get("is_phishing", False)
        risk_level = data.get("risk_level", "Unknown")
        
        response = f"Phishing Site Analysis for {url}:\n"
        response += f"Is Phishing: {'Yes' if is_phishing else 'No'}\n"
        response += f"Risk Level: {risk_level}\n"
        
        if is_phishing:
            response += "\n⚠️ WARNING: This site has been identified as a potential phishing site!\n"
        else:
            response += "\n✅ This site appears to be safe.\n"
            
        return response
    else:
        return f"Analysis failed: {result.get('message', 'Unknown error')}"

@mcp_server.tool()
def nft_security_analysis(chain_id: str, address: str, api_key: str = "demo-key") -> str:
    """
    Analyze NFT contract security.
    
    Args:
        chain_id: Blockchain chain ID (e.g., "1" for Ethereum, "56" for BSC)
        address: NFT contract address to analyze
        api_key: GoPlus Security API key
    """
    result = _make_request(api_key, "https://api.gopluslabs.io/api/v1/", 30, f"nft_security/{chain_id}", {"address": address})
    
    if "error" in result:
        return f"Error: {result['error']}"
    
    if result.get("code") == 1:
        data = result.get("result", {})
        risk_level = data.get("risk_level", "Unknown")
        risk_items = data.get("risk_items", [])
        
        response = f"NFT Security Analysis for {address} on chain {chain_id}:\n"
        response += f"Risk Level: {risk_level}\n\n"
        
        if risk_items:
            response += "Security Issues:\n"
            for item in risk_items:
                response += f"- {item.get('name', 'Unknown')}: {item.get('description', 'No description')}\n"
        else:
            response += "No security issues detected.\n"
            
        return response
    else:
        return f"Analysis failed: {result.get('message', 'Unknown error')}"

@mcp_server.tool()
def address_security_analysis(address: str, api_key: str = "demo-key") -> str:
    """
    Analyze address security and reputation.
    
    Args:
        address: Blockchain address to analyze
        api_key: GoPlus Security API key
    """
    result = _make_request(api_key, "https://api.gopluslabs.io/api/v1/", 30, f"address_security/{address}")
    
    if "error" in result:
        return f"Error: {result['error']}"
    
    if result.get("code") == 1:
        data = result.get("result", {})
        risk_level = data.get("risk_level", "Unknown")
        risk_items = data.get("risk_items", [])
        
        response = f"Address Security Analysis for {address}:\n"
        response += f"Risk Level: {risk_level}\n\n"
        
        if risk_items:
            response += "Security Issues:\n"
            for item in risk_items:
                response += f"- {item.get('name', 'Unknown')}: {item.get('description', 'No description')}\n"
        else:
            response += "No security issues detected.\n"
            
        return response
    else:
        return f"Analysis failed: {result.get('message', 'Unknown error')}"

# Add resources for documentation
@mcp_server.resource("goplus://api-docs")
def api_documentation() -> str:
    """GoPlus Security API documentation and usage examples."""
    return """
GoPlus Security API Documentation

Available Tools:
1. rug_pull_detection(chain_id, address, api_key) - Detect rug pull risks
2. phishing_site_detection(url, api_key) - Check for phishing sites
3. nft_security_analysis(chain_id, address, api_key) - Analyze NFT security
4. address_security_analysis(address, api_key) - Analyze address security

Supported Chains:
- Ethereum (chain_id: "1")
- BSC (chain_id: "56")
- Polygon (chain_id: "137")
- Arbitrum (chain_id: "42161")
- Optimism (chain_id: "10")
- Avalanche (chain_id: "43114")

Example Usage:
- Check a token: rug_pull_detection("1", "0x6B175474E89094C44Da98b954EedeAC495271d0F", "your-api-key")
- Check a website: phishing_site_detection("https://example.com", "your-api-key")
- Analyze an NFT: nft_security_analysis("1", "0x82f5ef9ddc3d231962ba57a9c2ebb307dc8d26c2", "your-api-key")
    """

@mcp_server.resource("goplus://supported-chains")
def supported_chains() -> str:
    """List of supported blockchain networks."""
    return """
Supported Blockchain Networks:

Ethereum Mainnet: chain_id = "1"
Binance Smart Chain: chain_id = "56"
Polygon: chain_id = "137"
Arbitrum One: chain_id = "42161"
Optimism: chain_id = "10"
Avalanche C-Chain: chain_id = "43114"
Fantom: chain_id = "250"
Aurora: chain_id = "1313161554"
Cronos: chain_id = "25"
Gnosis: chain_id = "100"
Heco: chain_id = "128"
Klaytn: chain_id = "8217"
Moonbeam: chain_id = "1284"
Moonriver: chain_id = "1285"
    """

# Create FastAPI app
app = FastAPI(title="GoPlus Security MCP Server")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["mcp-session-id", "mcp-protocol-version"]
)

# Add MCP endpoint
@app.post("/mcp")
async def mcp_endpoint(request: Request):
    """Handle MCP protocol requests."""
    try:
        # Get the request body
        body = await request.body()
        
        # Parse JSON
        import json
        data = json.loads(body)
        
        # Handle MCP protocol
        if data.get("method") == "initialize":
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": data.get("id"),
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
            })
        elif data.get("method") == "tools/list":
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": data.get("id"),
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
                        },
                        {
                            "name": "phishing_site_detection",
                            "description": "Check if a website is a known phishing site",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "url": {"type": "string", "description": "Website URL to check"},
                                    "api_key": {"type": "string", "description": "GoPlus Security API key"}
                                },
                                "required": ["url"]
                            }
                        },
                        {
                            "name": "nft_security_analysis",
                            "description": "Analyze NFT contract security",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "chain_id": {"type": "string", "description": "Blockchain chain ID"},
                                    "address": {"type": "string", "description": "NFT contract address"},
                                    "api_key": {"type": "string", "description": "GoPlus Security API key"}
                                },
                                "required": ["chain_id", "address"]
                            }
                        },
                        {
                            "name": "address_security_analysis",
                            "description": "Analyze address security and reputation",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "address": {"type": "string", "description": "Blockchain address to analyze"},
                                    "api_key": {"type": "string", "description": "GoPlus Security API key"}
                                },
                                "required": ["address"]
                            }
                        }
                    ]
                }
            })
        elif data.get("method") == "tools/call":
            # Handle tool calls
            tool_name = data.get("params", {}).get("name")
            arguments = data.get("params", {}).get("arguments", {})
            
            if tool_name == "rug_pull_detection":
                result = rug_pull_detection(
                    arguments.get("chain_id"),
                    arguments.get("address"),
                    arguments.get("api_key", "demo-key")
                )
            elif tool_name == "phishing_site_detection":
                result = phishing_site_detection(
                    arguments.get("url"),
                    arguments.get("api_key", "demo-key")
                )
            elif tool_name == "nft_security_analysis":
                result = nft_security_analysis(
                    arguments.get("chain_id"),
                    arguments.get("address"),
                    arguments.get("api_key", "demo-key")
                )
            elif tool_name == "address_security_analysis":
                result = address_security_analysis(
                    arguments.get("address"),
                    arguments.get("api_key", "demo-key")
                )
            else:
                result = f"Unknown tool: {tool_name}"
            
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": data.get("id"),
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": result
                        }
                    ]
                }
            })
        else:
            return JSONResponse({
                "jsonrpc": "2.0",
                "id": data.get("id"),
                "error": {
                    "code": -32601,
                    "message": "Method not found"
                }
            })
    except Exception as e:
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": data.get("id", 1),
            "error": {
                "code": -32603,
                "message": f"Internal error: {str(e)}"
            }
        })

@app.get("/")
async def root():
    return {"message": "GoPlus Security MCP Server", "status": "running"}

@app.get("/health")
async def health():
    return {"status": "healthy"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8081))
    uvicorn.run(app, host="0.0.0.0", port=port)
