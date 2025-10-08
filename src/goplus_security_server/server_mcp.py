"""
GoPlus Security MCP Server

A Model Context Protocol server that provides blockchain security analysis tools
using the GoPlus Security API.
"""

import requests
import asyncio
from typing import Dict, Any, Optional, Sequence
from mcp.server import Server
from mcp.server.models import InitializationOptions
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequest,
    CallToolResult,
    ListToolsRequest,
    ListToolsResult,
    Tool,
    TextContent,
    ImageContent,
    EmbeddedResource,
    LoggingLevel
)
import mcp.types as types


def create_server():
    """Create and configure the GoPlus Security MCP server."""
    
    server = Server("GoPlus Security")
    
    def _make_request(api_key: str, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a request to the GoPlus Security API."""
        base_url = "https://api.gopluslabs.io/api/v1/"
        timeout = 30
        
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

    @server.list_tools()
    async def handle_list_tools() -> list[Tool]:
        """List available tools."""
        return [
            Tool(
                name="rug_pull_detection",
                description="Detect potential rug pull risks for a token contract",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "chain_id": {
                            "type": "string",
                            "description": "Blockchain chain ID (e.g., '1' for Ethereum, '56' for BSC)"
                        },
                        "address": {
                            "type": "string", 
                            "description": "Token contract address to analyze"
                        }
                    },
                    "required": ["chain_id", "address"]
                }
            ),
            Tool(
                name="phishing_site_detection",
                description="Check if a website is a known phishing site",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "url": {
                            "type": "string",
                            "description": "Website URL to check"
                        }
                    },
                    "required": ["url"]
                }
            ),
            Tool(
                name="nft_security_analysis",
                description="Analyze NFT contract security",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "chain_id": {
                            "type": "string",
                            "description": "Blockchain chain ID"
                        },
                        "address": {
                            "type": "string",
                            "description": "NFT contract address to analyze"
                        }
                    },
                    "required": ["chain_id", "address"]
                }
            ),
            Tool(
                name="address_security_analysis",
                description="Analyze address security and reputation",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "address": {
                            "type": "string",
                            "description": "Blockchain address to analyze"
                        }
                    },
                    "required": ["address"]
                }
            )
        ]

    @server.call_tool()
    async def handle_call_tool(name: str, arguments: dict) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        """Handle tool calls."""
        
        # Get API key from session config (this would need to be implemented properly)
        # For now, using a demo key
        api_key = "demo-key"
        
        if name == "rug_pull_detection":
            chain_id = arguments.get("chain_id")
            address = arguments.get("address")
            
            if not chain_id or not address:
                return [types.TextContent(type="text", text="Error: chain_id and address are required")]
            
            result = _make_request(api_key, f"rugpull_detecting/{chain_id}", {"address": address})
            
            if "error" in result:
                return [types.TextContent(type="text", text=f"Error: {result['error']}")]
            
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
                
                return [types.TextContent(type="text", text=response)]
            else:
                return [types.TextContent(type="text", text=f"Analysis failed: {result.get('message', 'Unknown error')}")]

        elif name == "phishing_site_detection":
            url = arguments.get("url")
            
            if not url:
                return [types.TextContent(type="text", text="Error: url is required")]
            
            result = _make_request(api_key, "phishing_site_detecting", {"url": url})
            
            if "error" in result:
                return [types.TextContent(type="text", text=f"Error: {result['error']}")]
            
            if result.get("code") == 1:
                data = result.get("result", {})
                is_phishing = data.get("is_phishing", False)
                risk_level = data.get("risk_level", "Unknown")
                
                response = f"Phishing Site Analysis for {url}:\n"
                response += f"Is Phishing: {'Yes' if is_phishing else 'No'}\n"
                response += f"Risk Level: {risk_level}\n\n"
                
                if is_phishing:
                    response += "⚠️ This site appears to be a phishing site.\n"
                else:
                    response += "✅ This site appears to be safe.\n"
                
                return [types.TextContent(type="text", text=response)]
            else:
                return [types.TextContent(type="text", text=f"Analysis failed: {result.get('message', 'Unknown error')}")]

        elif name == "nft_security_analysis":
            chain_id = arguments.get("chain_id")
            address = arguments.get("address")
            
            if not chain_id or not address:
                return [types.TextContent(type="text", text="Error: chain_id and address are required")]
            
            result = _make_request(api_key, f"nft_security/{chain_id}", {"address": address})
            
            if "error" in result:
                return [types.TextContent(type="text", text=f"Error: {result['error']}")]
            
            if result.get("code") == 1:
                data = result.get("result", {})
                risk_level = data.get("risk_level", "Unknown")
                risk_items = data.get("risk_items", [])
                
                response = f"NFT Security Analysis for {address} on chain {chain_id}:\n"
                response += f"Risk Level: {risk_level}\n\n"
                
                if risk_items:
                    response += "Risk Items:\n"
                    for item in risk_items:
                        response += f"- {item.get('name', 'Unknown')}: {item.get('description', 'No description')}\n"
                else:
                    response += "No specific risk items detected.\n"
                
                return [types.TextContent(type="text", text=response)]
            else:
                return [types.TextContent(type="text", text=f"Analysis failed: {result.get('message', 'Unknown error')}")]

        elif name == "address_security_analysis":
            address = arguments.get("address")
            
            if not address:
                return [types.TextContent(type="text", text="Error: address is required")]
            
            result = _make_request(api_key, "address_security", {"address": address})
            
            if "error" in result:
                return [types.TextContent(type="text", text=f"Error: {result['error']}")]
            
            if result.get("code") == 1:
                data = result.get("result", {})
                risk_level = data.get("risk_level", "Unknown")
                risk_items = data.get("risk_items", [])
                
                response = f"Address Security Analysis for {address}:\n"
                response += f"Risk Level: {risk_level}\n\n"
                
                if risk_items:
                    response += "Risk Items:\n"
                    for item in risk_items:
                        response += f"- {item.get('name', 'Unknown')}: {item.get('description', 'No description')}\n"
                else:
                    response += "No security issues detected.\n"
                
                return [types.TextContent(type="text", text=response)]
            else:
                return [types.TextContent(type="text", text=f"Analysis failed: {result.get('message', 'Unknown error')}")]

        else:
            return [types.TextContent(type="text", text=f"Unknown tool: {name}")]

    return server
