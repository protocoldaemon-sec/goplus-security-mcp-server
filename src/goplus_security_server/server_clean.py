"""
GoPlus Security MCP Server

A Model Context Protocol server that provides blockchain security analysis tools
using the GoPlus Security API.
"""

import requests
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from mcp.server.fastmcp import Context, FastMCP
from smithery.server import smithery


class ConfigSchema(BaseModel):
    """Configuration schema for the GoPlus Security MCP server."""
    api_key: str = Field(..., description="GoPlus Security API key for authentication")
    base_url: str = Field("https://api.gopluslabs.io/api/v1/", description="Base URL for GoPlus Security API")
    timeout: int = Field(30, description="Request timeout in seconds", ge=5, le=300)


@smithery.server(config_schema=ConfigSchema)
def create_server():
    """Create and configure the GoPlus Security MCP server."""
    
    server = FastMCP("GoPlus Security")
    
    def _make_request(ctx: Context, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a request to the GoPlus Security API."""
        # Get configuration from session
        config = ctx.session_config
        api_key = config.api_key
        base_url = config.base_url
        timeout = config.timeout
        
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

    @server.tool()
    def rug_pull_detection(chain_id: str, address: str, ctx: Context) -> str:
        """
        Detect potential rug pull risks for a token contract.
        
        Args:
            chain_id: Blockchain chain ID (e.g., "1" for Ethereum, "56" for BSC)
            address: Token contract address to analyze
        """
        result = _make_request(ctx, f"rugpull_detecting/{chain_id}", {"address": address})
        
        if "error" in result:
            return f"Error: {result['error']}"
        
        # Format the response for better readability
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

    @server.tool()
    def phishing_site_detection(url: str, ctx: Context) -> str:
        """
        Check if a website is a known phishing site.
        
        Args:
            url: Website URL to check
        """
        result = _make_request(ctx, "phishing_site_detecting", {"url": url})
        
        if "error" in result:
            return f"Error: {result['error']}"
        
        # Format the response
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
            
            return response
        else:
            return f"Analysis failed: {result.get('message', 'Unknown error')}"

    @server.tool()
    def nft_security_analysis(chain_id: str, address: str, ctx: Context) -> str:
        """
        Analyze NFT contract security.
        
        Args:
            chain_id: Blockchain chain ID
            address: NFT contract address to analyze
        """
        result = _make_request(ctx, f"nft_security/{chain_id}", {"address": address})
        
        if "error" in result:
            return f"Error: {result['error']}"
        
        # Format the response
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
            
            return response
        else:
            return f"Analysis failed: {result.get('message', 'Unknown error')}"

    @server.tool()
    def address_security_analysis(address: str, ctx: Context) -> str:
        """
        Analyze address security and reputation.
        
        Args:
            address: Blockchain address to analyze
        """
        result = _make_request(ctx, "address_security", {"address": address})
        
        if "error" in result:
            return f"Error: {result['error']}"
        
        # Format the response
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
            
            return response
        else:
            return f"Analysis failed: {result.get('message', 'Unknown error')}"

    @server.resource("api://goplus-documentation")
    def api_documentation() -> str:
        """GoPlus Security API documentation and usage examples."""
        return """
# GoPlus Security API Documentation

## Available Tools

### 1. Rug Pull Detection
- **Function**: `rug_pull_detection(chain_id, address)`
- **Purpose**: Detect potential rug pull risks for token contracts
- **Parameters**:
  - `chain_id`: Blockchain chain ID (e.g., "1" for Ethereum, "56" for BSC)
  - `address`: Token contract address to analyze

### 2. Phishing Site Detection
- **Function**: `phishing_site_detection(url)`
- **Purpose**: Check if a website is a known phishing site
- **Parameters**:
  - `url`: Website URL to check

### 3. NFT Security Analysis
- **Function**: `nft_security_analysis(chain_id, address)`
- **Purpose**: Analyze NFT contract security
- **Parameters**:
  - `chain_id`: Blockchain chain ID
  - `address`: NFT contract address to analyze

### 4. Address Security Analysis
- **Function**: `address_security_analysis(address)`
- **Purpose**: Analyze address security and reputation
- **Parameters**:
  - `address`: Blockchain address to analyze

## Supported Blockchains
- Ethereum (chain_id: "1")
- BSC (chain_id: "56")
- Polygon (chain_id: "137")
- Arbitrum (chain_id: "42161")
- Optimism (chain_id: "10")
- Avalanche (chain_id: "43114")
- Fantom (chain_id: "250")
- Heco (chain_id: "128")
- Klaytn (chain_id: "8217")
- Moonbeam (chain_id: "1284")
- Moonriver (chain_id: "1285")

## Getting API Key
Visit https://gopluslabs.io/ to get your GoPlus Security API key.
"""

    @server.resource("api://supported-chains")
    def supported_chains() -> str:
        """List of supported blockchain networks."""
        return """
# Supported Blockchain Networks

| Chain ID | Network Name | Symbol |
|----------|--------------|--------|
| 1 | Ethereum | ETH |
| 56 | Binance Smart Chain | BNB |
| 137 | Polygon | MATIC |
| 42161 | Arbitrum | ETH |
| 10 | Optimism | ETH |
| 43114 | Avalanche | AVAX |
| 250 | Fantom | FTM |
| 128 | Heco | HT |
| 8217 | Klaytn | KLAY |
| 1284 | Moonbeam | GLMR |
| 1285 | Moonriver | MOVR |
"""

    return server
