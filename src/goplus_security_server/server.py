"""
GoPlus Security MCP Server

A Model Context Protocol server that provides blockchain security analysis tools
using the GoPlus Security API.
"""

import requests
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from mcp.server.fastmcp import Context, FastMCP
from smithery.decorators import smithery


class ConfigSchema(BaseModel):
    """Configuration schema for GoPlus Security API."""
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


@smithery.server(config_schema=ConfigSchema)
def create_server():
    """Create and configure the GoPlus Security MCP server."""
    
    server = FastMCP("GoPlus Security")
    
    def _make_request(ctx: Context, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Make a request to the GoPlus Security API."""
        config = ctx.session_config
        
        url = f"{config.base_url.rstrip('/')}/{endpoint.lstrip('/')}"
        headers = {
            "accept": "*/*",
            "GOPLUS-API-KEY": config.api_key
        }
        
        try:
            response = requests.get(url, headers=headers, params=params, timeout=config.timeout)
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
            url: Website URL to check for phishing risks
        """
        result = _make_request(ctx, "phishing_site", {"url": url})
        
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

    @server.tool()
    def nft_security_analysis(chain_id: str, address: str, ctx: Context) -> str:
        """
        Analyze NFT contract security.
        
        Args:
            chain_id: Blockchain chain ID (e.g., "1" for Ethereum, "56" for BSC)
            address: NFT contract address to analyze
        """
        result = _make_request(ctx, f"nft_security/{chain_id}", {"address": address})
        
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

    @server.tool()
    def solana_token_security(ctx: Context) -> str:
        """
        Get Solana token security information.
        Note: This endpoint doesn't require specific parameters in the current API.
        """
        result = _make_request(ctx, "solana/token_security")
        
        if "error" in result:
            return f"Error: {result['error']}"
        
        if result.get("code") == 1:
            data = result.get("result", {})
            response = "Solana Token Security Information:\n\n"
            
            # Format the response based on available data
            for key, value in data.items():
                if isinstance(value, dict):
                    response += f"{key}:\n"
                    for sub_key, sub_value in value.items():
                        response += f"  {sub_key}: {sub_value}\n"
                else:
                    response += f"{key}: {value}\n"
                    
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
        result = _make_request(ctx, f"address_security/{address}")
        
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

    @server.tool()
    def token_security_analysis(chain_id: str, address: str, ctx: Context) -> str:
        """
        Comprehensive token security analysis.
        
        Args:
            chain_id: Blockchain chain ID (e.g., "1" for Ethereum, "56" for BSC)
            address: Token contract address to analyze
        """
        result = _make_request(ctx, f"token_security/{chain_id}", {"address": address})
        
        if "error" in result:
            return f"Error: {result['error']}"
        
        if result.get("code") == 1:
            data = result.get("result", {})
            risk_level = data.get("risk_level", "Unknown")
            risk_items = data.get("risk_items", [])
            
            response = f"Token Security Analysis for {address} on chain {chain_id}:\n"
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
    @server.resource("goplus://api-docs")
    def api_documentation() -> str:
        """GoPlus Security API documentation and usage examples."""
        return """
GoPlus Security API Documentation

Available Tools:
1. rug_pull_detection(chain_id, address) - Detect rug pull risks
2. phishing_site_detection(url) - Check for phishing sites
3. nft_security_analysis(chain_id, address) - Analyze NFT security
4. solana_token_security() - Get Solana token security info
5. address_security_analysis(address) - Analyze address security
6. token_security_analysis(chain_id, address) - Comprehensive token analysis

Supported Chains:
- Ethereum (chain_id: "1")
- BSC (chain_id: "56")
- Polygon (chain_id: "137")
- Arbitrum (chain_id: "42161")
- Optimism (chain_id: "10")
- Avalanche (chain_id: "43114")

Example Usage:
- Check a token: rug_pull_detection("1", "0x6B175474E89094C44Da98b954EedeAC495271d0F")
- Check a website: phishing_site_detection("https://example.com")
- Analyze an NFT: nft_security_analysis("1", "0x82f5ef9ddc3d231962ba57a9c2ebb307dc8d26c2")
        """

    @server.resource("goplus://supported-chains")
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

    return server
