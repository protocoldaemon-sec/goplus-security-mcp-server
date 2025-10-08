"""
GoPlus Security MCP Server

A Model Context Protocol server that provides blockchain security analysis tools
using the GoPlus Security API.
"""

import requests
from typing import Dict, Any, Optional
from pydantic import BaseModel, Field
from mcp.server.fastmcp import Context, FastMCP


class ConfigSchema(BaseModel):
    """Configuration schema for the GoPlus Security MCP server."""
    api_key: str = Field(..., description="GoPlus Security API key for authentication")
    base_url: str = Field("https://api.gopluslabs.io/api/v1/", description="Base URL for GoPlus Security API")
    timeout: int = Field(30, description="Request timeout in seconds", ge=5, le=300)


def create_server():
    """Create and configure the GoPlus Security MCP server."""
    
    server = FastMCP("GoPlus Security")
    
    def _make_request(api_key: str, endpoint: str, params: Optional[Dict[str, Any]] = None, base_url: str = "https://api.gopluslabs.io/api/v1/", timeout: int = 30) -> Dict[str, Any]:
        """Make a request to the GoPlus Security API."""
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
    def rug_pull_detection(chain_id: str, address: str, api_key: str) -> str:
        """
        Detect potential rug pull risks for a token contract.
        
        Args:
            chain_id: Blockchain chain ID (e.g., "1" for Ethereum, "56" for BSC)
            address: Token contract address to analyze
            api_key: GoPlus Security API key
        """
        result = _make_request(api_key, f"rugpull_detecting/{chain_id}", {"address": address})
        
        if "error" in result:
            return f"Error: {result['error']}"
        
        # Format the response for better readability
        if result.get("code") == 1:
            data = result.get("result", {})
            risk_level = data.get("risk_level", "Unknown")
            risk_items = data.get("risk_items", [])
            
            response = f"🔍 Rug Pull Analysis for {address} on chain {chain_id}\n"
            response += "=" * 50 + "\n"
            response += f"Risk Level: {risk_level}\n\n"
            
            if risk_items:
                response += "Risk Items:\n"
                for item in risk_items:
                    response += f"• {item.get('name', 'Unknown')}: {item.get('description', 'No description')}\n"
            else:
                response += "✅ No specific risk items detected.\n"
            
            return response
        else:
            return f"Analysis failed: {result.get('message', 'Unknown error')}"

    @server.tool()
    def phishing_site_detection(url: str, api_key: str) -> str:
        """
        Check if a website is a known phishing site.
        
        Args:
            url: Website URL to check
            api_key: GoPlus Security API key
        """
        result = _make_request(api_key, "phishing_site", {"url": url})
        
        if "error" in result:
            return f"Error: {result['error']}"
        
        # Format the response
        if result.get("code") == 1:
            data = result.get("result", {})
            is_phishing = data.get("is_phishing", False)
            risk_level = data.get("risk_level", "Unknown")
            
            response = f"🔍 Phishing Site Analysis for {url}\n"
            response += "=" * 50 + "\n"
            response += f"Status: {'🚨 PHISHING SITE DETECTED' if is_phishing else '✅ Safe'}\n"
            response += f"Risk Level: {risk_level}\n"
            
            if is_phishing:
                response += "\n⚠️ This website has been identified as a phishing site.\n"
                response += "Do not enter any personal information or credentials.\n"
            
            return response
        else:
            return f"Analysis failed: {result.get('message', 'Unknown error')}"

    @server.tool()
    def nft_security_analysis(chain_id: str, address: str, api_key: str) -> str:
        """
        Analyze NFT contract security with detailed risk assessment.
        
        Args:
            chain_id: Blockchain chain ID
            address: NFT contract address to analyze
            api_key: GoPlus Security API key
        """
        result = _make_request(api_key, f"nft_security/{chain_id}", {"address": address})
        
        if "error" in result:
            return f"Error: {result['error']}"
        
        # Format the response with detailed NFT security information
        if result.get("code") == 1:
            data = result.get("result", {})
            
            response = f"🔍 NFT Security Analysis for {address} on chain {chain_id}\n"
            response += "=" * 60 + "\n\n"
            
            # Basic NFT Information
            response += "📋 Basic Information:\n"
            response += f"• Name: {data.get('nft_name', 'N/A')}\n"
            response += f"• Symbol: {data.get('nft_symbol', 'N/A')}\n"
            response += f"• Description: {data.get('nft_description', 'N/A')}\n"
            response += f"• ERC Standard: {data.get('nft_erc', 'N/A')}\n"
            response += f"• Creator: {data.get('creator_address', 'N/A')}\n"
            response += f"• Created Block: {data.get('create_block_number', 'N/A')}\n\n"
            
            # Social Links
            social_links = []
            if data.get('website_url'): social_links.append(f"🌐 Website: {data['website_url']}")
            if data.get('discord_url'): social_links.append(f"💬 Discord: {data['discord_url']}")
            if data.get('github_url'): social_links.append(f"🐙 GitHub: {data['github_url']}")
            if data.get('twitter_url'): social_links.append(f"🐦 Twitter: {data['twitter_url']}")
            if data.get('medium_url'): social_links.append(f"📝 Medium: {data['medium_url']}")
            if data.get('telegram_url'): social_links.append(f"📱 Telegram: {data['telegram_url']}")
            
            if social_links:
                response += "🔗 Social Links:\n"
                for link in social_links:
                    response += f"• {link}\n"
                response += "\n"
            
            # Trading Information
            response += "📊 Trading Information:\n"
            response += f"• Total Items: {data.get('nft_items', 'N/A')}\n"
            response += f"• Holders: {data.get('nft_owner_number', 'N/A')}\n"
            response += f"• 24h Average Price: {data.get('average_price_24h', 'N/A')}\n"
            response += f"• 24h Lowest Price: {data.get('lowest_price_24h', 'N/A')}\n"
            response += f"• 24h Sales: {data.get('sales_24h', 'N/A')}\n"
            response += f"• 24h Volume: {data.get('traded_volume_24h', 'N/A')}\n"
            response += f"• Total Volume: {data.get('total_volume', 'N/A')}\n"
            response += f"• Highest Price: {data.get('highest_price', 'N/A')}\n"
            response += f"• Verified: {'✅ Yes' if data.get('nft_verified') == '1' else '❌ No' if data.get('nft_verified') == '0' else '❓ Unknown'}\n\n"
            
            # Security Analysis
            response += "🛡️ Security Analysis:\n"
            
            # Trust and Verification
            if data.get('trust_list') == '1':
                response += "✅ Trust List: This NFT is on a famous and trustworthy list\n"
            elif data.get('trust_list') is None:
                response += "❓ Trust List: No information available\n"
            else:
                response += "❌ Trust List: Not on trusted list\n"
            
            # Malicious Behavior
            if data.get('malicious_nft_contract') == '1':
                response += "🚨 MALICIOUS: This NFT has performed malicious behaviors!\n"
            elif data.get('malicious_nft_contract') == '0':
                response += "✅ No malicious behavior detected\n"
            else:
                response += "❓ Malicious behavior: Unknown\n"
            
            # Open Source
            if data.get('nft_open_source') == '1':
                response += "✅ Open Source: Contract is open source\n"
            elif data.get('nft_open_source') == '0':
                response += "⚠️ Open Source: Contract is NOT open source (high risk)\n"
            else:
                response += "❓ Open Source: Unknown\n"
            
            # Proxy Contract
            if data.get('nft_proxy') == '1':
                response += "⚠️ Proxy Contract: Has proxy contract (potential risk)\n"
            elif data.get('nft_proxy') == '0':
                response += "✅ No Proxy: No proxy contract detected\n"
            else:
                response += "❓ Proxy Contract: Unknown\n"
            
            # Metadata
            if data.get('metadata_frozen') == '1':
                response += "✅ Metadata: Frozen (stored in IPFS/AR)\n"
            elif data.get('metadata_frozen') == '0':
                response += "⚠️ Metadata: Not frozen (centralized storage)\n"
            else:
                response += "❓ Metadata: Unknown\n"
            
            response += "\n" + "=" * 60 + "\n"
            response += "⚠️  Always do your own research before investing in NFTs!\n"
            
            return response
        else:
            return f"Analysis failed: {result.get('message', 'Unknown error')}"

    @server.tool()
    def address_security_analysis(address: str, api_key: str) -> str:
        """
        Analyze address security and reputation.
        
        Args:
            address: Blockchain address to analyze
            api_key: GoPlus Security API key
        """
        result = _make_request(api_key, "address_security", {"address": address})
        
        if "error" in result:
            return f"Error: {result['error']}"
        
        # Format the response
        if result.get("code") == 1:
            data = result.get("result", {})
            
            response = f"🔍 Address Security Analysis for {address}\n"
            response += "=" * 50 + "\n"
            
            # Basic information
            response += f"Address Type: {data.get('address_type', 'Unknown')}\n"
            response += f"Contract Type: {data.get('contract_type', 'Unknown')}\n"
            response += f"Risk Level: {data.get('risk_level', 'Unknown')}\n\n"
            
            # Security flags
            security_flags = data.get('security_flags', [])
            if security_flags:
                response += "Security Flags:\n"
                for flag in security_flags:
                    response += f"• {flag.get('name', 'Unknown')}: {flag.get('description', 'No description')}\n"
            else:
                response += "✅ No security flags detected.\n"
            
            return response
        else:
            return f"Analysis failed: {result.get('message', 'Unknown error')}"

    @server.tool()
    def token_security_analysis(chain_id: str, address: str, api_key: str) -> str:
        """
        Analyze token contract security with comprehensive risk assessment.
        
        Args:
            chain_id: Blockchain chain ID (e.g., "1" for Ethereum, "56" for BSC)
            address: Token contract address to analyze
            api_key: GoPlus Security API key
        """
        result = _make_request(api_key, f"token_security/{chain_id}", {"address": address})
        
        if "error" in result:
            return f"Error: {result['error']}"
        
        # Format the response with detailed token security information
        if result.get("code") == 1:
            data = result.get("result", {})
            
            response = f"🔍 Token Security Analysis for {address} on chain {chain_id}\n"
            response += "=" * 60 + "\n\n"
            
            # Basic Token Information
            response += "📋 Basic Information:\n"
            response += f"• Name: {data.get('token_name', 'N/A')}\n"
            response += f"• Symbol: {data.get('token_symbol', 'N/A')}\n"
            response += f"• Total Supply: {data.get('total_supply', 'N/A')}\n"
            response += f"• Holders: {data.get('holder_count', 'N/A')}\n"
            response += f"• Creator: {data.get('creator_address', 'N/A')}\n"
            response += f"• Creator Balance: {data.get('creator_balance', 'N/A')}\n"
            response += f"• Creator Percentage: {data.get('creator_percent', 'N/A')}\n\n"
            
            # Contract Security Analysis
            response += "🛡️ Contract Security Analysis:\n"
            
            # Open Source
            if data.get('is_open_source') == '1':
                response += "✅ Open Source: Contract is open source\n"
            elif data.get('is_open_source') == '0':
                response += "⚠️ Open Source: Contract is NOT open source (high risk)\n"
            else:
                response += "❓ Open Source: Unknown\n"
            
            # Proxy Contract
            if data.get('is_proxy') == '1':
                response += "⚠️ Proxy Contract: Has proxy contract (potential risk)\n"
            elif data.get('is_proxy') == '0':
                response += "✅ No Proxy: No proxy contract detected\n"
            else:
                response += "❓ Proxy Contract: Unknown\n"
            
            # Mint Function
            if data.get('is_mintable') == '1':
                response += "🚨 MINTABLE: Contract can mint new tokens (HIGH RISK)\n"
            elif data.get('is_mintable') == '0':
                response += "✅ No Mint: Cannot mint new tokens\n"
            else:
                response += "❓ Mint Function: Unknown\n"
            
            # Owner Information
            owner_address = data.get('owner_address')
            if owner_address:
                response += f"👤 Owner: {owner_address}\n"
                response += f"• Owner Balance: {data.get('owner_balance', 'N/A')}\n"
                response += f"• Owner Percentage: {data.get('owner_percent', 'N/A')}\n"
                
                # Take Back Ownership
                if data.get('can_take_back_ownership') == '1':
                    response += "🚨 OWNERSHIP RISK: Owner can reclaim ownership\n"
                elif data.get('can_take_back_ownership') == '0':
                    response += "✅ Ownership: Cannot reclaim ownership\n"
                
                # Owner Can Change Balance
                if data.get('owner_change_balance') == '1':
                    response += "🚨 BALANCE RISK: Owner can change token balances\n"
                elif data.get('owner_change_balance') == '0':
                    response += "✅ Balance: Owner cannot change balances\n"
            else:
                response += "👤 Owner: No owner or unknown\n"
            
            # Hidden Owner
            if data.get('hidden_owner') == '1':
                response += "🚨 HIDDEN OWNER: Contract has hidden owners (MALICIOUS)\n"
            elif data.get('hidden_owner') == '0':
                response += "✅ No Hidden Owner: No hidden ownership detected\n"
            else:
                response += "❓ Hidden Owner: Unknown\n"
            
            # Self-Destruct
            if data.get('selfdestruct') == '1':
                response += "🚨 SELF-DESTRUCT: Contract can self-destruct\n"
            elif data.get('selfdestruct') == '0':
                response += "✅ No Self-Destruct: Cannot self-destruct\n"
            else:
                response += "❓ Self-Destruct: Unknown\n"
            
            # External Call
            if data.get('external_call') == '1':
                response += "⚠️ External Call: Can call external contracts\n"
            elif data.get('external_call') == '0':
                response += "✅ No External Call: Cannot call external contracts\n"
            else:
                response += "❓ External Call: Unknown\n"
            
            # Gas Abuse
            if data.get('gas_abuse') == '1':
                response += "🚨 GAS ABUSE: Using user's gas to mint other assets\n"
            else:
                response += "✅ No Gas Abuse: No evidence of gas abuse\n"
            
            response += "\n"
            
            # Trading Security Analysis
            response += "📊 Trading Security Analysis:\n"
            
            # DEX Trading
            if data.get('is_in_dex') == '1':
                response += "✅ DEX Trading: Can be traded on DEX\n"
                
                # Buy/Sell/Transfer Tax
                buy_tax = data.get('buy_tax', '')
                sell_tax = data.get('sell_tax', '')
                transfer_tax = data.get('transfer_tax', '')
                
                if buy_tax:
                    if buy_tax == '1':
                        response += f"🚨 Buy Tax: 100% (cannot buy)\n"
                    else:
                        response += f"⚠️ Buy Tax: {float(buy_tax)*100:.1f}%\n"
                
                if sell_tax:
                    if sell_tax == '1':
                        response += f"🚨 Sell Tax: 100% (cannot sell)\n"
                    else:
                        response += f"⚠️ Sell Tax: {float(sell_tax)*100:.1f}%\n"
                
                if transfer_tax:
                    if transfer_tax == '1':
                        response += f"🚨 Transfer Tax: 100% (cannot transfer)\n"
                    else:
                        response += f"⚠️ Transfer Tax: {float(transfer_tax)*100:.1f}%\n"
                
                # Trading Restrictions
                if data.get('cannot_buy') == '1':
                    response += "🚨 Cannot Buy: Token cannot be purchased\n"
                if data.get('cannot_sell_all') == '1':
                    response += "🚨 Cannot Sell All: Cannot sell all tokens at once\n"
                
                # Modifiable Tax
                if data.get('slippage_modifiable') == '1':
                    response += "🚨 Modifiable Tax: Trading tax can be changed by owner\n"
                elif data.get('slippage_modifiable') == '0':
                    response += "✅ Fixed Tax: Trading tax cannot be modified\n"
                
                # Honeypot
                if data.get('is_honeypot') == '1':
                    response += "🚨 HONEYPOT: Token is a honeypot (SCAM)\n"
                elif data.get('is_honeypot') == '0':
                    response += "✅ No Honeypot: Not a honeypot\n"
                
                # Pausable Transfer
                if data.get('transfer_pausable') == '1':
                    response += "🚨 Pausable Transfer: Trading can be paused by owner\n"
                elif data.get('transfer_pausable') == '0':
                    response += "✅ No Pause: Trading cannot be paused\n"
                
                # Blacklist/Whitelist
                if data.get('is_blacklisted') == '1':
                    response += "🚨 Blacklist: Has blacklist function\n"
                elif data.get('is_blacklisted') == '0':
                    response += "✅ No Blacklist: No blacklist function\n"
                
                if data.get('is_whitelisted') == '1':
                    response += "⚠️ Whitelist: Has whitelist function\n"
                elif data.get('is_whitelisted') == '0':
                    response += "✅ No Whitelist: No whitelist function\n"
                
                # Anti-Whale
                if data.get('is_anti_whale') == '1':
                    response += "⚠️ Anti-Whale: Has transaction/position limits\n"
                    if data.get('anti_whale_modifiable') == '1':
                        response += "🚨 Modifiable Anti-Whale: Limits can be changed\n"
                elif data.get('is_anti_whale') == '0':
                    response += "✅ No Anti-Whale: No transaction limits\n"
                
                # Trading Cooldown
                if data.get('trading_cooldown') == '1':
                    response += "⚠️ Trading Cooldown: Has time restrictions between trades\n"
                
                # Personal Slippage
                if data.get('personal_slippage_modifiable') == '1':
                    response += "🚨 Personal Tax: Owner can set different tax for each address\n"
                
                # DEX Information
                dex_info = data.get('dex', [])
                if dex_info:
                    response += "\n📈 DEX Information:\n"
                    for dex in dex_info:
                        response += f"• {dex.get('name', 'Unknown')} ({dex.get('liquidity_type', 'Unknown')})\n"
                        response += f"  - Liquidity: ${dex.get('liquidity', 'N/A')}\n"
                        response += f"  - Pair: {dex.get('pair', 'N/A')}\n"
            else:
                response += "❌ DEX Trading: Cannot be traded on DEX\n"
            
            response += "\n"
            
            # Top Holders Information
            holders = data.get('holders', [])
            if holders:
                response += "👥 Top 10 Holders:\n"
                for i, holder in enumerate(holders[:5], 1):  # Show top 5
                    response += f"{i}. {holder.get('address', 'N/A')}\n"
                    response += f"   Balance: {holder.get('balance', 'N/A')} ({holder.get('percent', 'N/A')}%)\n"
                    if holder.get('is_locked') == '1':
                        response += f"   🔒 Locked: Yes\n"
                    if holder.get('tag'):
                        response += f"   Tag: {holder.get('tag')}\n"
                if len(holders) > 5:
                    response += f"   ... and {len(holders) - 5} more holders\n"
                response += "\n"
            
            # LP Information
            if data.get('is_in_dex') == '1':
                response += "💧 Liquidity Pool Information:\n"
                response += f"• LP Holders: {data.get('lp_holder_count', 'N/A')}\n"
                response += f"• LP Total Supply: {data.get('lp_total_supply', 'N/A')}\n"
                
                lp_holders = data.get('lp_holders', [])
                if lp_holders:
                    response += "• Top LP Holders:\n"
                    for i, holder in enumerate(lp_holders[:3], 1):  # Show top 3
                        response += f"  {i}. {holder.get('address', 'N/A')}\n"
                        response += f"     Balance: {holder.get('balance', 'N/A')} ({holder.get('percent', 'N/A')}%)\n"
                        if holder.get('is_locked') == '1':
                            response += f"     🔒 Locked: Yes\n"
                response += "\n"
            
            # Trust and Risk Assessment
            response += "🎯 Trust and Risk Assessment:\n"
            
            # Trust List
            if data.get('trust_list') == '1':
                response += "✅ Trust List: This token is on a famous and trustworthy list\n"
            else:
                response += "❓ Trust List: Not on trusted list or unknown\n"
            
            # Airdrop Scam
            if data.get('is_airdrop_scam') == '1':
                response += "🚨 AIRDROP SCAM: This token is an airdrop scam\n"
            elif data.get('is_airdrop_scam') == '0':
                response += "✅ No Airdrop Scam: Not detected as airdrop scam\n"
            else:
                response += "❓ Airdrop Scam: Unknown\n"
            
            # Fake Token
            fake_token = data.get('fake_token')
            if fake_token and fake_token.get('value') == 1:
                response += f"🚨 FAKE TOKEN: This is a counterfeit of mainstream asset\n"
                response += f"   Real Token: {fake_token.get('true_token_address', 'N/A')}\n"
            else:
                response += "✅ Authentic: Not detected as fake token\n"
            
            # CEX Listing
            cex_info = data.get('is_in_cex')
            if cex_info and cex_info.get('listed') == '1':
                response += "✅ CEX Listed: Listed on major centralized exchanges\n"
                cex_list = cex_info.get('cex_list', [])
                if cex_list:
                    response += f"   Exchanges: {', '.join(cex_list)}\n"
            else:
                response += "❓ CEX Listing: Not listed on major CEX or unknown\n"
            
            # Launchpad Token
            launchpad = data.get('launchpad_token')
            if launchpad and launchpad.get('is_launchpad_token') == '1':
                response += f"✅ Launchpad: Deployed through trusted launchpad\n"
                response += f"   Launchpad: {launchpad.get('launchpad_name', 'N/A')}\n"
            else:
                response += "❓ Launchpad: Not deployed through known launchpad\n"
            
            # Other Risks and Notes
            other_risks = data.get('other_potential_risks')
            if other_risks:
                response += f"\n⚠️ Other Potential Risks:\n{other_risks}\n"
            
            note = data.get('note')
            if note:
                response += f"\n📝 Additional Notes:\n{note}\n"
            
            response += "\n" + "=" * 60 + "\n"
            response += "⚠️  Always do your own research before investing in tokens!\n"
            response += "🔍 This analysis is based on GoPlus Security API data.\n"
            
            return response
        else:
            return f"Analysis failed: {result.get('message', 'Unknown error')}"

    @server.tool()
    def solana_token_security_analysis(address: str, api_key: str) -> str:
        """
        Analyze Solana token security with comprehensive risk assessment.
        
        Args:
            address: Solana token address to analyze
            api_key: GoPlus Security API key
        """
        result = _make_request(api_key, "solana/token_security", {"address": address})
        
        if "error" in result:
            return f"Error: {result['error']}"
        
        # Format the response with detailed Solana token security information
        if result.get("code") == 1:
            data = result.get("result", {})
            
            response = f"🔍 Solana Token Security Analysis for {address}\n"
            response += "=" * 60 + "\n\n"
            
            # Basic Token Information
            response += "📋 Basic Information:\n"
            response += f"• Name: {data.get('token_name', 'N/A')}\n"
            response += f"• Symbol: {data.get('token_symbol', 'N/A')}\n"
            response += f"• Total Supply: {data.get('total_supply', 'N/A')}\n"
            response += f"• Holders: {data.get('holder_count', 'N/A')}\n"
            response += f"• Creator: {data.get('creator_address', 'N/A')}\n"
            response += f"• Creator Balance: {data.get('creator_balance', 'N/A')}\n"
            response += f"• Creator Percentage: {data.get('creator_percent', 'N/A')}\n\n"
            
            # Contract Security Analysis
            response += "🛡️ Contract Security Analysis:\n"
            
            # Open Source
            if data.get('is_open_source') == '1':
                response += "✅ Open Source: Contract is open source\n"
            elif data.get('is_open_source') == '0':
                response += "⚠️ Open Source: Contract is NOT open source (high risk)\n"
            else:
                response += "❓ Open Source: Unknown\n"
            
            # Proxy Contract
            if data.get('is_proxy') == '1':
                response += "⚠️ Proxy Contract: Has proxy contract (potential risk)\n"
            elif data.get('is_proxy') == '0':
                response += "✅ No Proxy: No proxy contract detected\n"
            else:
                response += "❓ Proxy Contract: Unknown\n"
            
            # Mint Function
            if data.get('is_mintable') == '1':
                response += "🚨 MINTABLE: Contract can mint new tokens (HIGH RISK)\n"
            elif data.get('is_mintable') == '0':
                response += "✅ No Mint: Cannot mint new tokens\n"
            else:
                response += "❓ Mint Function: Unknown\n"
            
            # Owner Information
            owner_address = data.get('owner_address')
            if owner_address:
                response += f"👤 Owner: {owner_address}\n"
                response += f"• Owner Balance: {data.get('owner_balance', 'N/A')}\n"
                response += f"• Owner Percentage: {data.get('owner_percent', 'N/A')}\n"
                
                # Take Back Ownership
                if data.get('can_take_back_ownership') == '1':
                    response += "🚨 OWNERSHIP RISK: Owner can reclaim ownership\n"
                elif data.get('can_take_back_ownership') == '0':
                    response += "✅ Ownership: Cannot reclaim ownership\n"
                
                # Owner Can Change Balance
                if data.get('owner_change_balance') == '1':
                    response += "🚨 BALANCE RISK: Owner can change token balances\n"
                elif data.get('owner_change_balance') == '0':
                    response += "✅ Balance: Owner cannot change balances\n"
            else:
                response += "👤 Owner: No owner or unknown\n"
            
            # Hidden Owner
            if data.get('hidden_owner') == '1':
                response += "🚨 HIDDEN OWNER: Contract has hidden owners (MALICIOUS)\n"
            elif data.get('hidden_owner') == '0':
                response += "✅ No Hidden Owner: No hidden ownership detected\n"
            else:
                response += "❓ Hidden Owner: Unknown\n"
            
            # Self-Destruct
            if data.get('selfdestruct') == '1':
                response += "🚨 SELF-DESTRUCT: Contract can self-destruct\n"
            elif data.get('selfdestruct') == '0':
                response += "✅ No Self-Destruct: Cannot self-destruct\n"
            else:
                response += "❓ Self-Destruct: Unknown\n"
            
            # External Call
            if data.get('external_call') == '1':
                response += "⚠️ External Call: Can call external contracts\n"
            elif data.get('external_call') == '0':
                response += "✅ No External Call: Cannot call external contracts\n"
            else:
                response += "❓ External Call: Unknown\n"
            
            # Gas Abuse
            if data.get('gas_abuse') == '1':
                response += "🚨 GAS ABUSE: Using user's gas to mint other assets\n"
            else:
                response += "✅ No Gas Abuse: No evidence of gas abuse\n"
            
            response += "\n"
            
            # Trading Security Analysis
            response += "📊 Trading Security Analysis:\n"
            
            # DEX Trading
            if data.get('is_in_dex') == '1':
                response += "✅ DEX Trading: Can be traded on DEX\n"
                
                # Buy/Sell/Transfer Tax
                buy_tax = data.get('buy_tax', '')
                sell_tax = data.get('sell_tax', '')
                transfer_tax = data.get('transfer_tax', '')
                
                if buy_tax:
                    if buy_tax == '1':
                        response += f"🚨 Buy Tax: 100% (cannot buy)\n"
                    else:
                        response += f"⚠️ Buy Tax: {float(buy_tax)*100:.1f}%\n"
                
                if sell_tax:
                    if sell_tax == '1':
                        response += f"🚨 Sell Tax: 100% (cannot sell)\n"
                    else:
                        response += f"⚠️ Sell Tax: {float(sell_tax)*100:.1f}%\n"
                
                if transfer_tax:
                    if transfer_tax == '1':
                        response += f"🚨 Transfer Tax: 100% (cannot transfer)\n"
                    else:
                        response += f"⚠️ Transfer Tax: {float(transfer_tax)*100:.1f}%\n"
                
                # Trading Restrictions
                if data.get('cannot_buy') == '1':
                    response += "🚨 Cannot Buy: Token cannot be purchased\n"
                if data.get('cannot_sell_all') == '1':
                    response += "🚨 Cannot Sell All: Cannot sell all tokens at once\n"
                
                # Modifiable Tax
                if data.get('slippage_modifiable') == '1':
                    response += "🚨 Modifiable Tax: Trading tax can be changed by owner\n"
                elif data.get('slippage_modifiable') == '0':
                    response += "✅ Fixed Tax: Trading tax cannot be modified\n"
                
                # Honeypot
                if data.get('is_honeypot') == '1':
                    response += "🚨 HONEYPOT: Token is a honeypot (SCAM)\n"
                elif data.get('is_honeypot') == '0':
                    response += "✅ No Honeypot: Not a honeypot\n"
                
                # Pausable Transfer
                if data.get('transfer_pausable') == '1':
                    response += "🚨 Pausable Transfer: Trading can be paused by owner\n"
                elif data.get('transfer_pausable') == '0':
                    response += "✅ No Pause: Trading cannot be paused\n"
                
                # Blacklist/Whitelist
                if data.get('is_blacklisted') == '1':
                    response += "🚨 Blacklist: Has blacklist function\n"
                elif data.get('is_blacklisted') == '0':
                    response += "✅ No Blacklist: No blacklist function\n"
                
                if data.get('is_whitelisted') == '1':
                    response += "⚠️ Whitelist: Has whitelist function\n"
                elif data.get('is_whitelisted') == '0':
                    response += "✅ No Whitelist: No whitelist function\n"
                
                # Anti-Whale
                if data.get('is_anti_whale') == '1':
                    response += "⚠️ Anti-Whale: Has transaction/position limits\n"
                    if data.get('anti_whale_modifiable') == '1':
                        response += "🚨 Modifiable Anti-Whale: Limits can be changed\n"
                elif data.get('is_anti_whale') == '0':
                    response += "✅ No Anti-Whale: No transaction limits\n"
                
                # Trading Cooldown
                if data.get('trading_cooldown') == '1':
                    response += "⚠️ Trading Cooldown: Has time restrictions between trades\n"
                
                # Personal Slippage
                if data.get('personal_slippage_modifiable') == '1':
                    response += "🚨 Personal Tax: Owner can set different tax for each address\n"
                
                # DEX Information
                dex_info = data.get('dex', [])
                if dex_info:
                    response += "\n📈 DEX Information:\n"
                    for dex in dex_info:
                        response += f"• {dex.get('name', 'Unknown')} ({dex.get('liquidity_type', 'Unknown')})\n"
                        response += f"  - Liquidity: ${dex.get('liquidity', 'N/A')}\n"
                        response += f"  - Pair: {dex.get('pair', 'N/A')}\n"
            else:
                response += "❌ DEX Trading: Cannot be traded on DEX\n"
            
            response += "\n"
            
            # Top Holders Information
            holders = data.get('holders', [])
            if holders:
                response += "👥 Top 10 Holders:\n"
                for i, holder in enumerate(holders[:5], 1):  # Show top 5
                    response += f"{i}. {holder.get('address', 'N/A')}\n"
                    response += f"   Balance: {holder.get('balance', 'N/A')} ({holder.get('percent', 'N/A')}%)\n"
                    if holder.get('is_locked') == '1':
                        response += f"   🔒 Locked: Yes\n"
                    if holder.get('tag'):
                        response += f"   Tag: {holder.get('tag')}\n"
                if len(holders) > 5:
                    response += f"   ... and {len(holders) - 5} more holders\n"
                response += "\n"
            
            # LP Information
            if data.get('is_in_dex') == '1':
                response += "💧 Liquidity Pool Information:\n"
                response += f"• LP Holders: {data.get('lp_holder_count', 'N/A')}\n"
                response += f"• LP Total Supply: {data.get('lp_total_supply', 'N/A')}\n"
                
                lp_holders = data.get('lp_holders', [])
                if lp_holders:
                    response += "• Top LP Holders:\n"
                    for i, holder in enumerate(lp_holders[:3], 1):  # Show top 3
                        response += f"  {i}. {holder.get('address', 'N/A')}\n"
                        response += f"     Balance: {holder.get('balance', 'N/A')} ({holder.get('percent', 'N/A')}%)\n"
                        if holder.get('is_locked') == '1':
                            response += f"     🔒 Locked: Yes\n"
                response += "\n"
            
            # Trust and Risk Assessment
            response += "🎯 Trust and Risk Assessment:\n"
            
            # Trust List
            if data.get('trust_list') == '1':
                response += "✅ Trust List: This token is on a famous and trustworthy list\n"
            else:
                response += "❓ Trust List: Not on trusted list or unknown\n"
            
            # Airdrop Scam
            if data.get('is_airdrop_scam') == '1':
                response += "🚨 AIRDROP SCAM: This token is an airdrop scam\n"
            elif data.get('is_airdrop_scam') == '0':
                response += "✅ No Airdrop Scam: Not detected as airdrop scam\n"
            else:
                response += "❓ Airdrop Scam: Unknown\n"
            
            # Fake Token
            fake_token = data.get('fake_token')
            if fake_token and fake_token.get('value') == 1:
                response += f"🚨 FAKE TOKEN: This is a counterfeit of mainstream asset\n"
                response += f"   Real Token: {fake_token.get('true_token_address', 'N/A')}\n"
            else:
                response += "✅ Authentic: Not detected as fake token\n"
            
            # CEX Listing
            cex_info = data.get('is_in_cex')
            if cex_info and cex_info.get('listed') == '1':
                response += "✅ CEX Listed: Listed on major centralized exchanges\n"
                cex_list = cex_info.get('cex_list', [])
                if cex_list:
                    response += f"   Exchanges: {', '.join(cex_list)}\n"
            else:
                response += "❓ CEX Listing: Not listed on major CEX or unknown\n"
            
            # Launchpad Token
            launchpad = data.get('launchpad_token')
            if launchpad and launchpad.get('is_launchpad_token') == '1':
                response += f"✅ Launchpad: Deployed through trusted launchpad\n"
                response += f"   Launchpad: {launchpad.get('launchpad_name', 'N/A')}\n"
            else:
                response += "❓ Launchpad: Not deployed through known launchpad\n"
            
            # Other Risks and Notes
            other_risks = data.get('other_potential_risks')
            if other_risks:
                response += f"\n⚠️ Other Potential Risks:\n{other_risks}\n"
            
            note = data.get('note')
            if note:
                response += f"\n📝 Additional Notes:\n{note}\n"
            
            response += "\n" + "=" * 60 + "\n"
            response += "⚠️  Always do your own research before investing in tokens!\n"
            response += "🔍 This analysis is based on GoPlus Security API data.\n"
            
            return response
        else:
            return f"Analysis failed: {result.get('message', 'Unknown error')}"

    @server.resource("goplus://supported-chains")
    def supported_chains() -> str:
        """Get list of supported blockchain chains for GoPlus Security API."""
        return """
# Supported Blockchain Chains

| Chain ID | Chain Name | Native Token |
|----------|------------|--------------|
| 1 | Ethereum | ETH |
| 56 | BSC (Binance Smart Chain) | BNB |
| 137 | Polygon | MATIC |
| 250 | Fantom | FTM |
| 25 | Cronos | CRO |
| 128 | Huobi ECO Chain | HT |
| 10 | Optimism | ETH |
| 42161 | Arbitrum | ETH |
| 43114 | Avalanche | AVAX |
| 1285 | Moonriver | MOVR |
| 1284 | Moonbeam | GLMR |
| 100 | Gnosis | xDAI |
| 1 | Ethereum | ETH |
| 56 | BSC | BNB |
| 137 | Polygon | MATIC |
| 250 | Fantom | FTM |
| 25 | Cronos | CRO |
| 128 | Huobi ECO Chain | HT |
| 10 | Optimism | ETH |
| 42161 | Arbitrum | ETH |
| 43114 | Avalanche | AVAX |
| 1285 | Moonriver | MOVR |
| 1284 | Moonbeam | GLMR |
| 100 | Gnosis | xDAI |
| 66 | OKC | OKT |
| 288 | Boba Network | ETH |
| 1088 | Metis | METIS |
| 1284 | Moonbeam | GLMR |
| 2000 | Dogechain | DOGE |
| 2001 | Milkomeda C1 | ADA |
| 2222 | Kava | KAVA |
| 7700 | Canto | CANTO |
| 8217 | Klaytn | KLAY |
| 9001 | Evmos | EVMOS |
| 10001 | ETHW (EthereumPoW) | ETHW |
| tron | Tron | TRX |
| 321 | KCC | KCS |
| 201022 | FON | FON |
| 5000 | Mantle | MNT |
| 204 | opBNB | BNB |
| 42766 | ZKFair | USDC |
| 81457 | Blast | ETH |
| 169 | Manta Pacific | ETH |
| 80094 | Berachain | BERA |
| 2741 | Abstract | ABS |
| 177 | Hashkey Chain | HSK |
| 146 | Sonic | S |
| 1514 | Story | STORY |

## Usage Examples

### Ethereum
```json
{
  "chain_id": "1",
  "address": "0x1234567890123456789012345678901234567890"
}
```

### BSC (Binance Smart Chain)
```json
{
  "chain_id": "56", 
  "address": "0x1234567890123456789012345678901234567890"
}
```

### Polygon
```json
{
  "chain_id": "137",
  "address": "0x1234567890123456789012345678901234567890"
}
```

### Arbitrum
```json
{
  "chain_id": "42161",
  "address": "0x1234567890123456789012345678901234567890"
}
```

### Tron (Special Case)
```json
{
  "chain_id": "tron",
  "address": "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
}
```

## Notes

- **Tron**: Uses "tron" as chain_id instead of a numeric value
- **Address Format**: Most chains use 0x-prefixed addresses, except Tron which uses base58 format
- **Token Standards**: 
  - ERC-20 for Ethereum and EVM-compatible chains
  - TRC-20 for Tron network
- **Gas Fees**: Each network has different gas fee structures and native tokens
"""

    return server