# GoPlus Security MCP Server

A Model Context Protocol (MCP) server that provides blockchain security analysis tools using the GoPlus Security API.

## Features

This MCP server provides the following security analysis tools:

###Security Analysis Tools

1. **Rug Pull Detection** - Analyze token contracts for potential rug pull risks
2. **Phishing Site Detection** - Check if websites are known phishing sites
3. **NFT Security Analysis** - Analyze NFT contract security
4. **Solana Token Security** - Get Solana token security information
5. **Address Security Analysis** - Analyze blockchain address security and reputation
6. **Token Security Analysis** - Comprehensive token security analysis

### 🌐 Supported Blockchains

- Ethereum Mainnet (chain_id: "1")
- Binance Smart Chain (chain_id: "56")
- Polygon (chain_id: "137")
- Arbitrum One (chain_id: "42161")
- Optimism (chain_id: "10")
- Avalanche C-Chain (chain_id: "43114")
- Fantom (chain_id: "250")
- Aurora (chain_id: "1313161554")
- Cronos (chain_id: "25")
- Gnosis (chain_id: "100")
- Heco (chain_id: "128")
- Klaytn (chain_id: "8217")
- Moonbeam (chain_id: "1284")
- Moonriver (chain_id: "1285")

## Configuration

### API Key Setup

**IMPORTANT**: You need a GoPlus Security API key to use this server.

1. **Get API Key**: Visit [GoPlus Security](https://gopluslabs.io/) and sign up for an API key
2. **For Testing**: Use the API key in MCP Inspector or test scripts
3. **For Production**: Configure through Smithery platform

### Session Configuration

The server requires a GoPlus Security API key for authentication. Configure it through the session configuration:

- **api_key**: Your GoPlus Security API key (required)
- **base_url**: Base URL for the API (default: "https://api.gopluslabs.io/api/v1/")
- **timeout**: Request timeout in seconds (default: 30, range: 5-300)

## Usage Examples

### Rug Pull Detection
```
rug_pull_detection(chain_id="1", address="0x6B175474E89094C44Da98b954EedeAC495271d0F")
```

### Phishing Site Detection
```
phishing_site_detection(url="https://example.com")
```

### NFT Security Analysis
```
nft_security_analysis(chain_id="1", address="0x82f5ef9ddc3d231962ba57a9c2ebb307dc8d26c2")
```

### Address Security Analysis
```
address_security_analysis(address="0xc8b759860149542a98a3eb57c14aadf59d6d89b9")
```

## Development

### Prerequisites

- Python >= 3.10
- [uv](https://docs.astral.sh/uv/getting-started/installation/) package manager
- GoPlus Security API key

### Running the Server

1. **Development mode:**
   ```bash
   uv run dev
   ```

2. **Interactive playground:**
   ```bash
   uv run playground
   ```

3. **Production mode:**
   ```bash
   uv run start
   ```

### Project Structure

```
goplus-mcp/
├── src/
│   └── goplus_security_server/
│       ├── __init__.py
│       └── server.py          # Original Smithery server implementation
├── main.py                   # Main Docker entry point
├── Dockerfile                # Docker container configuration
├── pyproject.toml            # Project configuration
├── smithery.yaml             # Smithery deployment config
└── README.md                 # This file
```

## API Reference

### Tools

#### `rug_pull_detection(chain_id: str, address: str) -> str`
Detect potential rug pull risks for a token contract.

**Parameters:**
- `chain_id`: Blockchain chain ID (e.g., "1" for Ethereum)
- `address`: Token contract address to analyze

#### `phishing_site_detection(url: str) -> str`
Check if a website is a known phishing site.

**Parameters:**
- `url`: Website URL to check for phishing risks

#### `nft_security_analysis(chain_id: str, address: str) -> str`
Analyze NFT contract security.

**Parameters:**
- `chain_id`: Blockchain chain ID
- `address`: NFT contract address to analyze

#### `solana_token_security() -> str`
Get Solana token security information.

#### `address_security_analysis(address: str) -> str`
Analyze address security and reputation.

**Parameters:**
- `address`: Blockchain address to analyze

#### `token_security_analysis(chain_id: str, address: str) -> str`
Comprehensive token security analysis.

**Parameters:**
- `chain_id`: Blockchain chain ID
- `address`: Token contract address to analyze

### Resources

#### `goplus://api-docs`
API documentation and usage examples.

#### `goplus://supported-chains`
List of supported blockchain networks.

## Deployment

This server is designed to work with [Smithery](https://smithery.ai) for easy deployment and management.

1. Push your code to a GitHub repository
2. Connect your repository to Smithery
3. Deploy with one click

## License

This project is licensed under the MIT License.

## Support

For issues and questions:
- GoPlus Security API: [https://gopluslabs.io](https://gopluslabs.io)
- MCP Documentation: [https://modelcontextprotocol.io](https://modelcontextprotocol.io)
- Smithery: [https://smithery.ai](https://smithery.ai)