#!/usr/bin/env python3
"""
GoPlus Security MCP Server - Main Entry Point
Supports both HTTP and STDIO transport modes
"""

import os
import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.middleware.cors import CORSMiddleware
from typing import Optional
from src.goplus_security_server.server import create_server


def main():
    """Main function to start the server in HTTP or STDIO mode."""
    transport_mode = os.getenv("TRANSPORT", "stdio")
    
    if transport_mode == "http":
        # HTTP mode for Smithery deployment
        print("GoPlus Security MCP Server starting in HTTP mode...")
        
        # Create the MCP server
        mcp_server = create_server()
        
        # Extract the underlying FastMCP server from Smithery wrapper
        if hasattr(mcp_server, 'server'):
            fastmcp_server = mcp_server.server
        else:
            fastmcp_server = mcp_server
        
        # Setup Starlette app with CORS for cross-origin requests
        app = fastmcp_server.streamable_http_app()
        
        # Add CORS middleware for browser-based clients
        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["GET", "POST", "OPTIONS"],
            allow_headers=["*"],
            expose_headers=["mcp-session-id", "mcp-protocol-version"],
            max_age=86400,
        )

        # Use Smithery-required PORT environment variable
        port = int(os.environ.get("PORT", 8081))
        print(f"Listening on port {port}")

        uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")
    
    else:
        # STDIO mode for local development
        print("GoPlus Security MCP Server starting in STDIO mode...")
        
        # Create and run the MCP server
        mcp_server = create_server()
        mcp_server.run()


if __name__ == "__main__":
    main()