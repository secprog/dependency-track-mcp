#!/usr/bin/env python
"""Simple launcher for Dependency Track MCP Server with OAuth.

Requires .env file with configuration.
See .env.example for reference.
"""

import subprocess
import sys
from pathlib import Path


def main():
    """Start the MCP server."""
    # Check for .env file
    if not Path(".env").exists():
        print("Error: .env file not found!")
        print("Copy .env.example to .env and configure it.")
        sys.exit(1)
    
    # Run the server
    subprocess.run([sys.executable, "-m", "dependency_track_mcp.auth_wrapper"])


if __name__ == "__main__":
    main()
