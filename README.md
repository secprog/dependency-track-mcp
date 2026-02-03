# Dependency Track MCP Server

An MCP (Model Context Protocol) server for [OWASP Dependency Track](https://dependencytrack.org/) - enabling AI assistants to interact with your Software Composition Analysis platform.

## Features

- **Project Management**: List, create, update, and delete projects
- **Component Analysis**: View components, dependencies, and their relationships
- **Vulnerability Management**: Query vulnerabilities, findings, and CVE details
- **Security Metrics**: Access portfolio and project-level security metrics
- **Policy Compliance**: Monitor policy violations and compliance status
- **SBOM Operations**: Upload and export Software Bills of Materials (CycloneDX/SPDX)
- **Search**: Full-text search across projects, components, and vulnerabilities

## Installation

```bash
pip install dependency-track-mcp
```

Or install from source:

```bash
git clone https://github.com/your-org/dependency-track-mcp.git
cd dependency-track-mcp
pip install -e .
```

## Configuration

### Security Warning ⚠️ - OAuth 2.1 Required

**This MCP server requires OAuth 2.1 bearer token authentication** as specified in the [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

All requests must include a valid OAuth 2.1 bearer token:
```
Authorization: Bearer <your_oauth2_token>
```

Follow these security best practices:

- **Configure OAuth 2.1 issuer** - Set `MCP_OAUTH_ISSUER` to your OAuth provider
- **Never commit API keys** - Use environment variables or `.env` files (already in `.gitignore`)
- **Use HTTPS only** - Always connect to Dependency Track over HTTPS with valid certificates
- **Minimal scopes** - Request only the scopes your use case needs
- **Rotate credentials** - Change API keys and tokens periodically
- **Secure client configs** - Restrict file permissions on MCP client configuration files

📖 See [SECURITY.md](SECURITY.md) for comprehensive security guidance and OAuth 2.1 details.

### Environment Variables

Set the following environment variables:

```bash
# OAuth 2.1 Authorization (REQUIRED)
export MCP_OAUTH_ISSUER=https://auth.example.com
export MCP_OAUTH_AUDIENCE=dependency-track-mcp  # Optional
export MCP_OAUTH_REQUIRED_SCOPES="read:projects read:vulnerabilities"

# Dependency Track Backend (for server-to-API auth only)
export DEPENDENCY_TRACK_URL=https://dependency-track.example.com
export DEPENDENCY_TRACK_API_KEY=your-dtrack-api-key

# Optional
export DEPENDENCY_TRACK_TIMEOUT=30
export DEPENDENCY_TRACK_VERIFY_SSL=true
export DEPENDENCY_TRACK_MAX_RETRIES=3
```

Or create a `.env` file based on `.env.example`.

### OAuth 2.1 Setup

1. **Configure your OAuth provider** to support OpenID Connect with JWT tokens
2. **Publish JWKS endpoint** for token signature verification
3. **Set token claims** to include `sub`, `iat`, `exp`, and `scope` or `scopes`
4. **Use HTTPS** for all OAuth endpoints
5. **Set appropriate token lifetime** (e.g., 1 hour)

### Getting a Dependency Track API Key

The API key is used for **server-to-API authentication only** and is not exposed to MCP clients.

1. Log in to Dependency Track as an administrator
2. Navigate to Administration > Access Management > Teams
3. Select or create a team
4. Generate a new API key for the team
5. Copy the key (it won't be shown again)
6. Store it in `DEPENDENCY_TRACK_API_KEY` environment variable

## Usage

### Running the Server

```bash
# Using the installed entry point
dependency-track-mcp

# Or run directly
python -m dependency_track_mcp.main
```

This starts an HTTPS server with JWT authentication via Keycloak/OIDC.

### Configuration for Production

Required environment variables (or `.env` file):

```bash
# OAuth 2.1 (required)
MCP_OAUTH_ISSUER=https://keycloak.example.com/realms/mcp
MCP_OAUTH_AUDIENCE=mcp-api

# TLS certificates (required for HTTPS)
MCP_SERVER_TLS_CERT="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
MCP_SERVER_TLS_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"

# Dependency Track backend
DEPENDENCY_TRACK_URL=https://dtrack.example.com
DEPENDENCY_TRACK_API_KEY=your-api-key
```

### Local Development

For local development with HTTP (never use in production):

```bash
# Enable HTTP for local testing
MCP_DEV_ALLOW_HTTP=true
MCP_OAUTH_ISSUER=http://localhost:8083/realms/mcp
DEPENDENCY_TRACK_URL=http://localhost:8081
```

See [KEYCLOAK_SETUP.md](KEYCLOAK_SETUP.md) for setting up local Keycloak.

### With Claude Desktop

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "dependency-track": {
      "command": "python",
      "args": ["-m", "dependency_track_mcp.main"],
      "env": {
        "MCP_OAUTH_ISSUER": "https://auth.example.com",
        "MCP_OAUTH_AUDIENCE": "mcp-api",
        "MCP_OAUTH_REQUIRED_SCOPES": "read:projects read:vulnerabilities",
        "MCP_SERVER_TLS_CERT": "...",
        "MCP_SERVER_TLS_KEY": "...",
        "DEPENDENCY_TRACK_URL": "https://your-instance.example.com",
        "DEPENDENCY_TRACK_API_KEY": "your-dtrack-api-key"
      }
    }
  }
}
```

**Security Notes**:
- The Dependency Track API key is stored in the configuration file
- OAuth tokens are transmitted at runtime (not stored in config)
- TLS certificates can be provided as PEM content (use `\n` for newlines)
- Ensure your `claude_desktop_config.json` file has restricted permissions:
  - macOS/Linux: `chmod 600 ~/Library/Application\ Support/Claude/claude_desktop_config.json`
  - Windows: Use NTFS permissions to restrict access to your user account only
- MCP client is responsible for obtaining and providing valid OAuth tokens

## MCP Scopes

The server validates the following OAuth 2.1 scopes:

| Scope | Description |
|-------|-------------|
| `read:projects` | List and view projects |
| `write:projects` | Create, update, and delete projects |
| `read:components` | List and view components |
| `read:vulnerabilities` | View vulnerabilities and findings |
| `write:analysis` | Record analysis decisions (triage) |
| `read:metrics` | View security metrics |
| `read:policies` | View policy violations |
| `upload:bom` | Upload SBOM files |
| `search` | Search functionality |

**Token Scope Claims**: Your OAuth tokens should include scopes in one of these formats:

```
"scope": "read:projects read:vulnerabilities write:analysis"
"scopes": "read:projects read:vulnerabilities write:analysis"
```

## Available Tools

### Project Tools
- `list_projects` - List all projects with filtering and pagination
- `get_project` - Get project details by UUID
- `lookup_project` - Find project by name and version
- `create_project` - Create a new project
- `update_project` - Update project properties
- `delete_project` - Delete a project
- `get_project_children` - Get child projects

### Component Tools
- `list_project_components` - List components in a project
- `get_component` - Get component details
- `find_component_by_purl` - Find by Package URL
- `find_component_by_hash` - Find by file hash
- `get_dependency_graph` - Get project dependency graph
- `get_component_projects` - Find projects using a component

### Vulnerability Tools
- `get_vulnerability` - Get vulnerability details
- `get_affected_projects` - Find projects affected by a CVE
- `list_component_vulnerabilities` - List vulnerabilities for a component

### Finding & Analysis Tools
- `list_project_findings` - List security findings for a project
- `get_finding_analysis` - Get analysis decision for a finding
- `update_finding_analysis` - Record triage decision
- `list_findings_grouped` - Get findings grouped by vulnerability

### Metrics Tools
- `get_portfolio_metrics` - Get portfolio-wide metrics
- `get_portfolio_metrics_history` - Get historical portfolio metrics
- `get_project_metrics` - Get project metrics
- `get_project_metrics_history` - Get historical project metrics
- `refresh_portfolio_metrics` - Trigger metrics refresh
- `refresh_project_metrics` - Trigger project metrics refresh

### Policy Tools
- `list_policy_violations` - List all policy violations
- `list_project_policy_violations` - List violations for a project
- `list_component_policy_violations` - List violations for a component
- `list_policies` - List all security policies

### BOM Tools
- `upload_bom` - Upload SBOM (CycloneDX/SPDX)
- `check_bom_processing` - Check BOM processing status
- `export_project_bom` - Export project as CycloneDX
- `export_component_bom` - Export component as CycloneDX
- `validate_bom` - Validate BOM without uploading

### Search Tools
- `search` - Global search across all entities
- `search_projects` - Search projects
- `search_components` - Search components
- `search_vulnerabilities` - Search vulnerabilities
- `search_licenses` - Search licenses

## Development

### Setup

```bash
git clone https://github.com/your-org/dependency-track-mcp.git
cd dependency-track-mcp
pip install -e ".[dev]"
```

### Running Tests

```bash
pytest
```

### Code Formatting

```bash
ruff check .
ruff format .
```

## Security

This MCP server implements OAuth 2.1 bearer token authorization as required by the [MCP Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization).

**Key Security Features**:
- 🔐 **OAuth 2.1 Bearer Tokens** - Required per MCP specification
- ✅ **JWT Validation** - Structure, expiration, issuer, and scope validation
- 🔒 **HTTPS/TLS** - Certificate verification enabled by default
- 🔑 **Secure API Key Management** - Backend keys via environment variables only
- 🛡️ **Input Validation** - Pydantic models for all inputs/outputs
- 🚫 **No Token Passthrough** - OAuth tokens not sent to backend
- 📊 **Scope-Based Authorization** - Fine-grained permission control
- ⚡ **Rate Limiting** - Exponential backoff and retry logic

**OAuth 2.1 Requirements**:
- All requests must include valid Bearer token in Authorization header
- Tokens must be valid JWTs with required claims (`sub`, `iat`, `exp`, `scope`/`scopes`)
- Server validates token expiration, issuer, and required scopes
- MCP client is responsible for obtaining tokens from OAuth provider
- Token signature verification delegated to MCP client layer or JWKS endpoint

For detailed security information, threat model, deployment guidelines, and OAuth 2.1 configuration, see [SECURITY.md](SECURITY.md).

**Reporting Security Issues**: Please report security vulnerabilities responsibly by emailing the maintainer directly (see [SECURITY.md](SECURITY.md)) rather than opening public issues.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [OWASP Dependency Track](https://dependencytrack.org/)
- [FastMCP](https://github.com/jlowin/fastmcp)
- [Model Context Protocol](https://modelcontextprotocol.io/)
