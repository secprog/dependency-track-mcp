# Dependency Track MCP Server

An MCP (Model Context Protocol) server for [OWASP Dependency Track](https://dependencytrack.org/) - enabling AI assistants to interact with your Software Composition Analysis platform.

## Features

- **Project Management**: Create, update, and track projects and hierarchies
- **Component Analysis**: View components, dependencies, hashes, and usage
- **Vulnerability Management**: Query vulnerabilities, findings, triage, and VEX
- **Security Metrics**: Portfolio and project metrics with history
- **Policy Compliance**: Policies, violations, and enforcement visibility
- **SBOM Operations**: Upload, validate, and export SBOMs (CycloneDX/SPDX)
- **Reference Data**: Licenses, license groups, tags, CWE, repositories, services
- **Administration**: Teams, users, permissions, ACL, notifications, LDAP, OIDC
- **System & Integrations**: Badges, calculator, integrations, events, version info

## Installation

```bash
pip install dependency-track-mcp
```

Or install from source:

```bash
git clone https://github.com/secprog/dependency-track-mcp.git
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
- **Never commit API keys** - Use environment variables or an environment file based on [.env.example](.env.example) (already ignored by [.gitignore](.gitignore))
- **Use HTTPS only** - Always connect to Dependency Track over HTTPS with valid certificates
- **Minimal scopes** - Request only the scopes your use case needs
- **Rotate credentials** - Change API keys and tokens periodically
- **Secure client configs** - Restrict file permissions on MCP client configuration files

📖 See [KEYCLOAK_SETUP.md](KEYCLOAK_SETUP.md) and [.env.example](.env.example) for OAuth 2.1 setup and configuration examples.

### Environment Variables

Set the following environment variables:

```bash
# OAuth 2.1 Authorization (REQUIRED)
export MCP_OAUTH_ISSUER=https://auth.example.com
export MCP_OAUTH_JWKS_URL=https://auth.example.com/.well-known/jwks.json  # Optional (auto-derived if omitted)
export MCP_OAUTH_AUDIENCE=dependency-track-mcp  # Optional
export MCP_OAUTH_REQUIRED_SCOPES="read:projects read:vulnerabilities"  # Optional
export MCP_OAUTH_RESOURCE_URI=https://your-mcp-host.example.com/mcp  # Optional

# Dependency Track Backend (for server-to-API auth only)
export DEPENDENCY_TRACK_URL=https://dependency-track.example.com
export DEPENDENCY_TRACK_API_KEY=your-dtrack-api-key

# Optional
export DEPENDENCY_TRACK_TIMEOUT=30
export DEPENDENCY_TRACK_VERIFY_SSL=true
export DEPENDENCY_TRACK_MAX_RETRIES=3

# Server Settings (HTTPS by default)
export MCP_SERVER_HOST=0.0.0.0
export MCP_SERVER_PORT=9000
export MCP_SERVER_TLS_CERT="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
export MCP_SERVER_TLS_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
export MCP_SERVER_TLS_CA_CERTS="-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"  # Optional
export MCP_SERVER_TLS_KEYFILE_PASSWORD=your_password  # Optional
```

Or create an environment file based on [.env.example](.env.example).

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

This starts a FastAPI server with OAuth 2.1 JWT authentication and mounts the MCP endpoint at `/mcp`. If TLS certs are provided, it serves HTTPS. HTTP is only allowed when `MCP_DEV_ALLOW_HTTP=true`.

### HTTP Endpoints

- `/mcp` - MCP protocol endpoint (protected by OAuth 2.1 Bearer tokens)
- `/.well-known/oauth-protected-resource` - OAuth resource metadata (RFC 8707)
- `/health` - Health check
- `/admin/refresh-jwks` - JWKS cache refresh (protect in production)

### Configuration for Production

Required environment variables (or an environment file based on [.env.example](.env.example)):

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

### Quick Start Script

If you prefer a simple launcher with environment-file validation, use [start_services.py](start_services.py).

### Client Configuration (HTTP transport)

Point your MCP client at the HTTP endpoint and include a Bearer token:

- MCP endpoint: `https://<host>:<port>/mcp` (use `http://` only when `MCP_DEV_ALLOW_HTTP=true`)
- Authorization header: `Authorization: Bearer <oauth2_token>`

**Security Notes**:
- The Dependency Track API key is stored server-side only (not exposed to clients)
- OAuth tokens are transmitted at runtime (not stored in config)
- TLS certificates can be provided as PEM content (use `\n` for newlines)
- Restrict file permissions on any client config that includes secrets

## MCP Scopes

The server validates the following OAuth 2.1 scopes:

| Scope | Description |
|-------|-------------|
| `read:projects` | List and view projects |
| `write:projects` | Create, update, and delete projects |
| `read:components` | List and view components |
| `write:components` | Create/update components (where supported) |
| `read:vulnerabilities` | View vulnerabilities and findings |
| `write:vulnerabilities` | Update vulnerability data (where supported) |
| `write:analysis` | Record analysis decisions (triage) |
| `read:metrics` | View security metrics |
| `read:policies` | View policy violations |
| `write:policies` | Create/update policies |
| `upload:bom` | Upload SBOM files |
| `upload:vex` | Upload VEX documents |
| `search` | Search functionality |
| `read:licenses` | List and view licenses |
| `write:licenses` | Create/update licenses |
| `read:tags` | List and view tags |
| `write:tags` | Create/update tags |
| `read:services` | List and view services |
| `write:services` | Create/update services |
| `read:repositories` | List and view repositories |
| `write:repositories` | Create/update repositories |
| `read:cwe` | View CWE reference data |
| `admin:config` | Read/write configuration properties |
| `admin:teams` | Manage teams |
| `admin:users` | Manage users |
| `admin:permissions` | Manage permissions |
| `admin:acl` | Manage access control lists |
| `admin:notifications` | Manage notifications |
| `admin:ldap` | Manage LDAP settings |
| `admin:oidc` | Manage OIDC settings |
| `system:version` | Version and system info |
| `system:badges` | Project badges |
| `system:calculator` | Risk calculator |

**Token Scope Claims**: Your OAuth tokens should include scopes in one of these formats:

```
"scope": "read:projects read:vulnerabilities write:analysis"
"scopes": "read:projects read:vulnerabilities write:analysis"
```

## Available Tools

Tool groups are registered in [src/dependency_track_mcp/tools](src/dependency_track_mcp/tools) and include:

- **Core SCA**: Projects, components, vulnerabilities, findings, metrics, policies, BOM, search
- **Reference Data**: Licenses, license groups, tags, CWE, repositories, services, VEX
- **Properties**: Project, component, and config properties
- **Administration**: Teams, users, permissions, ACL, notifications, LDAP, OIDC
- **System & Integrations**: Version, badges, calculator, integrations, events

## Development

### Setup

```bash
git clone https://github.com/secprog/dependency-track-mcp.git
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
- ⚡ **Retry/Backoff** - Resilient HTTP client with retries

**OAuth 2.1 Requirements**:
- All requests must include valid Bearer token in Authorization header
- Tokens must be valid JWTs with required claims (`sub`, `iat`, `exp`, `scope`/`scopes`)
- Server validates token expiration, issuer, and required scopes
- MCP client is responsible for obtaining tokens from OAuth provider
- Token signature verification is performed using JWKS (auto-derived from issuer)

To validate your configuration locally, run [verify_security.py](verify_security.py).

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [OWASP Dependency Track](https://dependencytrack.org/)
- [FastMCP](https://github.com/jlowin/fastmcp)
- [Model Context Protocol](https://modelcontextprotocol.io/)
