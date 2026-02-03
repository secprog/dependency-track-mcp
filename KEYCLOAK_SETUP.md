# Keycloak Integration Guide

OAuth 2.1 authentication for Dependency Track MCP Server using Keycloak.

## Quick Start

```bash
# 1. Configure environment
cp .env.example .env
# Edit .env with your Keycloak settings

# 2. Install dependencies
pip install -e .

# 3. Start server
python -m dependency_track_mcp.auth_wrapper
```

**Key `.env` settings for local Keycloak (port 8083):**

```env
DEPENDENCY_TRACK_OAUTH_ISSUER=http://localhost:8083/realms/mcp
DEPENDENCY_TRACK_OAUTH_AUDIENCE=mcp-api
DEPENDENCY_TRACK_DEV_ALLOW_HTTP=true
DEPENDENCY_TRACK_URL=http://localhost:8081
DEPENDENCY_TRACK_API_KEY=your-api-key
```

## Architecture

```
Client (with Bearer token)
    |
    v
Auth Wrapper (port 9000) - validates JWT via JWKS
    |
    v
FastMCP Backend - MCP protocol
    |
    v
Dependency Track API
```

## Keycloak Configuration

### 1. Create a Realm

1. Open Keycloak Admin Console: `http://localhost:8083/admin`
2. Create a new realm (e.g., `mcp`)

### 2. Create a Client

1. Navigate to **Clients** → **Create client**
2. Configure:
   - **Client type**: OpenID Connect
   - **Client ID**: `mcp-client`
3. Enable **Client authentication** (confidential client)
4. Enable **Direct access grants**
5. Set **Valid redirect URIs**: `*` (restrict in production)

### 3. Configure Audience Mapping (Critical!)

Without this, tokens won't have the `aud` claim that the MCP server validates.

#### Create Client Scope

1. **Client Scopes** → **Create client scope**
2. Name: `mcp-audience`, Type: Default, Protocol: openid-connect
3. Save

#### Add Audience Mapper

1. In `mcp-audience` scope → **Mappers** → **Add mapper** → **By configuration**
2. Select **Audience**
3. Configure:
   - Name: `mcp-aud-mapper`
   - Included Custom Audience: `mcp-api`
   - Add to access token: ON
4. Save

#### Attach to Client

1. **Clients** → your client → **Client scopes**
2. Add `mcp-audience` as **Default** scope

### 4. Create a User

1. **Users** → **Add user**
2. Set username and email
3. **Credentials** tab → Set password

## Testing

### Get a Token

```bash
curl -X POST http://localhost:8083/realms/mcp/protocol/openid-connect/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=mcp-client" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "username=YOUR_USERNAME" \
  -d "password=YOUR_PASSWORD" \
  -d "scope=openid"
```

### Verify Token

Check at [jwt.io](https://jwt.io) that your token contains:
- `iss`: `http://localhost:8083/realms/mcp`
- `aud`: `mcp-api`
- `exp`: Future timestamp

### Test Endpoints

```bash
# OAuth metadata
curl http://localhost:9000/.well-known/oauth-protected-resource

# Unauthorized (should return 401)
curl -i http://localhost:9000/mcp

# Authorized request
curl -X POST http://localhost:9000/mcp \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"initialize","params":{},"id":1}'
```

## Server Endpoints

| Endpoint | Description |
|----------|-------------|
| `/mcp` | MCP endpoint (requires Bearer token) |
| `/.well-known/oauth-protected-resource` | OAuth metadata |
| `/health` | Health check |
| `/admin/refresh-jwks` | Force JWKS cache refresh |

## Troubleshooting

### Token Missing `aud` Claim

Configure the audience mapper in Keycloak (see section 3 above).

### JWKS Fetch Failure

- Verify Keycloak is running
- Check `DEPENDENCY_TRACK_DEV_ALLOW_HTTP=true` for local HTTP
- Test: `curl http://localhost:8083/realms/mcp/protocol/openid-connect/certs`

### Token Expired

Get a fresh token. Adjust lifespan in Keycloak: **Realm Settings** → **Tokens** → **Access Token Lifespan**

### Wrong Issuer

Ensure `DEPENDENCY_TRACK_OAUTH_ISSUER` exactly matches the `iss` claim (check trailing slashes).

## Production Deployment

```env
# Use HTTPS everywhere
DEPENDENCY_TRACK_OAUTH_ISSUER=https://keycloak.example.com/realms/mcp
DEPENDENCY_TRACK_URL=https://dtrack.example.com
DEPENDENCY_TRACK_DEV_ALLOW_HTTP=false
DEPENDENCY_TRACK_VERIFY_SSL=true
```

Add a reverse proxy (Caddy/Nginx) for TLS termination:

```
Internet → Reverse Proxy (HTTPS:443) → Auth Wrapper (9000) → FastMCP
```

## References

- [MCP OAuth 2.1 Specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [RFC 8707: OAuth Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc8707)
- [Keycloak Documentation](https://www.keycloak.org/documentation)
