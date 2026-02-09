#!/usr/bin/env python3
"""
Auto-configure Keycloak for MCP OAuth2 - no flags needed.

Just run: python setup_keycloak_auto.py

Defaults:
- Keycloak URL: http://localhost:8083
- Realm: mcp
- Admin user: admin
- Client ID: vscode-mcp
- Audience: mcp-api
- PKCE: Required (S256)
- Flows: Auth code + refresh only
- DCR: Initial Access Token created and saved to .env

Key fixes for your case (VS Code native-app redirect on random loopback port):
- Your redirect_uri is like: http://127.0.0.1:33418/
- Keycloak ignores the *port* for loopback, but still matches the *path* strictly.
- So we configure BOTH:
    http://127.0.0.1/
    http://127.0.0.1/*
  (plus vscode://dynamicauthprovider/* just in case your flow uses it)

Also:
- Uses Web Origins ["+"] (Keycloak UI equivalent)
- Prints a FINAL full dump of what Keycloak actually stored for the client
"""

import asyncio
import sys
from getpass import getpass

import httpx

# Hardcoded defaults
KEYCLOAK_URL = "http://localhost:8083"
REALM = "mcp"
ADMIN_USER = "admin"
CLIENT_ID = "vscode-mcp"
AUDIENCE = "mcp-api"
SCOPE_NAME = "mcp-audience"
MAPPER_NAME = "mcp-aud-mapper"

# Redirect URIs that match VS Code native loopback (random port) + VS Code schemes
REDIRECT_URIS = [
    # Native-app loopback: allow any port AND match "/" path
    "http://127.0.0.1/",
    "http://127.0.0.1/*",

    # (Optional) VS Code scheme-based flows
    "vscode://dynamicauthprovider/*",
    "vscode://vscode.github-authentication/did-authenticate",
    "vscode://ms-vscode.remote-server/did-authenticate",

    # If you have local web apps:
    "http://localhost:3000/*",
    "http://localhost:8000/*",
]

IAT_COUNT = 100


def dump_client_state(client: dict) -> None:
    """Print a readable dump of what Keycloak actually stored for the client."""
    print("\n" + "=" * 80)
    print("📦 FINAL CLIENT STATE AS STORED IN KEYCLOAK")
    print("=" * 80)

    keys_of_interest = [
        "id",
        "clientId",
        "name",
        "description",
        "enabled",
        "publicClient",
        "bearerOnly",
        "standardFlowEnabled",
        "implicitFlowEnabled",
        "directAccessGrantsEnabled",
        "serviceAccountsEnabled",
        "authorizationServicesEnabled",
        "redirectUris",
        "webOrigins",
        "rootUrl",
        "baseUrl",
        "adminUrl",
        "attributes",
        "defaultClientScopes",
        "optionalClientScopes",
        "protocol",
    ]

    for key in keys_of_interest:
        value = client.get(key)
        print(f"\n{key}:")
        if isinstance(value, list):
            for item in value:
                print(f"  - {item}")
        elif isinstance(value, dict):
            for k, v in value.items():
                print(f"  {k}: {v}")
        else:
            print(f"  {value}")

    extra_keys = sorted(set(client.keys()) - set(keys_of_interest))
    if extra_keys:
        print("\n" + "-" * 80)
        print("Extra keys present on this Keycloak version:")
        print("-" * 80)
        for k in extra_keys:
            v = client.get(k)
            if isinstance(v, (dict, list)):
                print(f"{k}: ({type(v).__name__}, elided)")
            else:
                print(f"{k}: {v}")

    print("\n" + "=" * 80)
    print("🔍 END CLIENT STATE DUMP")
    print("=" * 80)


async def get_admin_token(keycloak_url: str, realm: str, admin_user: str, admin_pass: str) -> str | None:
    token_url = f"{keycloak_url}/realms/{realm}/protocol/openid-connect/token"
    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        r = await client.post(
            token_url,
            data={
                "grant_type": "password",
                "client_id": "admin-cli",
                "username": admin_user,
                "password": admin_pass,
            },
        )
    if r.status_code == 200:
        return r.json().get("access_token")
    return None


async def ensure_realm(keycloak_url: str, realm: str, headers: dict) -> None:
    admin_base = f"{keycloak_url}/admin/realms"
    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        check = await client.get(f"{admin_base}/{realm}", headers=headers)
        if check.status_code == 200:
            print(f"✓ Realm '{realm}' exists")
            return
        if check.status_code != 404:
            raise RuntimeError(f"Error checking realm: {check.status_code} {check.text}")

        create = await client.post(admin_base, headers=headers, json={"realm": realm, "enabled": True})
        create.raise_for_status()
        print(f"✓ Realm '{realm}' created")


async def get_client_uuid(admin_api_url: str, client_id: str, headers: dict) -> str | None:
    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        r = await client.get(f"{admin_api_url}/clients", params={"clientId": client_id}, headers=headers)
        r.raise_for_status()
        data = r.json()
        return data[0].get("id") if data else None


async def get_client(admin_api_url: str, client_uuid: str, headers: dict) -> dict:
    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        r = await client.get(f"{admin_api_url}/clients/{client_uuid}", headers=headers)
        r.raise_for_status()
        return r.json()


def normalize_redirects(redirects: list[str]) -> list[str]:
    """Deduplicate and keep stable ordering."""
    seen: set[str] = set()
    out: list[str] = []
    for r in redirects:
        r = r.strip()
        if not r or r in seen:
            continue
        seen.add(r)
        out.append(r)
    return out


async def create_client(admin_api_url: str, client_id: str, redirect_uris: list[str], headers: dict) -> str:
    desired_attributes = {
        "pkce.code.challenge.required": "true",
        "pkce.code.challenge.method": "S256",
    }

    client_config = {
        "clientId": client_id,
        "enabled": True,
        "publicClient": True,
        "standardFlowEnabled": True,
        "implicitFlowEnabled": False,
        "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
        "authorizationServicesEnabled": False,
        "redirectUris": redirect_uris,
        "webOrigins": ["+"],
        "attributes": desired_attributes,
    }

    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        r = await client.post(f"{admin_api_url}/clients", json=client_config, headers=headers)
        r.raise_for_status()
        print(f"✓ Client '{client_id}' created (PKCE required, auth code only)")

    client_uuid = await get_client_uuid(admin_api_url, client_id, headers)
    if not client_uuid:
        raise RuntimeError("Client created but could not re-fetch client UUID")
    return client_uuid


async def update_client(admin_api_url: str, client_uuid: str, client_id: str, redirect_uris: list[str], headers: dict) -> None:
    desired_attributes = {
        "pkce.code.challenge.required": "true",
        "pkce.code.challenge.method": "S256",
    }

    current = await get_client(admin_api_url, client_uuid, headers)
    attrs = current.get("attributes") or {}
    attrs.update(desired_attributes)

    current.update(
        {
            "clientId": client_id,
            "enabled": True,
            "publicClient": True,
            "standardFlowEnabled": True,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "serviceAccountsEnabled": False,
            "authorizationServicesEnabled": False,
            "redirectUris": redirect_uris,
            "webOrigins": ["+"],
            "attributes": attrs,
        }
    )

    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        r = await client.put(f"{admin_api_url}/clients/{client_uuid}", json=current, headers=headers)
        r.raise_for_status()

    print(f"✓ Client '{client_id}' updated (PKCE required, auth code only)")


async def upsert_client(admin_api_url: str, client_id: str, redirect_uris: list[str], headers: dict) -> str:
    client_uuid = await get_client_uuid(admin_api_url, client_id, headers)
    if client_uuid:
        await update_client(admin_api_url, client_uuid, client_id, redirect_uris, headers)
        return client_uuid
    return await create_client(admin_api_url, client_id, redirect_uris, headers)


async def get_client_scope_id(admin_api_url: str, scope_name: str, headers: dict) -> str | None:
    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        r = await client.get(f"{admin_api_url}/client-scopes", headers=headers)
        r.raise_for_status()
        for scope in r.json():
            if scope.get("name") == scope_name:
                return scope.get("id")
    return None


async def ensure_audience_scope(admin_api_url: str, scope_name: str, audience: str, headers: dict) -> str:
    scope_id = await get_client_scope_id(admin_api_url, scope_name, headers)

    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        if not scope_id:
            r = await client.post(
                f"{admin_api_url}/client-scopes",
                headers=headers,
                json={
                    "name": scope_name,
                    "protocol": "openid-connect",
                    "attributes": {
                        "display.on.consent.screen": "false",
                        "include.in.token.scope": "false",
                    },
                },
            )
            r.raise_for_status()
            scope_id = await get_client_scope_id(admin_api_url, scope_name, headers)
            print(f"✓ Client scope '{scope_name}' created")
        else:
            print(f"✓ Client scope '{scope_name}' exists")

        if not scope_id:
            raise RuntimeError("Failed to get scope id")

        m = await client.get(
            f"{admin_api_url}/client-scopes/{scope_id}/protocol-mappers/models",
            headers=headers,
        )
        m.raise_for_status()
        mappers = m.json()
        if any(mapper.get("name") == MAPPER_NAME for mapper in mappers):
            print("✓ Audience mapper exists")
            return scope_id

        cm = await client.post(
            f"{admin_api_url}/client-scopes/{scope_id}/protocol-mappers/models",
            headers=headers,
            json={
                "name": MAPPER_NAME,
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "config": {
                    "included.custom.audience": audience,
                    "access.token.claim": "true",
                    "id.token.claim": "false",
                },
            },
        )
        cm.raise_for_status()
        print(f"✓ Audience mapper created (aud={audience})")

    return scope_id


async def attach_scope_to_client(admin_api_url: str, client_uuid: str, scope_id: str, headers: dict) -> None:
    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        r = await client.get(
            f"{admin_api_url}/clients/{client_uuid}/default-client-scopes",
            headers=headers,
        )
        r.raise_for_status()

        default_scopes = r.json()
        if any(scope.get("id") == scope_id for scope in default_scopes):
            print("✓ Audience scope attached to client")
            return

        a = await client.put(
            f"{admin_api_url}/clients/{client_uuid}/default-client-scopes/{scope_id}",
            headers=headers,
        )
        a.raise_for_status()
        print("✓ Audience scope attached to client")


async def create_initial_access_token(admin_api_url: str, headers: dict, count: int) -> str:
    async with httpx.AsyncClient(timeout=30.0, verify=False) as client:
        r = await client.post(
            f"{admin_api_url}/clients-initial-access",
            json={"count": count, "expiration": 0},
            headers=headers,
        )
        r.raise_for_status()
        token = r.json().get("token")
        if not token:
            raise RuntimeError("Initial access token response missing 'token'")
        return token


def write_env_token(token: str, env_file: str = ".env") -> None:
    try:
        with open(env_file, "r", encoding="utf-8") as f:
            env_content = f.read()
    except FileNotFoundError:
        env_content = ""

    key = "MCP_KEYCLOAK_INITIAL_ACCESS_TOKEN="
    if key in env_content:
        before = env_content.split(key)[0].rstrip()
        env_content = before + f"\n{key}{token}\n"
    else:
        env_content += "\n# Dynamic Client Registration Initial Access Token\n"
        env_content += f"{key}{token}\n"

    with open(env_file, "w", encoding="utf-8") as f:
        f.write(env_content)


async def main() -> None:
    print("=" * 80)
    print("Auto-Configure Keycloak for MCP OAuth2")
    print("=" * 80)
    print("\nUsing defaults:")
    print(f"  Keycloak: {KEYCLOAK_URL}")
    print(f"  Realm: {REALM}")
    print(f"  Admin: {ADMIN_USER}")
    print(f"  Client: {CLIENT_ID} (public, PKCE S256, auth code + refresh only)")
    print(f"  Audience: {AUDIENCE}")
    print("\nRedirect URIs to configure:")
    for u in REDIRECT_URIS:
        print(f"  - {u}")
    print()

    admin_pass = getpass(f"Enter password for '{ADMIN_USER}': ")

    print("\n🔐 Authenticating...")
    admin_token = await get_admin_token(KEYCLOAK_URL, REALM, ADMIN_USER, admin_pass)
    if not admin_token and REALM != "master":
        admin_token = await get_admin_token(KEYCLOAK_URL, "master", ADMIN_USER, admin_pass)

    if not admin_token:
        print("❌ Authentication failed (wrong password? wrong realm? keycloak not reachable?)")
        sys.exit(1)

    print("✓ Authenticated\n")

    headers = {"Authorization": f"Bearer {admin_token}", "Content-Type": "application/json"}

    print("🔧 Configuring realm and client...")
    await ensure_realm(KEYCLOAK_URL, REALM, headers)

    admin_api_url = f"{KEYCLOAK_URL}/admin/realms/{REALM}"

    # Normalize/dedupe redirects to keep updates stable
    redirects = normalize_redirects(REDIRECT_URIS)

    client_uuid = await upsert_client(admin_api_url, CLIENT_ID, redirects, headers)

    scope_id = await ensure_audience_scope(admin_api_url, SCOPE_NAME, AUDIENCE, headers)
    await attach_scope_to_client(admin_api_url, client_uuid, scope_id, headers)

    print("\n🎫 Creating DCR Initial Access Token...")
    iat = await create_initial_access_token(admin_api_url, headers, IAT_COUNT)
    print(f"✓ Token created: {iat[:20]}...")

    print("\n📝 Writing to .env...")
    write_env_token(iat, ".env")
    print("✓ Updated .env")

    # FINAL: re-fetch from server and print exactly what Keycloak stored
    final_client = await get_client(admin_api_url, client_uuid, headers)
    dump_client_state(final_client)

    print("\n✅ Configuration Complete!")
    print("Your redirect_uri like 'http://127.0.0.1:33418/' should now be accepted.")
    print("If it still fails, check the dump above: redirectUris must include http://127.0.0.1/ or http://127.0.0.1/*")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⚠️ Cancelled")
        sys.exit(0)
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
