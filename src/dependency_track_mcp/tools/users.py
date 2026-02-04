"""User management tools for Dependency Track."""

from typing import Annotated

from fastmcp import FastMCP
from pydantic import Field

from dependency_track_mcp.client import get_client
from dependency_track_mcp.exceptions import DependencyTrackError
from dependency_track_mcp.scopes import Scopes


def register_user_tools(mcp: FastMCP) -> None:
    """Register user management tools."""

    @mcp.tool(
        description="List all managed users",
        tags=[Scopes.READ_USERS],
    )
    async def list_managed_users(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[int, Field(ge=1, le=100, description="Items per page")] = 100,
    ) -> dict:
        """
        List all managed (local) users.

        Managed users have credentials stored in Dependency Track.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/user/managed", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "users": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List all LDAP users",
        tags=[Scopes.READ_USERS],
    )
    async def list_ldap_users(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[int, Field(ge=1, le=100, description="Items per page")] = 100,
    ) -> dict:
        """
        List all LDAP users.

        LDAP users authenticate against an external LDAP directory.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/user/ldap", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "users": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="List all OIDC users",
        tags=[Scopes.READ_USERS],
    )
    async def list_oidc_users(
        page: Annotated[int, Field(ge=1, description="Page number")] = 1,
        page_size: Annotated[int, Field(ge=1, le=100, description="Items per page")] = 100,
    ) -> dict:
        """
        List all OpenID Connect users.

        OIDC users authenticate via an external identity provider.
        """
        try:
            client = get_client()
            params = {"pageNumber": page, "pageSize": page_size}
            data, headers = await client.get_with_headers("/user/oidc", params=params)
            total_count = headers.get("X-Total-Count", len(data))

            return {
                "users": data,
                "total": int(total_count),
                "page": page,
                "page_size": page_size,
            }
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Get information about the current logged-in user",
        tags=[Scopes.READ_USERS],
    )
    async def get_current_user() -> dict:
        """
        Get information about the currently authenticated user.
        """
        try:
            client = get_client()
            data = await client.get("/user/self")
            return {"user": data}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a new managed user",
        tags=[Scopes.READ_USERS],
    )
    async def create_managed_user(
        username: Annotated[str, Field(description="Username")],
        password: Annotated[str, Field(description="Password")],
        fullname: Annotated[str | None, Field(description="Full name")] = None,
        email: Annotated[str | None, Field(description="Email address")] = None,
        force_password_change: Annotated[
            bool, Field(description="Force password change on first login")
        ] = False,
        non_expiry_password: Annotated[bool, Field(description="Password never expires")] = False,
        suspended: Annotated[bool, Field(description="Account is suspended")] = False,
    ) -> dict:
        """
        Create a new managed (local) user.
        """
        try:
            client = get_client()
            payload = {
                "username": username,
                "newPassword": password,
                "confirmPassword": password,
                "forcePasswordChange": force_password_change,
                "nonExpiryPassword": non_expiry_password,
                "suspended": suspended,
            }

            if fullname:
                payload["fullname"] = fullname
            if email:
                payload["email"] = email

            data = await client.put("/user/managed", data=payload)
            return {"user": data, "message": "User created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Update a managed user",
        tags=[Scopes.WRITE_USERS],
    )
    async def update_managed_user(
        username: Annotated[str, Field(description="Username to update")],
        fullname: Annotated[str | None, Field(description="New full name")] = None,
        email: Annotated[str | None, Field(description="New email address")] = None,
        new_password: Annotated[str | None, Field(description="New password")] = None,
        force_password_change: Annotated[
            bool | None, Field(description="Force password change")
        ] = None,
        non_expiry_password: Annotated[
            bool | None, Field(description="Password never expires")
        ] = None,
        suspended: Annotated[bool | None, Field(description="Suspend account")] = None,
    ) -> dict:
        """
        Update a managed user's properties.
        """
        try:
            client = get_client()
            payload = {"username": username}

            if fullname is not None:
                payload["fullname"] = fullname
            if email is not None:
                payload["email"] = email
            if new_password is not None:
                payload["newPassword"] = new_password
                payload["confirmPassword"] = new_password
            if force_password_change is not None:
                payload["forcePasswordChange"] = force_password_change
            if non_expiry_password is not None:
                payload["nonExpiryPassword"] = non_expiry_password
            if suspended is not None:
                payload["suspended"] = suspended

            data = await client.post("/user/managed", data=payload)
            return {"user": data, "message": "User updated successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete a managed user",
        tags=[Scopes.WRITE_USERS],
    )
    async def delete_managed_user(
        username: Annotated[str, Field(description="Username to delete")],
    ) -> dict:
        """
        Delete a managed user.
        """
        try:
            client = get_client()
            await client.delete("/user/managed", params={"username": username})
            return {"message": f"User {username} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a reference to an existing LDAP user",
        tags=[Scopes.WRITE_USERS],
    )
    async def create_ldap_user(
        username: Annotated[str, Field(description="LDAP username (DN or sAMAccountName)")],
    ) -> dict:
        """
        Create a reference to an existing LDAP user.

        This allows an LDAP user to be assigned to teams and permissions.
        """
        try:
            client = get_client()
            payload = {"username": username}

            data = await client.put("/user/ldap", data=payload)
            return {"user": data, "message": "LDAP user created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete an LDAP user reference",
        tags=[Scopes.WRITE_USERS],
    )
    async def delete_ldap_user(
        username: Annotated[str, Field(description="LDAP username to delete")],
    ) -> dict:
        """
        Delete an LDAP user reference.
        """
        try:
            client = get_client()
            await client.delete("/user/ldap", params={"username": username})
            return {"message": f"LDAP user {username} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Create a reference to an existing OIDC user",
        tags=[Scopes.WRITE_USERS],
    )
    async def create_oidc_user(
        username: Annotated[str, Field(description="OIDC username (subject claim)")],
    ) -> dict:
        """
        Create a reference to an existing OpenID Connect user.

        This allows an OIDC user to be assigned to teams and permissions.
        """
        try:
            client = get_client()
            payload = {"username": username}

            data = await client.put("/user/oidc", data=payload)
            return {"user": data, "message": "OIDC user created successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Delete an OIDC user reference",
        tags=[Scopes.WRITE_USERS],
    )
    async def delete_oidc_user(
        username: Annotated[str, Field(description="OIDC username to delete")],
    ) -> dict:
        """
        Delete an OIDC user reference.
        """
        try:
            client = get_client()
            await client.delete("/user/oidc", params={"username": username})
            return {"message": f"OIDC user {username} deleted successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Add a user to a team",
        tags=[Scopes.WRITE_USERS],
    )
    async def add_user_to_team(
        username: Annotated[str, Field(description="Username")],
        team_uuid: Annotated[str, Field(description="Team UUID")],
    ) -> dict:
        """
        Add a user to a team.
        """
        try:
            client = get_client()
            await client.post(f"/user/{username}/membership", data={"uuid": team_uuid})
            return {"message": f"User {username} added to team successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}

    @mcp.tool(
        description="Remove a user from a team",
        tags=[Scopes.MANAGE_USER_TEAMS],
    )
    async def remove_user_from_team(
        username: Annotated[str, Field(description="Username")],
        team_uuid: Annotated[str, Field(description="Team UUID")],
    ) -> dict:
        """
        Remove a user from a team.
        """
        try:
            client = get_client()
            await client.delete(f"/user/{username}/membership", params={"uuid": team_uuid})
            return {"message": f"User {username} removed from team successfully"}
        except DependencyTrackError as e:
            return {"error": str(e), "details": e.details}
