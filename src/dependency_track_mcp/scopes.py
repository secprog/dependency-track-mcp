"""MCP scopes for Dependency Track operations."""


class Scopes:
    """MCP scopes for Dependency Track operations.

    These scopes provide fine-grained access control for the MCP tools.
    """

    # Project scopes
    READ_PROJECTS = "read:projects"
    WRITE_PROJECTS = "write:projects"

    # Component scopes
    READ_COMPONENTS = "read:components"
    WRITE_COMPONENTS = "write:components"

    # Vulnerability scopes
    READ_VULNERABILITIES = "read:vulnerabilities"
    WRITE_VULNERABILITIES = "write:vulnerabilities"

    # Analysis scopes
    WRITE_ANALYSIS = "write:analysis"

    # Metrics scopes
    READ_METRICS = "read:metrics"

    # Policy scopes
    READ_POLICIES = "read:policies"
    WRITE_POLICIES = "write:policies"

    # BOM/VEX scopes
    UPLOAD_BOM = "upload:bom"
    UPLOAD_VEX = "upload:vex"

    # Search scope
    SEARCH = "search"

    # License scopes
    READ_LICENSES = "read:licenses"
    WRITE_LICENSES = "write:licenses"

    # Tag scopes
    READ_TAGS = "read:tags"
    WRITE_TAGS = "write:tags"

    # Service scopes
    READ_SERVICES = "read:services"
    WRITE_SERVICES = "write:services"

    # Repository scopes
    READ_REPOSITORIES = "read:repositories"
    WRITE_REPOSITORIES = "write:repositories"

    # CWE scope (read-only reference data)
    READ_CWE = "read:cwe"

    # Team management scopes (more granular than admin:teams)
    READ_TEAMS = "read:teams"
    WRITE_TEAMS = "write:teams"
    MANAGE_API_KEYS = "manage:api-keys"  # Generate, regenerate, delete API keys

    # User management scopes (more granular than admin:users)
    READ_USERS = "read:users"
    WRITE_USERS = "write:users"  # Create, update, delete users
    MANAGE_USER_TEAMS = "manage:user-teams"  # Add/remove users from teams

    # Permission management scopes (separate from general admin)
    READ_PERMISSIONS = "read:permissions"
    WRITE_PERMISSIONS = "write:permissions"  # Grant/revoke permissions

    # ACL scopes (project-level access control)
    READ_ACL = "read:acl"
    WRITE_ACL = "write:acl"  # Add/remove ACL mappings

    # Notification management scopes
    READ_NOTIFICATIONS = "read:notifications"
    WRITE_NOTIFICATION_PUBLISHERS = "write:notification-publishers"  # CRUD publishers
    WRITE_NOTIFICATION_RULES = "write:notification-rules"  # CRUD rules
    TEST_NOTIFICATIONS = "test:notifications"  # Send test notifications

    # LDAP integration scopes
    READ_LDAP = "read:ldap"  # List LDAP groups
    WRITE_LDAP = "write:ldap"  # Manage LDAP group mappings

    # OIDC integration scopes
    READ_OIDC = "read:oidc"  # Check availability, list groups
    WRITE_OIDC = "write:oidc"  # Manage OIDC groups and mappings

    # Configuration management scopes
    READ_CONFIG = "read:config"  # View config properties
    WRITE_CONFIG = "write:config"  # Modify system configuration

    # System scopes (read-only, low privilege)
    SYSTEM_VERSION = "system:version"
    SYSTEM_BADGES = "system:badges"
    SYSTEM_CALCULATOR = "system:calculator"


# List of all available scopes for documentation
ALL_SCOPES = [
    # Core functionality
    Scopes.READ_PROJECTS,
    Scopes.WRITE_PROJECTS,
    Scopes.READ_COMPONENTS,
    Scopes.WRITE_COMPONENTS,
    Scopes.READ_VULNERABILITIES,
    Scopes.WRITE_VULNERABILITIES,
    Scopes.WRITE_ANALYSIS,
    Scopes.READ_METRICS,
    Scopes.READ_POLICIES,
    Scopes.WRITE_POLICIES,
    Scopes.UPLOAD_BOM,
    Scopes.UPLOAD_VEX,
    Scopes.SEARCH,
    # Reference data
    Scopes.READ_LICENSES,
    Scopes.WRITE_LICENSES,
    Scopes.READ_TAGS,
    Scopes.WRITE_TAGS,
    Scopes.READ_SERVICES,
    Scopes.WRITE_SERVICES,
    Scopes.READ_REPOSITORIES,
    Scopes.WRITE_REPOSITORIES,
    Scopes.READ_CWE,
    # Team management
    Scopes.READ_TEAMS,
    Scopes.WRITE_TEAMS,
    Scopes.MANAGE_API_KEYS,
    # User management
    Scopes.READ_USERS,
    Scopes.WRITE_USERS,
    Scopes.MANAGE_USER_TEAMS,
    # Permission management
    Scopes.READ_PERMISSIONS,
    Scopes.WRITE_PERMISSIONS,
    # ACL management
    Scopes.READ_ACL,
    Scopes.WRITE_ACL,
    # Notification management
    Scopes.READ_NOTIFICATIONS,
    Scopes.WRITE_NOTIFICATION_PUBLISHERS,
    Scopes.WRITE_NOTIFICATION_RULES,
    Scopes.TEST_NOTIFICATIONS,
    # LDAP integration
    Scopes.READ_LDAP,
    Scopes.WRITE_LDAP,
    # OIDC integration
    Scopes.READ_OIDC,
    Scopes.WRITE_OIDC,
    # Configuration management
    Scopes.READ_CONFIG,
    Scopes.WRITE_CONFIG,
    # System (read-only)
    Scopes.SYSTEM_VERSION,
    Scopes.SYSTEM_BADGES,
    Scopes.SYSTEM_CALCULATOR,
]
