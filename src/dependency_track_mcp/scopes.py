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

    # Administrative scopes
    ADMIN_CONFIG = "admin:config"
    ADMIN_TEAMS = "admin:teams"
    ADMIN_USERS = "admin:users"
    ADMIN_PERMISSIONS = "admin:permissions"
    ADMIN_ACL = "admin:acl"
    ADMIN_NOTIFICATIONS = "admin:notifications"
    ADMIN_LDAP = "admin:ldap"
    ADMIN_OIDC = "admin:oidc"

    # System scopes
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
    # Administrative
    Scopes.ADMIN_CONFIG,
    Scopes.ADMIN_TEAMS,
    Scopes.ADMIN_USERS,
    Scopes.ADMIN_PERMISSIONS,
    Scopes.ADMIN_ACL,
    Scopes.ADMIN_NOTIFICATIONS,
    Scopes.ADMIN_LDAP,
    Scopes.ADMIN_OIDC,
    # System
    Scopes.SYSTEM_VERSION,
    Scopes.SYSTEM_BADGES,
    Scopes.SYSTEM_CALCULATOR,
]
