"""MCP scopes for Dependency Track operations."""


class Scopes:
    """MCP scopes for Dependency Track operations.

    These scopes provide fine-grained access control for the MCP tools.
    """

    READ_PROJECTS = "read:projects"
    WRITE_PROJECTS = "write:projects"
    READ_COMPONENTS = "read:components"
    READ_VULNERABILITIES = "read:vulnerabilities"
    WRITE_ANALYSIS = "write:analysis"
    READ_METRICS = "read:metrics"
    READ_POLICIES = "read:policies"
    UPLOAD_BOM = "upload:bom"
    SEARCH = "search"


# List of all available scopes for documentation
ALL_SCOPES = [
    Scopes.READ_PROJECTS,
    Scopes.WRITE_PROJECTS,
    Scopes.READ_COMPONENTS,
    Scopes.READ_VULNERABILITIES,
    Scopes.WRITE_ANALYSIS,
    Scopes.READ_METRICS,
    Scopes.READ_POLICIES,
    Scopes.UPLOAD_BOM,
    Scopes.SEARCH,
]
