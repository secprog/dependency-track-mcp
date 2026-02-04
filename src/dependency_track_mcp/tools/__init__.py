"""Dependency Track MCP Tools."""

from dependency_track_mcp.tools.acl import register_acl_tools
from dependency_track_mcp.tools.badges import register_badge_tools
from dependency_track_mcp.tools.bom import register_bom_tools
from dependency_track_mcp.tools.calculator import register_calculator_tools
from dependency_track_mcp.tools.component_properties import register_component_property_tools
from dependency_track_mcp.tools.components import register_component_tools
from dependency_track_mcp.tools.config_properties import register_config_property_tools
from dependency_track_mcp.tools.cwe import register_cwe_tools
from dependency_track_mcp.tools.events import register_event_tools
from dependency_track_mcp.tools.findings import register_finding_tools
from dependency_track_mcp.tools.integrations import register_integration_tools
from dependency_track_mcp.tools.ldap import register_ldap_tools
from dependency_track_mcp.tools.license_groups import register_license_group_tools
from dependency_track_mcp.tools.licenses import register_license_tools
from dependency_track_mcp.tools.metrics import register_metrics_tools
from dependency_track_mcp.tools.notifications import register_notification_tools
from dependency_track_mcp.tools.oidc import register_oidc_tools
from dependency_track_mcp.tools.permissions import register_permission_tools
from dependency_track_mcp.tools.policies import register_policy_tools
from dependency_track_mcp.tools.project_properties import register_project_property_tools
from dependency_track_mcp.tools.projects import register_project_tools
from dependency_track_mcp.tools.repositories import register_repository_tools
from dependency_track_mcp.tools.search import register_search_tools
from dependency_track_mcp.tools.services import register_service_tools
from dependency_track_mcp.tools.tags import register_tag_tools
from dependency_track_mcp.tools.teams import register_team_tools
from dependency_track_mcp.tools.users import register_user_tools
from dependency_track_mcp.tools.version import register_version_tools
from dependency_track_mcp.tools.vex import register_vex_tools
from dependency_track_mcp.tools.vulnerabilities import register_vulnerability_tools


def register_all_tools(mcp):
    """Register all Dependency Track tools with the MCP server."""
    # Core SCA tools
    register_project_tools(mcp)
    register_component_tools(mcp)
    register_vulnerability_tools(mcp)
    register_finding_tools(mcp)
    register_metrics_tools(mcp)
    register_policy_tools(mcp)
    register_bom_tools(mcp)
    register_search_tools(mcp)
    # Reference data
    register_license_tools(mcp)
    register_license_group_tools(mcp)
    register_tag_tools(mcp)
    register_cwe_tools(mcp)
    register_repository_tools(mcp)
    register_service_tools(mcp)
    register_vex_tools(mcp)
    # Properties
    register_project_property_tools(mcp)
    register_component_property_tools(mcp)
    register_config_property_tools(mcp)
    # Administrative
    register_team_tools(mcp)
    register_user_tools(mcp)
    register_permission_tools(mcp)
    register_acl_tools(mcp)
    register_notification_tools(mcp)
    register_ldap_tools(mcp)
    register_oidc_tools(mcp)
    # System / Integration
    register_version_tools(mcp)
    register_badge_tools(mcp)
    register_calculator_tools(mcp)
    register_integration_tools(mcp)
    register_event_tools(mcp)
