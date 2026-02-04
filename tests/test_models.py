"""Tests for Pydantic models."""

import pytest
from pydantic import ValidationError

from dependency_track_mcp.models import (
    Analysis,
    AnalysisJustification,
    AnalysisResponse,
    AnalysisState,
    BomProcessingStatus,
    BomUploadResponse,
    Component,
    Finding,
    License,
    PolicyViolationType,
    PortfolioMetrics,
    Project,
    ProjectMetrics,
    Severity,
    Tag,
    ViolationState,
    Vulnerability,
)


class TestEnums:
    """Tests for enum definitions."""

    def test_severity_enum_values(self):
        """Test Severity enum has all required values."""
        assert Severity.CRITICAL.value == "CRITICAL"
        assert Severity.HIGH.value == "HIGH"
        assert Severity.MEDIUM.value == "MEDIUM"
        assert Severity.LOW.value == "LOW"
        assert Severity.INFO.value == "INFO"
        assert Severity.UNASSIGNED.value == "UNASSIGNED"

    def test_analysis_state_enum_values(self):
        """Test AnalysisState enum has all required values."""
        assert AnalysisState.NOT_SET.value == "NOT_SET"
        assert AnalysisState.EXPLOITABLE.value == "EXPLOITABLE"
        assert AnalysisState.IN_TRIAGE.value == "IN_TRIAGE"
        assert AnalysisState.RESOLVED.value == "RESOLVED"
        assert AnalysisState.FALSE_POSITIVE.value == "FALSE_POSITIVE"
        assert AnalysisState.NOT_AFFECTED.value == "NOT_AFFECTED"

    def test_analysis_justification_enum_values(self):
        """Test AnalysisJustification enum has all required values."""
        assert AnalysisJustification.NOT_SET.value == "NOT_SET"
        assert AnalysisJustification.CODE_NOT_PRESENT.value == "CODE_NOT_PRESENT"

    def test_analysis_response_enum_values(self):
        """Test AnalysisResponse enum has all required values."""
        assert AnalysisResponse.NOT_SET.value == "NOT_SET"
        assert AnalysisResponse.CAN_NOT_FIX.value == "CAN_NOT_FIX"
        assert AnalysisResponse.WILL_NOT_FIX.value == "WILL_NOT_FIX"

    def test_violation_state_enum_values(self):
        """Test ViolationState enum has all required values."""
        assert ViolationState.INFO.value == "INFO"
        assert ViolationState.WARN.value == "WARN"
        assert ViolationState.FAIL.value == "FAIL"

    def test_policy_violation_type_enum_values(self):
        """Test PolicyViolationType enum has all required values."""
        assert PolicyViolationType.LICENSE.value == "LICENSE"
        assert PolicyViolationType.SECURITY.value == "SECURITY"
        assert PolicyViolationType.OPERATIONAL.value == "OPERATIONAL"


class TestTag:
    """Tests for Tag model."""

    def test_tag_creation(self):
        """Test creating a Tag."""
        tag = Tag(name="production")
        assert tag.name == "production"

    def test_tag_required_name(self):
        """Test that name is required."""
        with pytest.raises(ValidationError):
            Tag()


class TestLicense:
    """Tests for License model."""

    def test_license_creation_full(self):
        """Test creating License with all fields."""
        license_obj = License(
            uuid="uuid-123",
            licenseId="MIT",
            name="MIT License",
            spdxLicenseId="MIT",
        )
        assert license_obj.uuid == "uuid-123"
        assert license_obj.licenseId == "MIT"
        assert license_obj.name == "MIT License"

    def test_license_creation_partial(self):
        """Test creating License with optional fields."""
        license_obj = License()
        assert license_obj.uuid is None
        assert license_obj.name is None


class TestProject:
    """Tests for Project model."""

    def test_project_creation(self):
        """Test creating a Project."""
        project = Project(
            uuid="proj-123",
            name="Test Project",
            version="1.0.0",
            description="A test project",
        )
        assert project.uuid == "proj-123"
        assert project.name == "Test Project"
        assert project.active is True

    def test_project_required_fields(self):
        """Test that uuid and name are required."""
        with pytest.raises(ValidationError):
            Project()

    def test_project_with_tags(self):
        """Test Project with tags."""
        project = Project(
            uuid="proj-123",
            name="Test Project",
            tags=[Tag(name="prod"), Tag(name="critical")],
        )
        assert len(project.tags) == 2


class TestComponent:
    """Tests for Component model."""

    def test_component_creation(self):
        """Test creating a Component."""
        component = Component(
            uuid="comp-123",
            name="lodash",
            version="4.17.21",
            purl="pkg:npm/lodash@4.17.21",
        )
        assert component.uuid == "comp-123"
        assert component.name == "lodash"

    def test_component_required_fields(self):
        """Test that uuid and name are required."""
        with pytest.raises(ValidationError):
            Component()


class TestVulnerability:
    """Tests for Vulnerability model."""

    def test_vulnerability_creation(self):
        """Test creating a Vulnerability."""
        vuln = Vulnerability(
            uuid="vuln-123",
            vulnId="CVE-2021-44228",
            source="NVD",
            title="Log4Shell",
            severity=Severity.CRITICAL,
        )
        assert vuln.uuid == "vuln-123"
        assert vuln.vulnId == "CVE-2021-44228"
        assert vuln.severity == Severity.CRITICAL

    def test_vulnerability_required_fields(self):
        """Test required fields for Vulnerability."""
        with pytest.raises(ValidationError):
            Vulnerability()


class TestAnalysis:
    """Tests for Analysis model."""

    def test_analysis_creation(self):
        """Test creating an Analysis."""
        analysis = Analysis(
            state=AnalysisState.RESOLVED,
            justification=AnalysisJustification.CODE_NOT_PRESENT,
        )
        assert analysis.state == AnalysisState.RESOLVED
        assert analysis.isSuppressed is False

    def test_analysis_all_optional(self):
        """Test that all Analysis fields are optional."""
        analysis = Analysis()
        assert analysis.state is None
        assert analysis.isSuppressed is False


class TestFinding:
    """Tests for Finding model."""

    def test_finding_creation(self):
        """Test creating a Finding."""
        component = Component(uuid="comp-123", name="lodash")
        vuln = Vulnerability(uuid="vuln-123", vulnId="CVE-2021-44228", source="NVD")
        finding = Finding(component=component, vulnerability=vuln)
        assert finding.component.uuid == "comp-123"
        assert finding.vulnerability.vulnId == "CVE-2021-44228"


class TestPortfolioMetrics:
    """Tests for PortfolioMetrics model."""

    def test_portfolio_metrics_creation(self):
        """Test creating PortfolioMetrics."""
        metrics = PortfolioMetrics(
            critical=5,
            high=10,
            medium=20,
            vulnerabilities=35,
        )
        assert metrics.critical == 5
        assert metrics.high == 10
        assert metrics.vulnerabilities == 35

    def test_portfolio_metrics_defaults(self):
        """Test PortfolioMetrics default values."""
        metrics = PortfolioMetrics()
        assert metrics.critical == 0
        assert metrics.vulnerabilities == 0
        assert metrics.inheritedRiskScore == 0.0


class TestProjectMetrics:
    """Tests for ProjectMetrics model."""

    def test_project_metrics_creation(self):
        """Test creating ProjectMetrics."""
        metrics = ProjectMetrics(
            critical=5,
            high=10,
        )
        assert metrics.critical == 5
        assert isinstance(metrics, PortfolioMetrics)


class TestBomUploadResponse:
    """Tests for BomUploadResponse model."""

    def test_bom_upload_response(self):
        """Test creating BomUploadResponse."""
        response = BomUploadResponse(token="token-123")
        assert response.token == "token-123"


class TestBomProcessingStatus:
    """Tests for BomProcessingStatus model."""

    def test_bom_processing_status_processing(self):
        """Test BomProcessingStatus when processing."""
        status = BomProcessingStatus(processing=True)
        assert status.processing is True

    def test_bom_processing_status_complete(self):
        """Test BomProcessingStatus when complete."""
        status = BomProcessingStatus(processing=False)
        assert status.processing is False
