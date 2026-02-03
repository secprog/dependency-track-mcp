"""Pydantic models for Dependency Track API."""

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# Enums
class Severity(str, Enum):
    """Vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNASSIGNED = "UNASSIGNED"


class AnalysisState(str, Enum):
    """Analysis state for findings."""

    NOT_SET = "NOT_SET"
    EXPLOITABLE = "EXPLOITABLE"
    IN_TRIAGE = "IN_TRIAGE"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    NOT_AFFECTED = "NOT_AFFECTED"


class AnalysisJustification(str, Enum):
    """Justification for analysis decisions."""

    NOT_SET = "NOT_SET"
    CODE_NOT_PRESENT = "CODE_NOT_PRESENT"
    CODE_NOT_REACHABLE = "CODE_NOT_REACHABLE"
    REQUIRES_CONFIGURATION = "REQUIRES_CONFIGURATION"
    REQUIRES_DEPENDENCY = "REQUIRES_DEPENDENCY"
    REQUIRES_ENVIRONMENT = "REQUIRES_ENVIRONMENT"
    PROTECTED_BY_COMPILER = "PROTECTED_BY_COMPILER"
    PROTECTED_AT_RUNTIME = "PROTECTED_AT_RUNTIME"
    PROTECTED_AT_PERIMETER = "PROTECTED_AT_PERIMETER"
    PROTECTED_BY_MITIGATING_CONTROL = "PROTECTED_BY_MITIGATING_CONTROL"


class AnalysisResponse(str, Enum):
    """Response type for analysis."""

    NOT_SET = "NOT_SET"
    CAN_NOT_FIX = "CAN_NOT_FIX"
    WILL_NOT_FIX = "WILL_NOT_FIX"
    UPDATE = "UPDATE"
    ROLLBACK = "ROLLBACK"
    WORKAROUND_AVAILABLE = "WORKAROUND_AVAILABLE"


class ViolationState(str, Enum):
    """Policy violation state."""

    INFO = "INFO"
    WARN = "WARN"
    FAIL = "FAIL"


class PolicyViolationType(str, Enum):
    """Type of policy violation."""

    LICENSE = "LICENSE"
    SECURITY = "SECURITY"
    OPERATIONAL = "OPERATIONAL"


# Base Models
class Tag(BaseModel):
    """Project/component tag."""

    name: str


class License(BaseModel):
    """License information."""

    uuid: str | None = None
    licenseId: str | None = None
    name: str | None = None
    spdxLicenseId: str | None = None


# Project Models
class Project(BaseModel):
    """Dependency Track project."""

    uuid: str
    name: str
    version: str | None = None
    description: str | None = None
    classifier: str | None = None
    active: bool = True
    tags: list[Tag] = Field(default_factory=list)
    lastBomImport: datetime | None = None
    lastBomImportFormat: str | None = None
    lastInheritedRiskScore: float | None = None
    metrics: dict[str, Any] | None = None


class ProjectCreate(BaseModel):
    """Create project request."""

    name: str
    version: str | None = None
    description: str | None = None
    classifier: str | None = None
    active: bool = True
    tags: list[str] = Field(default_factory=list)
    parent: str | None = Field(None, description="Parent project UUID")


# Component Models
class Component(BaseModel):
    """Software component."""

    uuid: str
    name: str
    version: str | None = None
    group: str | None = None
    description: str | None = None
    purl: str | None = None
    cpe: str | None = None
    license: str | None = None
    resolvedLicense: License | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    sha512: str | None = None


# Vulnerability Models
class Vulnerability(BaseModel):
    """Security vulnerability."""

    uuid: str
    vulnId: str
    source: str
    title: str | None = None
    description: str | None = None
    severity: Severity | None = None
    severityRank: int | None = None
    cvssV2BaseScore: float | None = None
    cvssV3BaseScore: float | None = None
    cwes: list[dict[str, Any]] = Field(default_factory=list)
    recommendation: str | None = None
    published: datetime | None = None
    updated: datetime | None = None


# Finding Models
class Analysis(BaseModel):
    """Analysis decision for a finding."""

    state: AnalysisState | None = None
    justification: AnalysisJustification | None = None
    response: AnalysisResponse | None = None
    details: str | None = None
    comments: list[dict[str, Any]] = Field(default_factory=list)
    isSuppressed: bool = False


class Finding(BaseModel):
    """Security finding (component + vulnerability)."""

    component: Component
    vulnerability: Vulnerability
    analysis: Analysis | None = None
    attribution: dict[str, Any] | None = None
    matrix: str | None = None


# Metrics Models
class PortfolioMetrics(BaseModel):
    """Portfolio-wide metrics."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unassigned: int = 0
    vulnerabilities: int = 0
    vulnerableComponents: int = 0
    components: int = 0
    suppressed: int = 0
    findingsTotal: int = 0
    findingsAudited: int = 0
    findingsUnaudited: int = 0
    inheritedRiskScore: float = 0.0
    policyViolationsFail: int = 0
    policyViolationsWarn: int = 0
    policyViolationsInfo: int = 0
    policyViolationsTotal: int = 0
    policyViolationsAudited: int = 0
    policyViolationsUnaudited: int = 0
    policyViolationsSecurityTotal: int = 0
    policyViolationsSecurityAudited: int = 0
    policyViolationsSecurityUnaudited: int = 0
    policyViolationsLicenseTotal: int = 0
    policyViolationsLicenseAudited: int = 0
    policyViolationsLicenseUnaudited: int = 0
    policyViolationsOperationalTotal: int = 0
    policyViolationsOperationalAudited: int = 0
    policyViolationsOperationalUnaudited: int = 0


class ProjectMetrics(PortfolioMetrics):
    """Project-specific metrics."""

    project: dict[str, Any] | None = None
    firstOccurrence: datetime | None = None
    lastOccurrence: datetime | None = None


# Policy Models
class PolicyCondition(BaseModel):
    """Policy condition that was violated."""

    uuid: str
    subject: str | None = None
    operator: str | None = None
    value: str | None = None


class Policy(BaseModel):
    """Security policy."""

    uuid: str
    name: str
    violationState: ViolationState | None = None


class PolicyViolation(BaseModel):
    """Policy violation record."""

    uuid: str
    type: PolicyViolationType
    component: Component | None = None
    project: Project | None = None
    policyCondition: PolicyCondition | None = None
    timestamp: datetime | None = None
    text: str | None = None


# BOM Models
class BomUploadResponse(BaseModel):
    """Response from BOM upload."""

    token: str


class BomProcessingStatus(BaseModel):
    """BOM processing status."""

    processing: bool


# Search Models
class SearchResult(BaseModel):
    """Search result item."""

    uuid: str
    name: str | None = None
    version: str | None = None
    group: str | None = None
    description: str | None = None


# Analysis Request Models
class AnalysisRequest(BaseModel):
    """Request to update analysis."""

    project: str = Field(..., description="Project UUID")
    component: str = Field(..., description="Component UUID")
    vulnerability: str = Field(..., description="Vulnerability UUID")
    analysisState: AnalysisState | None = None
    analysisJustification: AnalysisJustification | None = None
    analysisResponse: AnalysisResponse | None = None
    analysisDetails: str | None = None
    comment: str | None = None
    isSuppressed: bool | None = None
