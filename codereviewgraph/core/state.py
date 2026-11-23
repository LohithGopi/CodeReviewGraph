"""State definitions and Pydantic data models for CodeReviewGraph."""
from typing import TypedDict, List, Optional, Dict, Any
from pydantic import BaseModel, Field


class FindingSeverity:
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingCategory:
    SECURITY = "SECURITY"
    CODE_QUALITY = "CODE_QUALITY"
    PERFORMANCE = "PERFORMANCE"
    COMPLEXITY = "COMPLEXITY"


class AuditFinding(BaseModel):
    """Normalized finding from an agent audit node."""
    id: str = Field(description="Unique finding identifier")
    category: str = Field(description="SECURITY, CODE_QUALITY, PERFORMANCE, etc.")
    title: str = Field(description="Brief summary of finding")
    severity: str = Field(description="INFO, LOW, MEDIUM, HIGH, CRITICAL")
    line_number: Optional[int] = Field(default=None, description="1-based line number")
    cwe: Optional[str] = Field(default=None, description="Common Weakness Enumeration ID")
    description: str = Field(description="Detailed explanation of the issue")
    remediation: str = Field(description="Recommended fix or pattern")
    snippet: Optional[str] = Field(default=None, description="Code snippet where issue occurred")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Verification confidence")


class RefactoringPatch(BaseModel):
    """Drop-in remediation patch generated for verified flaws."""
    finding_id: str
    file_path: Optional[str] = None
    target_lines: Optional[str] = None
    original_snippet: str
    patched_snippet: str
    explanation: str


class AuditReport(BaseModel):
    """Final aggregated audit report."""
    summary: str
    health_score: int = Field(ge=0, le=100)
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    findings: List[AuditFinding]
    patches: List[RefactoringPatch]
    ast_metrics: Dict[str, Any]
    markdown_report: str


class CodeReviewState(TypedDict, total=False):
    """LangGraph state passed between nodes in the review workflow."""
    raw_code: str
    file_path: Optional[str]
    language: str
    ast_summary: Dict[str, Any]
    security_findings: List[Dict[str, Any]]
    quality_findings: List[Dict[str, Any]]
    verified_findings: List[Dict[str, Any]]
    overall_score: int
    needs_refactor: bool
    refactoring_patches: List[Dict[str, Any]]
    final_report: Optional[Dict[str, Any]]
    current_stage: str
    error: Optional[str]
