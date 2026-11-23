"""Unit tests for individual LangGraph agent nodes."""
from codereviewgraph.graph.nodes_analysis import (
    planner_node,
    security_auditor_node,
    quality_performance_node,
)
from codereviewgraph.graph.nodes_review import (
    verification_critic_node,
    refactoring_advisor_node,
    report_compiler_node,
)


def test_planner_node_extracts_metrics():
    state = {"raw_code": "def hello():\n    return 'world'", "language": "python"}
    output = planner_node(state)
    assert output["current_stage"] == "PLANNING_COMPLETED"
    assert output["ast_summary"]["function_count"] == 1
    assert "hello" in output["ast_summary"]["functions"]


def test_security_auditor_node_detects_vulnerabilities():
    state = {
        "raw_code": "eval('import os; os.system(\"calc\")')",
        "language": "python",
        "ast_summary": {"valid_syntax": True}
    }
    output = security_auditor_node(state)
    assert output["current_stage"] == "SECURITY_AUDIT_COMPLETED"
    assert len(output["security_findings"]) >= 1


def test_quality_performance_node_detects_smells():
    state = {
        "raw_code": "try:\n    x = 1\nexcept:\n    pass",
        "language": "python"
    }
    output = quality_performance_node(state)
    assert output["current_stage"] == "QUALITY_AUDIT_COMPLETED"
    assert len(output["quality_findings"]) >= 1


def test_verification_critic_node_clean_code():
    state = {
        "raw_code": "def clean():\n    return 42",
        "security_findings": [],
        "quality_findings": [],
        "ast_summary": {"valid_syntax": True}
    }
    output = verification_critic_node(state)
    assert output["current_stage"] == "VERIFICATION_COMPLETED"
    assert output["overall_score"] == 100
    assert output["needs_refactor"] is False


def test_verification_critic_node_critical_flaw():
    state = {
        "raw_code": "eval('2+2')",
        "security_findings": [{
            "id": "SEC-002-1",
            "title": "eval",
            "severity": "CRITICAL"
        }],
        "quality_findings": [],
        "ast_summary": {"valid_syntax": True}
    }
    output = verification_critic_node(state)
    assert output["overall_score"] <= 70
    assert output["needs_refactor"] is True


def test_refactoring_advisor_node_generates_patches():
    state = {
        "raw_code": "result = eval('3+4')",
        "needs_refactor": True
    }
    output = refactoring_advisor_node(state)
    assert output["current_stage"] == "REFACTORING_COMPLETED"
    assert len(output["refactoring_patches"]) >= 1
    assert "literal_eval" in output["refactoring_patches"][0]["patched_snippet"]


def test_report_compiler_node_creates_report():
    state = {
        "raw_code": "def foo(): pass",
        "verified_findings": [],
        "refactoring_patches": [],
        "overall_score": 100,
        "ast_summary": {"lines_of_code": 1, "valid_syntax": True}
    }
    output = report_compiler_node(state)
    assert output["current_stage"] == "REVIEW_COMPLETED"
    report = output["final_report"]
    assert report["health_score"] == 100
    assert "No security or quality issues" in report["markdown_report"]
