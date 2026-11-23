"""End-to-end integration tests for the LangGraph workflow and conditional routing."""
from codereviewgraph.graph.workflow import create_code_review_graph


def test_workflow_clean_code_bypasses_refactor():
    """Verify that clean code receives score 100 and bypasses refactoring node."""
    app = create_code_review_graph()
    clean_code = """
def add_numbers(x: int, y: int) -> int:
    \"\"\"Add two integers cleanly.\"\"\"
    return x + y
"""
    result = app.invoke(
        {"raw_code": clean_code, "language": "python"},
        config={"configurable": {"thread_id": "test-clean-run"}}
    )
    
    assert result["current_stage"] == "REVIEW_COMPLETED"
    assert result["overall_score"] == 100
    assert result["needs_refactor"] is False
    assert len(result["refactoring_patches"]) == 0
    
    report = result["final_report"]
    assert report is not None
    assert report["health_score"] == 100
    assert report["total_findings"] == 0


def test_workflow_critical_vulnerability_routes_to_refactor():
    """Verify that code with critical SQLi and eval flaws triggers the refactor node."""
    app = create_code_review_graph()
    vulnerable_code = """
import sqlite3

def get_user_profile(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    db = sqlite3.connect(":memory:")
    cursor = db.cursor()
    cursor.execute(query)
    eval(user_input)
    return cursor.fetchall()
"""
    result = app.invoke(
        {"raw_code": vulnerable_code, "language": "python"},
        config={"configurable": {"thread_id": "test-vuln-run"}}
    )
    
    assert result["current_stage"] == "REVIEW_COMPLETED"
    assert result["needs_refactor"] is True
    assert result["overall_score"] < 60
    assert len(result["verified_findings"]) >= 2
    assert len(result["refactoring_patches"]) >= 1

    report = result["final_report"]
    assert report["critical_count"] >= 1
    assert "AUTOMATED REMEDIATION PATCHES" in report["markdown_report"].upper()
