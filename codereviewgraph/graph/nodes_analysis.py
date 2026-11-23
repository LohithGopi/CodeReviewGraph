"""Analysis nodes for CodeReviewGraph: Planner, Security Auditor, and Quality/Performance."""
import json
from langchain_core.messages import HumanMessage
from codereviewgraph.core.state import CodeReviewState
from codereviewgraph.core.security_rules import analyze_ast, scan_security_rules, scan_quality_rules
from codereviewgraph.core.models import get_chat_model


def planner_node(state: CodeReviewState) -> CodeReviewState:
    """Triage and planning node: extracts AST metrics and structures the review tasks."""
    code = state.get("raw_code", "")
    language = state.get("language", "python")
    
    ast_metrics = analyze_ast(code) if language.lower() == "python" else {
        "valid_syntax": True,
        "lines_of_code": len(code.splitlines()),
        "function_count": 0,
        "class_count": 0,
        "import_count": 0,
        "functions": [],
        "classes": []
    }

    return {
        "raw_code": code,
        "language": language,
        "ast_summary": ast_metrics,
        "current_stage": "PLANNING_COMPLETED",
        "security_findings": [],
        "quality_findings": [],
        "verified_findings": [],
        "refactoring_patches": []
    }


def security_auditor_node(state: CodeReviewState) -> CodeReviewState:
    """Security node: identifies OWASP vulnerabilities, injection risks, and secret leaks."""
    code = state.get("raw_code", "")
    model = get_chat_model()
    
    prompt = (
        "TASK: SECURITY_AUDIT\n"
        "Analyze the following code for security vulnerabilities, injection flaws, and exposed credentials:\n"
        f"```python\n{code}\n```"
    )
    
    response = model.invoke([HumanMessage(content=prompt)])
    findings = []
    
    try:
        data = json.loads(str(response.content))
        if isinstance(data, dict) and "findings" in data:
            findings = data["findings"]
    except Exception:
        # Fallback to direct pattern scan
        findings = scan_security_rules(code)

    return {
        **state,
        "security_findings": findings,
        "current_stage": "SECURITY_AUDIT_COMPLETED"
    }


def quality_performance_node(state: CodeReviewState) -> CodeReviewState:
    """Quality & performance node: evaluates maintainability, complexity, and smells."""
    code = state.get("raw_code", "")
    model = get_chat_model()
    
    prompt = (
        "TASK: QUALITY_AUDIT\n"
        "Evaluate the following code for code smells, error handling quality, and anti-patterns:\n"
        f"```python\n{code}\n```"
    )
    
    response = model.invoke([HumanMessage(content=prompt)])
    findings = []
    
    try:
        data = json.loads(str(response.content))
        if isinstance(data, dict) and "findings" in data:
            findings = data["findings"]
    except Exception:
        findings = scan_quality_rules(code)

    return {
        **state,
        "quality_findings": findings,
        "current_stage": "QUALITY_AUDIT_COMPLETED"
    }
