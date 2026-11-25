"""Review, reflection, refactoring, and report compilation nodes for CodeReviewGraph."""
from langchain_core.messages import HumanMessage
from codereviewgraph.core.state import CodeReviewState, FindingSeverity
from codereviewgraph.core.models import get_chat_model, parse_llm_json


def verification_critic_node(state: CodeReviewState) -> CodeReviewState:
    """Reflection and verification node: cross-verifies findings, computes score, determines refactor need."""
    security_findings = state.get("security_findings", [])
    quality_findings = state.get("quality_findings", [])
    ast_summary = state.get("ast_summary", {})
    
    # Merge and deduplicate findings
    all_findings = []
    seen_ids = set()
    for f in (security_findings + quality_findings):
        f_id = f.get("id")
        if f_id not in seen_ids:
            seen_ids.add(f_id)
            all_findings.append(f)

    # Calculate penalty scores
    # Score starts at 100
    score = 100
    has_critical = False
    
    for f in all_findings:
        sev = f.get("severity", "").upper()
        if sev == FindingSeverity.CRITICAL:
            score -= 30
            has_critical = True
        elif sev == FindingSeverity.HIGH:
            score -= 15
            has_critical = True
        elif sev == FindingSeverity.MEDIUM:
            score -= 8
        elif sev == FindingSeverity.LOW:
            score -= 3
        elif sev == FindingSeverity.INFO:
            score -= 1

    if not ast_summary.get("valid_syntax", True):
        has_critical = True

    overall_score = max(0, min(100, score))
    needs_refactor = has_critical and len(all_findings) > 0

    return {
        **state,
        "verified_findings": all_findings,
        "overall_score": overall_score,
        "needs_refactor": needs_refactor,
        "current_stage": "VERIFICATION_COMPLETED"
    }


def refactoring_advisor_node(state: CodeReviewState) -> CodeReviewState:
    """Refactoring node: generates drop-in remediation patches for critical and high vulnerabilities."""
    code = state.get("raw_code", "")
    language = state.get("language", "python")
    model = get_chat_model()
    
    prompt = (
        "TASK: GENERATE_PATCH\n"
        "Generate drop-in remediation patches for the following vulnerable code:\n"
        f"```{language}\n{code}\n```"
    )
    
    response = model.invoke([HumanMessage(content=prompt)])
    patches = []
    
    try:
        data = parse_llm_json(response.content)
        if "patches" in data:
            patches = data["patches"]
    except Exception:
        patches = []

    return {
        **state,
        "refactoring_patches": patches,
        "current_stage": "REFACTORING_COMPLETED"
    }


def report_compiler_node(state: CodeReviewState) -> CodeReviewState:
    """Report compilation node: generates structured summary and markdown report."""
    findings = state.get("verified_findings", [])
    patches = state.get("refactoring_patches", [])
    score = state.get("overall_score", 100)
    ast_summary = state.get("ast_summary", {})
    code = state.get("raw_code", "")
    
    severities = [str(f.get("severity") or "").upper() for f in findings]
    crit_count = sum(1 for s in severities if s == FindingSeverity.CRITICAL)
    high_count = sum(1 for s in severities if s == FindingSeverity.HIGH)
    med_count = sum(1 for s in severities if s == FindingSeverity.MEDIUM)
    low_count = sum(1 for s in severities if s in (FindingSeverity.LOW, FindingSeverity.INFO))
    
    # Generate Markdown Report
    lines = [
        "# CodeReviewGraph Audit Report",
        "",
        f"**Health Score:** {score}/100",
        f"**Total Findings:** {len(findings)} (Critical: {crit_count}, High: {high_count}, Medium: {med_count}, Low/Info: {low_count})",
        f"**Lines of Code:** {ast_summary.get('lines_of_code', len(code.splitlines()))}",
        f"**Syntax Valid:** {ast_summary.get('valid_syntax', True)}",
        "",
        "## Summary of Findings",
    ]
    
    if not findings:
        lines.append("✅ No security or quality issues detected. Code is in good standing.")
    else:
        for f in findings:
            sev_badge = f"[{f.get('severity')}]"
            lines.append(f"### {sev_badge} {f.get('title')}")
            lines.append(f"- **ID:** `{f.get('id')}`")
            lines.append(f"- **Category:** {f.get('category')}")
            if f.get("line_number"):
                lines.append(f"- **Line:** {f.get('line_number')}")
            if f.get("cwe"):
                lines.append(f"- **CWE:** {f.get('cwe')}")
            lines.append(f"- **Description:** {f.get('description')}")
            lines.append(f"- **Remediation:** {f.get('remediation')}")
            if f.get("snippet"):
                lines.append(f"```python\n{f.get('snippet')}\n```")
            lines.append("")

    if patches:
        lines.append("## Automated Remediation Patches")
        for p in patches:
            lines.append(f"### Patch for `{p.get('finding_id')}`")
            lines.append(f"**Explanation:** {p.get('explanation')}")
            lines.append("```python")
            lines.append(f"# Original:\n{p.get('original_snippet')}")
            lines.append(f"# Patched:\n{p.get('patched_snippet')}")
            lines.append("```")
            lines.append("")

    markdown_report = "\n".join(lines)
    
    final_report = {
        "summary": f"Audit completed with health score {score}/100 and {len(findings)} findings.",
        "health_score": score,
        "total_findings": len(findings),
        "critical_count": crit_count,
        "high_count": high_count,
        "medium_count": med_count,
        "low_count": low_count,
        "findings": findings,
        "patches": patches,
        "ast_metrics": ast_summary,
        "markdown_report": markdown_report
    }

    return {
        **state,
        "final_report": final_report,
        "current_stage": "REVIEW_COMPLETED"
    }
