"""Unit tests for AST analysis, security rules, and deterministic model."""
from codereviewgraph.core.security_rules import analyze_ast, scan_security_rules, scan_quality_rules
from codereviewgraph.core.models import DeterministicCodeAuditorModel
from langchain_core.messages import HumanMessage


def test_analyze_ast_valid_python():
    code = """
def calculate_sum(a, b):
    return a + b

class MathHelper:
    def multiply(self, x, y):
        return x * y
"""
    metrics = analyze_ast(code)
    assert metrics["valid_syntax"] is True
    assert metrics["function_count"] == 2
    assert metrics["class_count"] == 1
    assert "calculate_sum" in metrics["functions"]
    assert "MathHelper" in metrics["classes"]


def test_analyze_ast_syntax_error():
    code = "def invalid_func(: pass"
    metrics = analyze_ast(code)
    assert metrics["valid_syntax"] is False
    assert metrics["syntax_error"] is not None


def test_scan_security_rules_sqli():
    code = "query = f'SELECT * FROM users WHERE username = {user_input}'"
    findings = scan_security_rules(code)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "CRITICAL"
    assert "SQL" in findings[0]["title"]


def test_scan_security_rules_eval():
    code = "result = eval(user_supplied_data)"
    findings = scan_security_rules(code)
    assert len(findings) >= 1
    assert any("eval" in f["title"].lower() for f in findings)


def test_scan_security_rules_subprocess_shell_true():
    code = "import subprocess\nsubprocess.run(cmd, shell=True)"
    findings = scan_security_rules(code)
    assert len(findings) >= 1
    assert any("shell=True" in f["title"] for f in findings)


def test_scan_security_rules_multiline_subprocess():
    code = """
import subprocess
subprocess.run(
    ['ls', '-la'],
    shell=True
)
"""
    findings = scan_security_rules(code)
    assert len(findings) >= 1
    assert any("shell=True" in f["title"] for f in findings)
    assert findings[0]["line_number"] == 3


def test_scan_quality_rules():
    code = "try:\n    do_work()\nexcept:\n    pass\nfrom math import *"
    findings = scan_quality_rules(code)
    assert len(findings) >= 2
    categories = [f["category"] for f in findings]
    assert all(c == "CODE_QUALITY" for c in categories)


def test_deterministic_chat_model_invoke():
    model = DeterministicCodeAuditorModel()
    prompt = "TASK: SECURITY_AUDIT\n```python\neval('2+2')\n```"
    response = model.invoke([HumanMessage(content=prompt)])
    assert response.content is not None
    assert "findings" in response.content


def test_extract_code_handles_nested_backticks():
    model = DeterministicCodeAuditorModel()
    code_with_fences = '"""Example: ```pass```"""\neval("1+1")'
    prompt = f"TASK: SECURITY_AUDIT\n```python\n{code_with_fences}\n```"
    response = model.invoke([HumanMessage(content=prompt)])
    assert "SEC-002" in response.content


def test_parse_llm_json_strips_markdown_fences():
    from codereviewgraph.core.models import parse_llm_json
    fenced = '```json\n{"findings": [{"id": "X-1"}]}\n```'
    assert parse_llm_json(fenced) == {"findings": [{"id": "X-1"}]}


def test_analyze_ast_counts_async_functions():
    metrics = analyze_ast("async def fetch_data():\n    return 1\n")
    assert metrics["function_count"] == 1
    assert "fetch_data" in metrics["functions"]


def test_report_compiler_normalizes_lowercase_severity():
    from codereviewgraph.graph.nodes_review import report_compiler_node
    out = report_compiler_node({
        "raw_code": "eval('1')",
        "verified_findings": [{"id": "SEC-1", "title": "Eval", "severity": "critical"}],
        "refactoring_patches": [],
        "overall_score": 70,
        "ast_summary": {"lines_of_code": 1, "valid_syntax": True},
    })
    assert out["final_report"]["critical_count"] == 1
