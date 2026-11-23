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
