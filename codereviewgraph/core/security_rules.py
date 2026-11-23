"""Deterministic security rules and static code analyzer for CodeReviewGraph."""
import re
import ast
from typing import List, Dict, Any
from codereviewgraph.core.state import FindingSeverity, FindingCategory


# High-precision regular expression patterns for vulnerabilities
SECURITY_PATTERNS = [
    {
        "id": "SEC-001",
        "title": "Potential SQL Injection via String Formatting",
        "severity": FindingSeverity.CRITICAL,
        "cwe": "CWE-89",
        "pattern": re.compile(
            r"(f[\"'].*?(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*?\{|(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE).*?(\%s|\{\}|\.format\(|f[\"'].*?\{))",
            re.IGNORECASE
        ),
        "description": "SQL statement constructed using dynamic string formatting or interpolation instead of parameterized queries.",
        "remediation": "Use parameterized queries or ORM query binding (e.g., cursor.execute('SELECT * FROM t WHERE id = ?', (val,)))."
    },
    {
        "id": "SEC-002",
        "title": "Arbitrary Code Execution via eval() or exec()",
        "severity": FindingSeverity.CRITICAL,
        "cwe": "CWE-95",
        "pattern": re.compile(r"\b(eval|exec)\s*\(", re.IGNORECASE),
        "description": "Direct invocation of eval() or exec() can allow arbitrary code execution if evaluating untrusted input.",
        "remediation": "Avoid eval() and exec(). Use ast.literal_eval() for safe evaluation of literals or structured serialization like json.loads()."
    },
    {
        "id": "SEC-003",
        "title": "Command Injection via shell=True Subprocess",
        "severity": FindingSeverity.HIGH,
        "cwe": "CWE-78",
        "pattern": re.compile(r"subprocess\.(Popen|run|call|check_output)\s*\(.*?shell\s*=\s*True", re.DOTALL),
        "description": "Executing subprocess commands with shell=True is susceptible to shell injection attacks.",
        "remediation": "Set shell=False and pass arguments as a list of strings instead of a single interpolated string."
    },
    {
        "id": "SEC-004",
        "title": "Hardcoded Secret or API Key",
        "severity": FindingSeverity.HIGH,
        "cwe": "CWE-798",
        "pattern": re.compile(r"(api[_-]?key|secret|token|password|auth_token)\s*=\s*['\"][A-Za-z0-9_\-]{16,}['\"]", re.IGNORECASE),
        "description": "Hardcoded authentication token, API key, or credential detected in source code.",
        "remediation": "Load credentials securely from environment variables (os.getenv) or a secrets manager."
    },
    {
        "id": "SEC-005",
        "title": "Insecure / Deprecated Cryptographic Hash (MD5 / SHA1)",
        "severity": FindingSeverity.MEDIUM,
        "cwe": "CWE-328",
        "pattern": re.compile(r"hashlib\.(md5|sha1)\s*\(", re.IGNORECASE),
        "description": "MD5 and SHA1 algorithms are cryptographically broken and vulnerable to collision attacks.",
        "remediation": "Use SHA-256 (hashlib.sha256) or modern password hashing algorithms like bcrypt or argon2."
    },
    {
        "id": "SEC-006",
        "title": "Unsafe Deserialization via pickle",
        "severity": FindingSeverity.HIGH,
        "cwe": "CWE-502",
        "pattern": re.compile(r"pickle\.(loads|load)\s*\(", re.IGNORECASE),
        "description": "Deserializing untrusted pickle streams can lead to arbitrary code execution.",
        "remediation": "Use safe data formats like JSON, Protocol Buffers, or messagepack."
    }
]

QUALITY_PATTERNS = [
    {
        "id": "QUAL-001",
        "title": "Bare Exception Catch",
        "severity": FindingSeverity.LOW,
        "pattern": re.compile(r"except\s*:\s*"),
        "description": "Catching bare exceptions suppresses SystemExit and KeyboardInterrupt and hides unexpected errors.",
        "remediation": "Catch specific exception types (e.g., except ValueError:) or at minimum except Exception:."
    },
    {
        "id": "QUAL-002",
        "title": "Use of Wildcard Import",
        "severity": FindingSeverity.INFO,
        "pattern": re.compile(r"from\s+[a-zA-Z0-9_\.]+\s+import\s+\*"),
        "description": "Wildcard imports pollute the namespace and make symbol origins ambiguous.",
        "remediation": "Explicitly import required symbols by name."
    },
    {
        "id": "QUAL-003",
        "title": "Missing Error Handling in File Operation",
        "severity": FindingSeverity.LOW,
        "pattern": re.compile(r"open\s*\(.*?\)(?!\s*as\b)", re.IGNORECASE),
        "description": "File opened without a 'with' context manager risks unclosed file handles on failure.",
        "remediation": "Use the 'with open(...) as f:' context manager pattern."
    }
]


def scan_security_rules(code: str) -> List[Dict[str, Any]]:
    """Scan code against security patterns and return findings with line numbers."""
    findings = []
    lines = code.splitlines()

    for rule in SECURITY_PATTERNS:
        # Check multiline or single line
        if rule["pattern"].search(code):
            # Locate specific lines
            for i, line in enumerate(lines, 1):
                if rule["pattern"].search(line):
                    findings.append({
                        "id": f"{rule['id']}-{i}",
                        "category": FindingCategory.SECURITY,
                        "title": rule["title"],
                        "severity": rule["severity"],
                        "line_number": i,
                        "cwe": rule["cwe"],
                        "description": rule["description"],
                        "remediation": rule["remediation"],
                        "snippet": line.strip(),
                        "confidence": 0.95
                    })
    return findings


def scan_quality_rules(code: str) -> List[Dict[str, Any]]:
    """Scan code against code quality patterns."""
    findings = []
    lines = code.splitlines()

    for rule in QUALITY_PATTERNS:
        for i, line in enumerate(lines, 1):
            if rule["pattern"].search(line):
                findings.append({
                    "id": f"{rule['id']}-{i}",
                    "category": FindingCategory.CODE_QUALITY,
                    "title": rule["title"],
                    "severity": rule["severity"],
                    "line_number": i,
                    "cwe": None,
                    "description": rule["description"],
                    "remediation": rule["remediation"],
                    "snippet": line.strip(),
                    "confidence": 0.90
                })
    return findings


def analyze_ast(code: str) -> Dict[str, Any]:
    """Parse code AST and extract complexity and structural metrics."""
    metrics = {
        "valid_syntax": True,
        "lines_of_code": len(code.splitlines()),
        "function_count": 0,
        "class_count": 0,
        "import_count": 0,
        "functions": [],
        "classes": [],
        "syntax_error": None
    }
    try:
        tree = ast.parse(code)
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                metrics["function_count"] += 1
                metrics["functions"].append(node.name)
            elif isinstance(node, ast.ClassDef):
                metrics["class_count"] += 1
                metrics["classes"].append(node.name)
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                metrics["import_count"] += 1
    except SyntaxError as e:
        metrics["valid_syntax"] = False
        metrics["syntax_error"] = f"Line {e.lineno}: {e.msg}"

    return metrics
