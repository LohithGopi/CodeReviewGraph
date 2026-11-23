# CodeReviewGraph 🔍

**Stateful Multi-Agent Code Auditor & Refactoring Workflow powered by LangGraph & LangChain.**

## Overview
CodeReviewGraph orchestrates a multi-agent review pipeline across specialized nodes:
1. **Planner & Triage Node:** Identifies programming language, functions, and audit scope.
2. **Security Auditor Node:** Scans for OWASP vulnerabilities (SQLi, unsafe eval/exec, path traversal, secrets).
3. **Quality & Performance Node:** Analyzes maintainability, typing, complexity, and bad practices.
4. **Verification / Reflection Critic Node:** Cross-verifies findings, computes calibrated severity scores (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`), and computes a 0-100 quality score.
5. **Refactoring Patch Generator Node (Conditional):** Generates drop-in remediation patches for critical vulnerabilities.
6. **Report Compiler Node:** Aggregates findings into structured JSON and Markdown audit summaries.

## Installation
```bash
py -m pip install -e .
```

## Running Tests
```bash
py -m pytest -v tests
```

## Running the API Server
```bash
py -m uvicorn codereviewgraph.api.app:app --host 127.0.0.1 --port 8000
```
Visit `http://127.0.0.1:8000/health` or `http://127.0.0.1:8000/docs`.

## CLI Usage
```bash
# Run audit on a file
py -m codereviewgraph.cli audit path/to/file.py

# Run audit on inline code
py -m codereviewgraph.cli audit --code "user_input = request.get('id'); db.execute(f'SELECT * FROM users WHERE id = {user_input}')"
```
