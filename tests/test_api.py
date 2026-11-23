"""API smoke tests for FastAPI endpoints."""
from fastapi.testclient import TestClient
from codereviewgraph.api.app import app

client = TestClient(app)


def test_dashboard_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    assert "CodeReviewGraph" in response.text
    assert "<!DOCTYPE html>" in response.text


def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "codereviewgraph"


def test_api_audit_clean_code():
    payload = {
        "code": "def multiply(a: int, b: int) -> int:\n    return a * b",
        "language": "python",
        "thread_id": "api-test-clean"
    }
    response = client.post("/api/audit", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["report"]["health_score"] == 100
    assert data["report"]["total_findings"] == 0


def test_api_audit_vulnerable_code():
    payload = {
        "code": "import subprocess\nsubprocess.run('ls', shell=True)",
        "language": "python",
        "thread_id": "api-test-vuln"
    }
    response = client.post("/api/audit", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "SUCCESS"
    assert data["report"]["high_count"] >= 1


def test_api_audit_empty_code():
    payload = {"code": "   "}
    response = client.post("/api/audit", json=payload)
    assert response.status_code == 400


def test_api_get_run_checkpoint():
    thread_id = "api-checkpoint-test"
    client.post("/api/audit", json={
        "code": "print('checkpoint')",
        "thread_id": thread_id
    })

    response = client.get(f"/api/runs/{thread_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["thread_id"] == thread_id
    assert "values" in data
