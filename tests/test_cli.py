"""Tests for CodeReviewGraph CLI entrypoints and exit codes."""
import pytest
from codereviewgraph.cli import main


def test_cli_help():
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 0


def test_cli_audit_clean_code():
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--code", "def add(a, b):\n    return a + b"])
    assert exc.value.code == 0


def test_cli_audit_critical_code():
    with pytest.raises(SystemExit) as exc:
        main(["audit", "--code", "import subprocess\nsubprocess.run('ls', shell=True)"])
    assert exc.value.code == 2


def test_cli_audit_missing_args():
    with pytest.raises(SystemExit) as exc:
        main(["audit"])
    assert exc.value.code == 1
