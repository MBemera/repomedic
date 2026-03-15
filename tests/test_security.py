"""Tests for the security analyzer."""

from __future__ import annotations

from repomedic.analyzers.security import SecurityAnalyzer
from repomedic.core.context import ScanContext


def test_hardcoded_aws_key(make_project):
    project = make_project({"app.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'})
    ctx = ScanContext(str(project))
    result = SecurityAnalyzer().analyze(ctx)

    assert len(result.findings) >= 1
    finding = result.findings[0]
    assert finding.code == "SEC-001"
    assert finding.severity.value == "error"
    assert "AWS" in finding.title


def test_hardcoded_openai_key(make_project):
    project = make_project({"config.py": 'OPENAI_KEY = "sk-abc123def456ghi789jklmnopqrst"\n'})
    ctx = ScanContext(str(project))
    result = SecurityAnalyzer().analyze(ctx)

    assert len(result.findings) >= 1
    assert any(f.code == "SEC-001" for f in result.findings)


def test_hardcoded_github_token(make_project):
    project = make_project({"deploy.py": 'TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl"\n'})
    ctx = ScanContext(str(project))
    result = SecurityAnalyzer().analyze(ctx)

    assert len(result.findings) >= 1
    assert any(f.code == "SEC-001" for f in result.findings)


def test_hardcoded_password(make_project):
    project = make_project({"db.py": "password = 'supersecret123'\n"})
    ctx = ScanContext(str(project))
    result = SecurityAnalyzer().analyze(ctx)

    assert len(result.findings) >= 1
    assert any(f.code == "SEC-001" for f in result.findings)


def test_env_not_gitignored(make_project):
    project = make_project({
        ".env": "SECRET_KEY=abc123\n",
        ".gitignore": "*.pyc\n",
    })
    ctx = ScanContext(str(project))
    result = SecurityAnalyzer().analyze(ctx)

    assert any(f.code == "SEC-002" for f in result.findings)


def test_env_gitignored(make_project):
    project = make_project({
        ".env": "SECRET_KEY=abc123\n",
        ".gitignore": ".env\n*.pyc\n",
    })
    ctx = ScanContext(str(project))
    result = SecurityAnalyzer().analyze(ctx)

    assert not any(f.code == "SEC-002" for f in result.findings)


def test_debug_mode(make_project):
    project = make_project({"settings.py": "DEBUG = True\nSECRET = 'foo'\n"})
    ctx = ScanContext(str(project))
    result = SecurityAnalyzer().analyze(ctx)

    assert any(f.code == "SEC-003" for f in result.findings)
    debug_finding = [f for f in result.findings if f.code == "SEC-003"][0]
    assert debug_finding.severity.value == "warning"


def test_no_issues_clean_project(make_project):
    project = make_project({"app.py": "import os\nprint('hello')\n"})
    ctx = ScanContext(str(project))
    result = SecurityAnalyzer().analyze(ctx)

    # Should have no SEC-001 or SEC-003 findings
    assert not any(f.code in ("SEC-001", "SEC-003") for f in result.findings)


def test_comments_ignored(make_project):
    project = make_project({"app.py": '# password = "supersecret123"\n'})
    ctx = ScanContext(str(project))
    result = SecurityAnalyzer().analyze(ctx)

    assert not any(f.code == "SEC-001" for f in result.findings)
