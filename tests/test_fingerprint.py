"""Tests for content-aware fingerprint assignment (v2)."""

from __future__ import annotations

from repomedic.core.scanner import Scanner
from repomedic.models import Finding, Category, Severity


def _fingerprints(project, code="STATIC-001"):
    report = Scanner().scan(str(project), analyzer_names=["static"])
    return {f.fingerprint for f in report.findings if f.code == code}


def test_fingerprint_survives_line_drift(make_project):
    """Inserting lines above a finding must not change its fingerprint."""
    project = make_project({"app.py": "def broken(:\n    pass\n"})
    before = _fingerprints(project)
    assert before

    (project / "app.py").write_text("# comment\n# more\n\ndef broken(:\n    pass\n")
    after = _fingerprints(project)
    assert after == before


def test_fingerprint_changes_when_flagged_line_changes(make_project):
    project = make_project({"app.py": "def broken(:\n    pass\n"})
    before = _fingerprints(project)

    (project / "app.py").write_text("def other_broken(:\n    pass\n")
    after = _fingerprints(project)
    assert after != before


def test_fingerprint_stable_across_runs(make_project):
    project = make_project({"app.py": "def broken(:\n    pass\n"})
    assert _fingerprints(project) == _fingerprints(project)


def test_duplicate_findings_get_distinct_fingerprints(make_project):
    """Two identical secrets on identical lines must not share an ID."""
    project = make_project(
        {"config.py": 'k1 = "AKIAIOSFODNN7EXAMPLE"\nk2 = "AKIAIOSFODNN7EXAMPLE"\n'}
    )
    report = Scanner().scan(str(project), analyzer_names=["security"])
    secret_fps = [f.fingerprint for f in report.findings if f.code == "SEC-001"]
    assert len(secret_fps) == 2
    assert len(set(secret_fps)) == 2


def test_fingerprint_format():
    finding = Finding(
        category=Category.hygiene,
        severity=Severity.info,
        code="X-001",
        title="t",
        description="d",
    )
    assert finding.fingerprint.startswith("RM-")
    assert len(finding.fingerprint) == 13  # RM- + 10 hex chars


def test_project_level_findings_fingerprinted(make_project):
    project = make_project({"app.py": "x = 1\n"})
    report = Scanner().scan(str(project), analyzer_names=["config"])
    for f in report.findings:
        assert f.fingerprint.startswith("RM-")
