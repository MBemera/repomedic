"""Tests for the Rust analyzer."""

from __future__ import annotations

from repomedic.analyzers.rust import RustAnalyzer
from repomedic.core.context import ScanContext


def test_applicable_with_rs_files(make_project):
    project = make_project({"main.rs": "fn main() {}\n"})
    ctx = ScanContext(str(project))
    analyzer = RustAnalyzer()
    assert analyzer.is_applicable(ctx)


def test_applicable_with_cargo_toml(make_project):
    project = make_project({
        "Cargo.toml": '[package]\nname = "test"\nversion = "0.1.0"\n',
    })
    ctx = ScanContext(str(project))
    analyzer = RustAnalyzer()
    assert analyzer.is_applicable(ctx)


def test_not_applicable_without_rust(make_project):
    project = make_project({"hello.py": "print('hello')\n"})
    ctx = ScanContext(str(project))
    analyzer = RustAnalyzer()
    assert not analyzer.is_applicable(ctx)


def test_missing_cargo_toml(make_project):
    project = make_project({"main.rs": "fn main() {}\n"})
    ctx = ScanContext(str(project))
    analyzer = RustAnalyzer()
    result = analyzer.analyze(ctx)

    dep_findings = [f for f in result.findings if f.code == "RUST-DEP-001"]
    assert len(dep_findings) == 1
    assert dep_findings[0].language == "rust"


def test_missing_cargo_lock(make_project):
    project = make_project({
        "Cargo.toml": '[package]\nname = "test"\nversion = "0.1.0"\n',
        "src/main.rs": "fn main() {}\n",
    })
    ctx = ScanContext(str(project))
    analyzer = RustAnalyzer()
    result = analyzer.analyze(ctx)

    lock_findings = [f for f in result.findings if f.code == "RUST-DEP-002"]
    assert len(lock_findings) == 1
