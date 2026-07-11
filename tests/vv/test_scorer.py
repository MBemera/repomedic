"""Unit tests for corpus validation, matching, aggregation, and gates."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

import vv.scorer as scorer
from repomedic.analyzers import get_all_analyzers
from vv.scorer import (
    AnalyzerScore,
    AnalyzerThreshold,
    CaseDefinition,
    CorpusCase,
    ExpectedFinding,
    FindingIdentity,
    RequirementName,
    ScorerConfigurationError,
    ThresholdFile,
    aggregate,
    check_thresholds,
    compare_findings,
    discover_cases,
    load_case,
    score_case,
)


def _expected() -> ExpectedFinding:
    return ExpectedFinding(
        analyzer="static",
        code="STATIC-001",
        file="app.py",
        lines=(2, 4),
        severity="error",
    )


def _case(
    tmp_path: Path,
    *,
    allow_extra: bool = False,
    forbid: tuple[str, ...] = (),
    requires: tuple[RequirementName, ...] = (),
) -> CorpusCase:
    project = tmp_path / "project"
    project.mkdir(exist_ok=True)
    definition = CaseDefinition(
        schema_version=1,
        analyzer="static",
        requires=requires,
        expect=(_expected(),),
        forbid=forbid,
        allow_extra=allow_extra,
    )
    return CorpusCase("unit-case", tmp_path, project, definition)


def _actual(*, code: str = "STATIC-001", line: int = 3) -> FindingIdentity:
    return FindingIdentity("static", code, "app.py", line, "error")


def test_corpus_covers_every_registered_analyzer() -> None:
    cases = discover_cases()
    covered = {case.analyzer for case in cases if case.analyzer != "all"}
    registered = {analyzer.name for analyzer in get_all_analyzers()}
    assert covered == registered
    assert any(case.analyzer == "all" for case in cases)


def test_load_case_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    case_directory = tmp_path / "duplicate"
    (case_directory / "project").mkdir(parents=True)
    (case_directory / "expected.yaml").write_text(
        "schema_version: 1\nanalyzer: static\nanalyzer: git\nexpect: []\n"
    )
    with pytest.raises(ScorerConfigurationError, match="duplicate key"):
        load_case(case_directory)


def test_expected_finding_rejects_path_traversal() -> None:
    with pytest.raises(ValidationError, match="relative"):
        ExpectedFinding(
            analyzer="static",
            code="STATIC-001",
            file="../outside.py",
            lines=(1, 1),
            severity="error",
        )


def test_runtime_case_requires_explicit_execution_permission() -> None:
    with pytest.raises(ValidationError, match="allow_exec"):
        CaseDefinition(
            schema_version=1,
            analyzer="runtime",
            allow_exec=False,
            entrypoint="crash.py",
            expect=(),
        )


def test_matching_accepts_inclusive_line_range(tmp_path: Path) -> None:
    score = compare_findings(_case(tmp_path), [_actual(line=4)])
    assert score.passed
    assert score.true_positives == 1


def test_location_mismatch_is_one_false_positive_and_negative(tmp_path: Path) -> None:
    score = compare_findings(_case(tmp_path), [_actual(line=5)])
    assert score.false_positives == 1
    assert score.false_negatives == 1


def test_one_actual_finding_cannot_match_twice(tmp_path: Path) -> None:
    case = _case(tmp_path)
    score = compare_findings(case, [_actual(), _actual()])
    assert score.true_positives == 1
    assert score.false_positives == 1


def test_allow_extra_does_not_hide_forbidden_findings(tmp_path: Path) -> None:
    case = _case(tmp_path, allow_extra=True, forbid=("STATIC-999",))
    score = compare_findings(case, [_actual(), _actual(code="STATIC-999")])
    assert score.false_positives == 0
    assert len(score.allowed_extra) == 1
    assert [item.code for item in score.forbidden] == ["STATIC-999"]
    assert not score.passed


def test_empty_evaluated_analyzer_set_stays_empty(tmp_path: Path) -> None:
    score = compare_findings(_case(tmp_path), [], analyzers_evaluated=())
    assert score.analyzers_evaluated == ()


def test_clean_control_counts_only_applicable_analyzers() -> None:
    clean_case = next(case for case in discover_cases() if case.name == "clean-project")
    score = score_case(clean_case, strict=False)
    inapplicable = {"git", "go", "javascript", "logs", "rust", "shell"}
    assert score.passed
    assert inapplicable.isdisjoint(score.analyzers_evaluated)


def test_aggregate_uses_micro_counts(tmp_path: Path) -> None:
    passed = compare_findings(_case(tmp_path), [_actual()])
    missed = compare_findings(_case(tmp_path), [])
    result = aggregate([passed, missed])["static"]
    assert result.true_positives == 1
    assert result.false_negatives == 1
    assert result.recall == 0.5


def test_threshold_equality_passes() -> None:
    names = [analyzer.name for analyzer in get_all_analyzers()]
    scores = {
        name: AnalyzerScore(name, cases_run=1, true_positives=1)
        for name in names
    }
    thresholds = ThresholdFile(
        schema_version=1,
        analyzers={name: AnalyzerThreshold(precision=1.0, recall=1.0) for name in names},
    )
    assert check_thresholds(scores, thresholds, strict=True) == []


def test_missing_requirement_skips_or_fails_in_strict_mode(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _case(tmp_path, requires=(RequirementName.git,))
    monkeypatch.setattr(scorer, "_requirement_available", lambda requirement: False)
    assert score_case(case, strict=False).status == "skipped"
    assert score_case(case, strict=True).status == "error"
