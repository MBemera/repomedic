"""Run every committed ground-truth case through its production entry point."""

from __future__ import annotations

import pytest

from vv.scorer import CaseScore, CorpusCase, discover_cases, score_case


def _case_parameter(case: CorpusCase):
    marks = [pytest.mark.corpus]
    if case.definition.requires:
        marks.append(pytest.mark.toolchain)
    return pytest.param(case, id=case.name, marks=marks)


CASES = [_case_parameter(case) for case in discover_cases()]


def _failure_summary(score: CaseScore) -> str:
    parts = [f"status={score.status}"]
    if score.reason:
        parts.append(score.reason)
    parts.append(f"tp={score.true_positives}")
    parts.append(f"fp={score.false_positives}")
    parts.append(f"fn={score.false_negatives}")
    if score.forbidden:
        codes = ", ".join(item.code for item in score.forbidden)
        parts.append(f"forbidden={codes}")
    return "; ".join(parts)


@pytest.mark.parametrize("case", CASES)
def test_ground_truth_case(case: CorpusCase) -> None:
    score = score_case(case)
    if score.status == "skipped":
        pytest.skip(score.reason or "required toolchain unavailable")
    assert score.passed, _failure_summary(score)
