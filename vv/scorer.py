"""Score RepoMedic findings against the committed ground-truth corpus."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from enum import Enum
from pathlib import Path, PurePosixPath
from typing import Iterable, Iterator, Literal, Sequence

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, StrictStr
from pydantic import ValidationError, field_validator, model_validator

from repomedic.analyzers import get_all_analyzers
from repomedic.analyzers.runtime import RuntimeAnalyzer
from repomedic.core.service import ScanRequest, run_scan
from repomedic.models import Finding, Severity
from repomedic.utils.process import run as run_process

VV_ROOT = Path(__file__).resolve().parent
CORPUS_DIR = VV_ROOT / "corpus"
THRESHOLDS_PATH = VV_ROOT / "thresholds.yaml"
EXPECTED_FILENAME = "expected.yaml"
PROJECT_DIRECTORY_NAME = "project"
STRICT_ENVIRONMENT_VARIABLE = "REPOMEDIC_VV_STRICT"
MAX_DEFINITION_BYTES = 64 * 1024
MAX_IDENTITY_TEXT_LENGTH = 500
DEFAULT_RUNTIME_TIMEOUT_SECONDS = 30
MAX_RUNTIME_TIMEOUT_SECONDS = 300
SCAN_ANALYZER_TIMEOUT_SECONDS = 330.0
OUTSIDE_PROJECT_PATH = "<outside-project>"
INVALID_PATH = "<invalid-path>"
INVALID_CODE = "<invalid-code>"


class ScorerConfigurationError(ValueError):
    """The corpus or threshold configuration is invalid."""


class CaseExecutionError(RuntimeError):
    """A corpus case could not be prepared or executed safely."""


class RequirementName(str, Enum):
    bandit = "bandit"
    bash = "bash"
    cargo = "cargo"
    cargo_audit = "cargo-audit"
    git = "git"
    gitleaks = "gitleaks"
    go = "go"
    govulncheck = "govulncheck"
    node = "node"
    npm = "npm"
    npx = "npx"
    python = "python"
    ruff = "ruff"
    semgrep = "semgrep"
    shellcheck = "shellcheck"
    tsc = "tsc"


DIRECT_REQUIREMENTS: dict[RequirementName, str] = {
    RequirementName.bandit: "bandit",
    RequirementName.bash: "bash",
    RequirementName.cargo: "cargo",
    RequirementName.git: "git",
    RequirementName.gitleaks: "gitleaks",
    RequirementName.go: "go",
    RequirementName.govulncheck: "govulncheck",
    RequirementName.node: "node",
    RequirementName.npm: "npm",
    RequirementName.npx: "npx",
    RequirementName.ruff: "ruff",
    RequirementName.shellcheck: "shellcheck",
}

PROBE_REQUIREMENTS: dict[RequirementName, tuple[str, ...]] = {
    RequirementName.cargo_audit: ("cargo", "audit", "--version"),
    RequirementName.semgrep: ("semgrep", "--version"),
    RequirementName.tsc: ("npx", "--no-install", "tsc", "--version"),
}


def _validate_plain_text(value: str, field_name: str, max_length: int = 200) -> str:
    if not value or value != value.strip():
        raise ValueError(f"{field_name} must be non-empty without surrounding whitespace")
    if len(value) > max_length or any(not character.isprintable() for character in value):
        raise ValueError(f"{field_name} contains invalid characters")
    return value


def _validate_relative_path(value: str) -> str:
    if len(value) > MAX_IDENTITY_TEXT_LENGTH or "\\" in value:
        raise ValueError("path must be a short POSIX-style relative path")
    parts = value.split("/")
    if not value or value.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        raise ValueError("path must be relative and cannot contain '.', '..', or empty parts")
    if any(not character.isprintable() for character in value):
        raise ValueError("path contains invalid characters")
    return str(PurePosixPath(value))


class ExpectedFinding(BaseModel):
    """One finding the case expects RepoMedic to emit."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    analyzer: StrictStr
    code: StrictStr
    file: StrictStr | None
    lines: tuple[StrictInt, StrictInt] | None
    severity: Severity

    @field_validator("analyzer")
    @classmethod
    def validate_analyzer(cls, value: str) -> str:
        return _validate_plain_text(value, "expected analyzer")

    @field_validator("code")
    @classmethod
    def validate_code(cls, value: str) -> str:
        return _validate_plain_text(value, "expected code")

    @field_validator("file")
    @classmethod
    def validate_file(cls, value: str | None) -> str | None:
        return None if value is None else _validate_relative_path(value)

    @field_validator("lines")
    @classmethod
    def validate_lines(cls, value: tuple[int, int] | None) -> tuple[int, int] | None:
        if value is None:
            return None
        start, end = value
        if start < 1 or end < start:
            raise ValueError("lines must be an inclusive positive [start, end] range")
        return value


class CaseDefinition(BaseModel):
    """Validated contents of one case's expected.yaml."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: StrictInt
    analyzer: StrictStr
    requires: tuple[RequirementName, ...] = ()
    allow_exec: StrictBool = False
    initialize_git: StrictBool = False
    entrypoint: StrictStr | None = None
    arguments: tuple[StrictStr, ...] = ()
    timeout: StrictInt = Field(
        default=DEFAULT_RUNTIME_TIMEOUT_SECONDS,
        ge=1,
        le=MAX_RUNTIME_TIMEOUT_SECONDS,
    )
    expect: tuple[ExpectedFinding, ...]
    forbid: tuple[StrictStr, ...] = ()
    allow_extra: StrictBool = False

    @field_validator("analyzer")
    @classmethod
    def validate_analyzer(cls, value: str) -> str:
        return _validate_plain_text(value, "case analyzer")

    @field_validator("entrypoint")
    @classmethod
    def validate_entrypoint(cls, value: str | None) -> str | None:
        return None if value is None else _validate_relative_path(value)

    @field_validator("arguments")
    @classmethod
    def validate_arguments(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for argument in value:
            if "\x00" in argument or len(argument) > MAX_IDENTITY_TEXT_LENGTH:
                raise ValueError("runtime arguments must be bounded and cannot contain NUL")
        return value

    @field_validator("forbid")
    @classmethod
    def validate_forbidden_codes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_validate_plain_text(code, "forbidden code") for code in value)

    @model_validator(mode="after")
    def validate_semantics(self) -> CaseDefinition:
        if self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        if len(set(self.requires)) != len(self.requires):
            raise ValueError("requires cannot contain duplicates")
        if len(set(self.forbid)) != len(self.forbid):
            raise ValueError("forbid cannot contain duplicates")
        if len(self.expect) > 200 or len(self.forbid) > 200:
            raise ValueError("expect and forbid are limited to 200 entries")
        if self.analyzer == "all" and self.expect:
            raise ValueError("analyzer 'all' is only valid for an empty-expect clean control")
        if self.analyzer == "all" and self.allow_extra:
            raise ValueError("analyzer 'all' clean controls cannot allow extra findings")
        if self.analyzer == "runtime" and self.entrypoint is None:
            raise ValueError("runtime cases require entrypoint")
        if self.analyzer == "runtime" and not self.allow_exec:
            raise ValueError("runtime cases require explicit allow_exec: true")
        if self.analyzer != "runtime" and (self.entrypoint is not None or self.arguments):
            raise ValueError("entrypoint and arguments are only valid for runtime cases")
        if self.initialize_git and self.analyzer not in {"git", "all"}:
            raise ValueError("initialize_git is only valid for git or all-analyzer cases")
        if self.initialize_git and RequirementName.git not in self.requires:
            raise ValueError("initialize_git requires 'git' in requires")
        return self


class AnalyzerThreshold(BaseModel):
    """Minimum accepted metrics for one analyzer."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    precision: float = Field(ge=0.0, le=1.0)
    recall: float = Field(ge=0.0, le=1.0)


class ThresholdFile(BaseModel):
    """Validated vv/thresholds.yaml."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: StrictInt
    analyzers: dict[StrictStr, AnalyzerThreshold]

    @model_validator(mode="after")
    def validate_schema_version(self) -> ThresholdFile:
        if self.schema_version != 1:
            raise ValueError("schema_version must be 1")
        return self


@dataclass(frozen=True)
class CorpusCase:
    """A validated case definition and its project directory."""

    name: str
    directory: Path
    project: Path
    definition: CaseDefinition

    @property
    def analyzer(self) -> str:
        return self.definition.analyzer


@dataclass(frozen=True)
class ExpectedIdentity:
    analyzer: str
    code: str
    file: str | None
    lines: tuple[int, int] | None
    severity: str


@dataclass(frozen=True)
class FindingIdentity:
    analyzer: str
    code: str
    file: str | None
    line: int | None
    severity: str


@dataclass(frozen=True)
class FindingMatch:
    expected: ExpectedIdentity
    actual: FindingIdentity


CaseStatus = Literal["scored", "skipped", "error"]


@dataclass(frozen=True)
class CaseScore:
    case_name: str
    selected_analyzer: str
    status: CaseStatus
    analyzers_evaluated: tuple[str, ...] = ()
    matches: tuple[FindingMatch, ...] = ()
    missing: tuple[ExpectedIdentity, ...] = ()
    unexpected: tuple[FindingIdentity, ...] = ()
    allowed_extra: tuple[FindingIdentity, ...] = ()
    forbidden: tuple[FindingIdentity, ...] = ()
    reason: str | None = None

    @property
    def true_positives(self) -> int:
        return len(self.matches)

    @property
    def false_positives(self) -> int:
        return len(self.unexpected)

    @property
    def false_negatives(self) -> int:
        return len(self.missing)

    @property
    def passed(self) -> bool:
        return (
            self.status == "scored"
            and not self.missing
            and not self.unexpected
            and not self.forbidden
        )


@dataclass(frozen=True)
class AnalyzerScore:
    analyzer: str
    cases_run: int = 0
    cases_skipped: int = 0
    cases_failed: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 1.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 1.0


@dataclass(frozen=True)
class ThresholdFailure:
    analyzer: str
    metric: str
    message: str
    actual: float | None = None
    minimum: float | None = None


class _UniqueKeyLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects duplicate mapping keys."""


def _construct_unique_mapping(loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False) -> dict:
    mapping: dict = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise yaml.constructor.ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate key: {key}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)


def _registered_analyzer_names() -> tuple[str, ...]:
    return tuple(sorted(analyzer.name for analyzer in get_all_analyzers()))


def _validation_error(path: Path, error: ValidationError) -> ScorerConfigurationError:
    details = []
    for item in error.errors(include_input=False):
        location = ".".join(str(part) for part in item["loc"])
        details.append(f"{location}: {item['msg']}")
    return ScorerConfigurationError(f"invalid {path}: {'; '.join(details)}")


def _load_yaml_mapping(path: Path) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ScorerConfigurationError(f"configuration file is missing or unsafe: {path}")
    if path.stat().st_size > MAX_DEFINITION_BYTES:
        raise ScorerConfigurationError(f"configuration file exceeds 64 KiB: {path}")
    try:
        data = yaml.load(path.read_text(encoding="utf-8"), Loader=_UniqueKeyLoader)
    except (OSError, UnicodeError, yaml.YAMLError) as error:
        raise ScorerConfigurationError(f"could not safely parse {path}: {error}") from error
    if not isinstance(data, dict):
        raise ScorerConfigurationError(f"configuration must be a YAML mapping: {path}")
    return data


def _validate_case_analyzers(definition: CaseDefinition, path: Path) -> None:
    registered = set(_registered_analyzer_names())
    if definition.analyzer != "all" and definition.analyzer not in registered:
        raise ScorerConfigurationError(f"unknown analyzer '{definition.analyzer}' in {path}")
    expected_codes = set()
    expected_identities = set()
    for expected in definition.expect:
        if expected.analyzer not in registered:
            raise ScorerConfigurationError(f"unknown expected analyzer '{expected.analyzer}' in {path}")
        if expected.analyzer != definition.analyzer:
            raise ScorerConfigurationError(f"expected analyzer must equal case analyzer in {path}")
        identity = (expected.analyzer, expected.code, expected.file, expected.lines, expected.severity)
        if identity in expected_identities:
            raise ScorerConfigurationError(f"duplicate expected finding in {path}")
        expected_identities.add(identity)
        expected_codes.add(expected.code)
    overlap = expected_codes.intersection(definition.forbid)
    if overlap:
        raise ScorerConfigurationError(f"expected and forbidden codes overlap in {path}: {', '.join(sorted(overlap))}")


def load_case(case_directory: Path) -> CorpusCase:
    """Load and validate one vv/corpus/<case> directory."""
    case_directory = Path(case_directory)
    if case_directory.is_symlink() or not case_directory.is_dir():
        raise ScorerConfigurationError(f"case directory is missing or unsafe: {case_directory}")
    project = case_directory / PROJECT_DIRECTORY_NAME
    if project.is_symlink() or not project.is_dir():
        raise ScorerConfigurationError(f"case project is missing or unsafe: {project}")
    expected_path = case_directory / EXPECTED_FILENAME
    raw = _load_yaml_mapping(expected_path)
    try:
        definition = CaseDefinition.model_validate(raw)
    except ValidationError as error:
        raise _validation_error(expected_path, error) from error
    _validate_case_analyzers(definition, expected_path)
    if definition.entrypoint is not None:
        entrypoint = project / definition.entrypoint
        if entrypoint.is_symlink() or not entrypoint.is_file():
            raise ScorerConfigurationError(f"runtime entrypoint is missing or unsafe: {entrypoint}")
    return CorpusCase(
        name=_validate_plain_text(case_directory.name, "case name", MAX_IDENTITY_TEXT_LENGTH),
        directory=case_directory,
        project=project,
        definition=definition,
    )


def discover_cases(corpus_directory: Path = CORPUS_DIR) -> list[CorpusCase]:
    """Discover corpus cases in deterministic directory-name order."""
    corpus_directory = Path(corpus_directory)
    if corpus_directory.is_symlink() or not corpus_directory.is_dir():
        raise ScorerConfigurationError(f"corpus directory is missing or unsafe: {corpus_directory}")
    case_directories = sorted(
        (entry for entry in corpus_directory.iterdir() if entry.is_dir() and not entry.name.startswith(".")),
        key=lambda entry: entry.name,
    )
    if not case_directories:
        raise ScorerConfigurationError(f"no corpus cases found in {corpus_directory}")
    return [load_case(case_directory) for case_directory in case_directories]


def load_thresholds(path: Path = THRESHOLDS_PATH) -> ThresholdFile:
    """Load thresholds and require exact coverage of registered analyzers."""
    path = Path(path)
    raw = _load_yaml_mapping(path)
    try:
        thresholds = ThresholdFile.model_validate(raw)
    except ValidationError as error:
        raise _validation_error(path, error) from error
    registered = set(_registered_analyzer_names())
    configured = set(thresholds.analyzers)
    if registered != configured:
        missing = ", ".join(sorted(registered - configured)) or "none"
        extra = ", ".join(sorted(configured - registered)) or "none"
        raise ScorerConfigurationError(
            f"threshold analyzer coverage must be exact (missing: {missing}; extra: {extra})"
        )
    return thresholds


def _strict_mode(strict: bool | None) -> bool:
    if strict is not None:
        return strict
    raw_value = os.getenv(STRICT_ENVIRONMENT_VARIABLE, "0").strip().lower()
    if raw_value in {"", "0", "false", "no"}:
        return False
    if raw_value in {"1", "true", "yes"}:
        return True
    raise ScorerConfigurationError(
        f"{STRICT_ENVIRONMENT_VARIABLE} must be 0/1, false/true, or no/yes"
    )


def _requirement_available(requirement: RequirementName) -> bool:
    if requirement is RequirementName.python:
        return Path(sys.executable).is_file()
    executable = DIRECT_REQUIREMENTS.get(requirement)
    if executable is not None:
        return shutil.which(executable) is not None
    probe = PROBE_REQUIREMENTS.get(requirement)
    if probe is None:
        return False
    return run_process(list(probe), timeout=10).ok


def missing_requirements(case: CorpusCase) -> tuple[str, ...]:
    """Return unavailable declared tools without executing corpus content."""
    return tuple(
        requirement.value
        for requirement in case.definition.requires
        if not _requirement_available(requirement)
    )


def _selected_analyzers(case: CorpusCase) -> tuple[str, ...]:
    if case.analyzer != "all":
        return (case.analyzer,)
    analyzers = [name for name in _registered_analyzer_names() if name != "runtime"]
    if not _requirement_available(RequirementName.semgrep):
        analyzers.remove("semgrep")
    return tuple(analyzers)


def _run_git(project: Path, arguments: list[str]) -> None:
    command = [
        "git",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=",
        "-c",
        "commit.gpgSign=false",
        *arguments,
    ]
    if not run_process(command, cwd=str(project), timeout=15).ok:
        raise CaseExecutionError("fixed git corpus preparation failed")


def _initialize_git(project: Path) -> None:
    _run_git(project, ["init", "--quiet"])
    _run_git(project, ["add", "--all"])
    _run_git(
        project,
        [
            "-c",
            "user.name=RepoMedic V&V",
            "-c",
            "user.email=vv@invalid.example",
            "commit",
            "--quiet",
            "-m",
            "Seed corpus case",
        ],
    )


def _safe_identity_text(value: object, fallback: str) -> str:
    if not isinstance(value, str):
        return fallback
    try:
        return _validate_plain_text(value, "finding identity", MAX_IDENTITY_TEXT_LENGTH)
    except ValueError:
        return fallback


def _safe_finding_path(value: str | None) -> str | None:
    if value is None:
        return None
    try:
        return _validate_relative_path(value)
    except ValueError:
        return INVALID_PATH


def _finding_identity(analyzer: str, finding: Finding) -> FindingIdentity:
    line = finding.line if isinstance(finding.line, int) and finding.line > 0 else None
    return FindingIdentity(
        analyzer=_safe_identity_text(analyzer, OUTSIDE_PROJECT_PATH),
        code=_safe_identity_text(finding.code, INVALID_CODE),
        file=_safe_finding_path(finding.file_path),
        line=line,
        severity=finding.severity.value,
    )


def _scan_case(case: CorpusCase, project: Path) -> tuple[list[FindingIdentity], tuple[str, ...]]:
    analyzers = list(_selected_analyzers(case))
    outcome = run_scan(
        ScanRequest(
            target=str(project),
            analyzers=analyzers,
            min_severity="info",
            max_findings=0,
            fail_on="never",
            analyzer_timeout=SCAN_ANALYZER_TIMEOUT_SECONDS,
            allow_exec=case.definition.allow_exec,
            use_baseline=False,
        )
    )
    try:
        failed = tuple(result.analyzer for result in outcome.report.results if result.error)
        if failed:
            names = ", ".join(sorted(failed))
            raise CaseExecutionError(f"analyzer execution failed: {names}")
        if case.analyzer != "all" and not outcome.report.results:
            raise CaseExecutionError(f"requested analyzer was not applicable: {case.analyzer}")
        actual = [
            _finding_identity(result.analyzer, finding)
            for result in outcome.report.results
            for finding in result.findings
        ]
        evaluated = tuple(result.analyzer for result in outcome.report.results)
        return actual, evaluated
    finally:
        outcome.cleanup()


def _runtime_case(case: CorpusCase, project: Path) -> tuple[list[FindingIdentity], tuple[str, ...]]:
    entrypoint = case.definition.entrypoint
    if entrypoint is None:
        raise CaseExecutionError("runtime case has no entrypoint")
    script = (project / entrypoint).resolve()
    if not script.is_relative_to(project.resolve()) or not script.is_file():
        raise CaseExecutionError("runtime entrypoint escaped the project copy")
    result = RuntimeAnalyzer().analyze_script(
        str(script),
        cwd=str(project),
        args=list(case.definition.arguments),
        timeout=case.definition.timeout,
        env_mode="isolated",
    )
    if result.error:
        raise CaseExecutionError("runtime analyzer execution failed")
    actual = [_finding_identity("runtime", finding) for finding in result.findings]
    return actual, ("runtime",)


def _execute_case(case: CorpusCase, project: Path) -> tuple[list[FindingIdentity], tuple[str, ...]]:
    if case.definition.initialize_git:
        _initialize_git(project)
    if case.analyzer == "runtime":
        return _runtime_case(case, project)
    return _scan_case(case, project)


@contextmanager
def _isolated_tool_caches(root: Path) -> Iterator[None]:
    overrides = {
        "GOCACHE": str(root / "go-build"),
        "NPM_CONFIG_CACHE": str(root / "npm"),
    }
    previous = {name: os.environ.get(name) for name in overrides}
    for cache_path in overrides.values():
        Path(cache_path).mkdir(parents=True, exist_ok=True)
    os.environ.update(overrides)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value


def _expected_identity(expected: ExpectedFinding) -> ExpectedIdentity:
    return ExpectedIdentity(
        analyzer=expected.analyzer,
        code=expected.code,
        file=expected.file,
        lines=expected.lines,
        severity=expected.severity.value,
    )


def _identity_matches(expected: ExpectedIdentity, actual: FindingIdentity) -> bool:
    if (
        expected.analyzer != actual.analyzer
        or expected.code != actual.code
        or expected.file != actual.file
        or expected.severity != actual.severity
    ):
        return False
    if expected.lines is None:
        return actual.line is None
    start, end = expected.lines
    return actual.line is not None and start <= actual.line <= end


def _find_maximum_matches(
    expected: list[ExpectedIdentity],
    actual: list[FindingIdentity],
) -> dict[int, int]:
    candidates = [
        [actual_index for actual_index, item in enumerate(actual) if _identity_matches(wanted, item)]
        for wanted in expected
    ]
    actual_owners: dict[int, int] = {}

    def assign(expected_index: int, seen: set[int]) -> bool:
        for actual_index in candidates[expected_index]:
            if actual_index in seen:
                continue
            seen.add(actual_index)
            previous_owner = actual_owners.get(actual_index)
            if previous_owner is None or assign(previous_owner, seen):
                actual_owners[actual_index] = expected_index
                return True
        return False

    order = sorted(range(len(expected)), key=lambda index: len(candidates[index]))
    for expected_index in order:
        assign(expected_index, set())
    return actual_owners


def compare_findings(
    case: CorpusCase,
    actual: list[FindingIdentity],
    analyzers_evaluated: tuple[str, ...] | None = None,
) -> CaseScore:
    """Compare expected and actual identities with one-to-one matching."""
    expected = [_expected_identity(item) for item in case.definition.expect]
    actual_owners = _find_maximum_matches(expected, actual)
    matched_expected = set(actual_owners.values())
    matched_actual = set(actual_owners)
    matches = tuple(
        FindingMatch(expected[expected_index], actual[actual_index])
        for actual_index, expected_index in sorted(actual_owners.items())
    )
    missing = tuple(item for index, item in enumerate(expected) if index not in matched_expected)
    extras = tuple(item for index, item in enumerate(actual) if index not in matched_actual)
    forbidden = tuple(item for item in actual if item.code in case.definition.forbid)
    unexpected = () if case.definition.allow_extra else extras
    allowed_extra = extras if case.definition.allow_extra else ()
    return CaseScore(
        case_name=case.name,
        selected_analyzer=case.analyzer,
        status="scored",
        analyzers_evaluated=(
            analyzers_evaluated
            if analyzers_evaluated is not None
            else _selected_analyzers(case)
        ),
        matches=matches,
        missing=missing,
        unexpected=unexpected,
        allowed_extra=allowed_extra,
        forbidden=forbidden,
    )


def score_case(case: CorpusCase | Path, *, strict: bool | None = None) -> CaseScore:
    """Execute and score one case in an isolated temporary project copy."""
    loaded_case = load_case(case) if isinstance(case, Path) else case
    selected = _selected_analyzers(loaded_case)
    missing = missing_requirements(loaded_case)
    if missing:
        reason = f"missing required tools: {', '.join(missing)}"
        status: CaseStatus = "error" if _strict_mode(strict) else "skipped"
        return CaseScore(loaded_case.name, loaded_case.analyzer, status, selected, reason=reason)
    try:
        with tempfile.TemporaryDirectory(prefix="repomedic-vv-") as temporary_directory:
            temporary_root = Path(temporary_directory)
            project = temporary_root / PROJECT_DIRECTORY_NAME
            shutil.copytree(loaded_case.project, project, symlinks=True)
            with _isolated_tool_caches(temporary_root / "caches"):
                actual, evaluated = _execute_case(loaded_case, project)
        return compare_findings(loaded_case, actual, evaluated)
    except CaseExecutionError as error:
        return CaseScore(
            loaded_case.name,
            loaded_case.analyzer,
            "error",
            selected,
            reason=str(error),
        )
    except Exception as error:
        return CaseScore(
            loaded_case.name,
            loaded_case.analyzer,
            "error",
            selected,
            reason=f"unexpected corpus execution failure: {type(error).__name__}",
        )


@dataclass
class _AnalyzerAccumulator:
    cases_run: int = 0
    cases_skipped: int = 0
    cases_failed: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0


def aggregate(scores: Iterable[CaseScore]) -> dict[str, AnalyzerScore]:
    """Micro-aggregate case scores per registered analyzer."""
    accumulators = {name: _AnalyzerAccumulator() for name in _registered_analyzer_names()}
    for score in scores:
        for analyzer in score.analyzers_evaluated:
            accumulator = accumulators[analyzer]
            if score.status == "skipped":
                accumulator.cases_skipped += 1
            elif score.status == "error":
                accumulator.cases_failed += 1
            else:
                accumulator.cases_run += 1
                if not score.passed:
                    accumulator.cases_failed += 1
        for match in score.matches:
            accumulators[match.expected.analyzer].true_positives += 1
        for missing in score.missing:
            accumulators[missing.analyzer].false_negatives += 1
        for unexpected in score.unexpected:
            accumulators[unexpected.analyzer].false_positives += 1
    return {
        name: AnalyzerScore(analyzer=name, **vars(accumulator))
        for name, accumulator in accumulators.items()
    }


def check_thresholds(
    scores: dict[str, AnalyzerScore],
    thresholds: ThresholdFile | Path = THRESHOLDS_PATH,
    *,
    strict: bool | None = None,
) -> list[ThresholdFailure]:
    """Return every metric, coverage, or execution failure."""
    configured = load_thresholds(thresholds) if isinstance(thresholds, Path) else thresholds
    failures: list[ThresholdFailure] = []
    strict_enabled = _strict_mode(strict)
    for analyzer, minimums in configured.analyzers.items():
        score = scores.get(analyzer)
        if score is None:
            failures.append(ThresholdFailure(analyzer, "coverage", "analyzer has no aggregate score"))
            continue
        if score.cases_failed:
            failures.append(ThresholdFailure(analyzer, "cases", "one or more cases failed"))
        has_positive_case = score.true_positives + score.false_negatives > 0
        if not has_positive_case:
            if score.cases_skipped and not strict_enabled:
                continue
            failures.append(ThresholdFailure(analyzer, "coverage", "no positive case was evaluated"))
            continue
        if score.precision < minimums.precision:
            failures.append(
                ThresholdFailure(
                    analyzer,
                    "precision",
                    "precision is below threshold",
                    score.precision,
                    minimums.precision,
                )
            )
        if score.recall < minimums.recall:
            failures.append(
                ThresholdFailure(
                    analyzer,
                    "recall",
                    "recall is below threshold",
                    score.recall,
                    minimums.recall,
                )
            )
    return failures


def _format_location(file: str | None, line: int | tuple[int, int] | None) -> str:
    path = file or "<project>"
    if line is None:
        return path
    if isinstance(line, tuple):
        return f"{path}:{line[0]}-{line[1]}"
    return f"{path}:{line}"


def _print_case_failures(scores: list[CaseScore]) -> None:
    for score in scores:
        if score.passed or score.status == "skipped":
            continue
        print(f"\nCase {score.case_name}: FAIL")
        if score.reason:
            print(f"  {score.reason}")
        for missing in score.missing:
            location = _format_location(missing.file, missing.lines)
            print(f"  missing {missing.analyzer}/{missing.code} {location} {missing.severity}")
        for unexpected in score.unexpected:
            location = _format_location(unexpected.file, unexpected.line)
            print(f"  unexpected {unexpected.analyzer}/{unexpected.code} {location} {unexpected.severity}")
        for forbidden in score.forbidden:
            location = _format_location(forbidden.file, forbidden.line)
            print(f"  forbidden {forbidden.analyzer}/{forbidden.code} {location} {forbidden.severity}")


def _analyzer_result_label(
    score: AnalyzerScore,
    failures: list[ThresholdFailure],
) -> str:
    if any(failure.analyzer == score.analyzer for failure in failures):
        return "FAIL"
    if not score.true_positives and score.cases_skipped:
        return "SKIP"
    return "PASS"


def _print_analyzer_table(
    aggregated: dict[str, AnalyzerScore],
    thresholds: ThresholdFile,
    failures: list[ThresholdFailure],
) -> None:
    print("Analyzer      Run Skip  TP  FP  FN  Precision  Min  Recall  Min  Result")
    print("------------ --- ---- --- --- --- ---------- ---- ------- ---- ------")
    for analyzer in sorted(thresholds.analyzers):
        score = aggregated[analyzer]
        minimums = thresholds.analyzers[analyzer]
        result = _analyzer_result_label(score, failures)
        print(
            f"{analyzer:<12} {score.cases_run:>3} {score.cases_skipped:>4} "
            f"{score.true_positives:>3} {score.false_positives:>3} "
            f"{score.false_negatives:>3} {score.precision:>10.3f} "
            f"{minimums.precision:>4.2f} {score.recall:>7.3f} "
            f"{minimums.recall:>4.2f} {result:>6}"
        )


def _select_cases(cases: list[CorpusCase], requested: list[str] | None) -> list[CorpusCase]:
    if not requested:
        return cases
    requested_names = set(requested)
    known_names = {case.name for case in cases}
    unknown = requested_names - known_names
    if unknown:
        raise ScorerConfigurationError(f"unknown case(s): {', '.join(sorted(unknown))}")
    return [case for case in cases if case.name in requested_names]


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS_DIR)
    parser.add_argument("--thresholds", type=Path, default=THRESHOLDS_PATH)
    parser.add_argument("--case", action="append", dest="cases")
    parser.add_argument("--strict", action="store_true", default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the corpus scorer and print a deterministic CI-friendly table."""
    arguments = _argument_parser().parse_args(argv)
    try:
        cases = _select_cases(discover_cases(arguments.corpus), arguments.cases)
        thresholds = load_thresholds(arguments.thresholds)
        strict = _strict_mode(arguments.strict)
        scores = [score_case(case, strict=strict) for case in cases]
        aggregated = aggregate(scores)
        failures = check_thresholds(aggregated, thresholds, strict=strict)
    except ScorerConfigurationError as error:
        print(f"Configuration error: {error}", file=sys.stderr)
        return 2

    _print_analyzer_table(aggregated, thresholds, failures)
    _print_case_failures(scores)
    failed_cases = any(score.status == "error" or not score.passed for score in scores if score.status != "skipped")
    return 1 if failures or failed_cases else 0


if __name__ == "__main__":
    raise SystemExit(main())
