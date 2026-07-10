"""Typed payloads for the non-scan commands (doctor, explain, fix, list-analyzers).

Scan output has always been a schema-versioned pydantic model
(:class:`repomedic.models.ScanReport`); the other commands used to emit
ad-hoc dicts, which meant machine consumers had no stable, validatable
shape. Each payload here carries its own ``schema_version`` (independent of
the scan report's) with the same policy: bump on removed/renamed fields or
semantics changes; additive fields do not bump.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

COMMAND_SCHEMA_VERSION = 1


class DoctorCheck(BaseModel):
    name: str
    info: str
    status: Literal["OK", "MISSING", "OPTIONAL"]


class DoctorReport(BaseModel):
    """`repomedic doctor` — environment/toolchain health."""

    tool: Literal["repomedic"] = "repomedic"
    schema_version: int = COMMAND_SCHEMA_VERSION
    target: str
    checks: list[DoctorCheck] = Field(default_factory=list)
    fix_commands: list[str] = Field(default_factory=list)
    healthy: bool = True


class DependencyInfo(BaseModel):
    name: str
    description: str


class ExplainReport(BaseModel):
    """`repomedic explain` — project brief."""

    tool: Literal["repomedic"] = "repomedic"
    schema_version: int = COMMAND_SCHEMA_VERSION
    target: str
    project_type: str
    languages: dict[str, int] = Field(default_factory=dict)
    dependencies: list[DependencyInfo] = Field(default_factory=list)
    file_count: int = 0


class FixAction(BaseModel):
    action: str
    description: str
    status: Literal["FIXED", "WOULD FIX", "SKIPPED", "ERROR"]


class FixReport(BaseModel):
    """`repomedic fix` — applied (or previewed) auto-fixes."""

    tool: Literal["repomedic"] = "repomedic"
    schema_version: int = COMMAND_SCHEMA_VERSION
    target: str
    dry_run: bool = False
    actions: list[FixAction] = Field(default_factory=list)


class AnalyzerInfo(BaseModel):
    name: str
    description: str


class AnalyzerList(BaseModel):
    """`repomedic list-analyzers`."""

    tool: Literal["repomedic"] = "repomedic"
    schema_version: int = COMMAND_SCHEMA_VERSION
    analyzers: list[AnalyzerInfo] = Field(default_factory=list)
