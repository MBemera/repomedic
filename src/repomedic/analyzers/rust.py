"""Rust analyzer — cargo check, clippy, dependency analysis."""

from __future__ import annotations

import json
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity
from repomedic.utils.process import run


@register
class RustAnalyzer(BaseAnalyzer):
    name = "rust"
    description = "Cargo check, Clippy linting, dependency analysis"

    def is_applicable(self, ctx: ScanContext) -> bool:
        return len(ctx.rust_files) > 0 or ctx.has_cargo_toml

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []

        # 1. Dependency checks first — `cargo check` generates Cargo.lock as a
        #    side effect, so the lock-file check must observe the state before it.
        findings.extend(self._check_dependencies(ctx))

        # 2. Cargo check (compile errors)
        findings.extend(self._cargo_check(ctx))

        # 3. Clippy (lint warnings) — only if cargo check passed
        if not any(f.severity == Severity.error for f in findings):
            findings.extend(self._run_clippy(ctx))

        # 4. Cargo audit for vulnerabilities
        findings.extend(self._run_cargo_audit(ctx))

        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _cargo_check(self, ctx: ScanContext) -> list[Finding]:
        """Run cargo check to detect compile errors."""
        if not ctx.has_cargo_toml:
            return []

        result = run(
            ["cargo", "check", "--message-format=json"],
            cwd=str(ctx.target),
            timeout=120,
        )

        if not result.ran:
            return []  # cargo not installed

        return self._parse_cargo_json(ctx, result.stdout, is_clippy=False)

    def _run_clippy(self, ctx: ScanContext) -> list[Finding]:
        """Run cargo clippy for lint warnings."""
        if not ctx.has_cargo_toml:
            return []

        result = run(
            ["cargo", "clippy", "--message-format=json", "--", "-W", "clippy::all"],
            cwd=str(ctx.target),
            timeout=120,
        )

        if not result.ran:
            return []

        return self._parse_cargo_json(ctx, result.stdout, is_clippy=True)

    def _parse_cargo_json(self, ctx: ScanContext, stdout: str, *, is_clippy: bool) -> list[Finding]:
        """Parse cargo/clippy JSON output into findings."""
        findings = []
        seen_messages: set[str] = set()

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue

            if msg.get("reason") != "compiler-message":
                continue

            compiler_msg = msg.get("message", {})
            level = compiler_msg.get("level", "")
            message_text = compiler_msg.get("message", "")

            # Deduplicate
            dedup_key = f"{level}:{message_text}"
            if dedup_key in seen_messages:
                continue
            seen_messages.add(dedup_key)

            # Determine severity
            if level == "error":
                severity = Severity.error
            elif level in ("warning", "note"):
                severity = Severity.warning
            else:
                continue

            # Extract file location from spans
            spans = compiler_msg.get("spans", [])
            file_path = None
            line_num = None
            col_num = None
            if spans:
                primary = next((s for s in spans if s.get("is_primary")), spans[0])
                file_path = primary.get("file_name")
                line_num = primary.get("line_start")
                col_num = primary.get("column_start")

            if file_path:
                try:
                    file_path = str(Path(file_path).relative_to(ctx.target))
                except ValueError:
                    pass

            # Build suggestion from children
            suggestion_parts = []
            for child in compiler_msg.get("children", []):
                if child.get("level") == "help":
                    suggestion_parts.append(child.get("message", ""))
            suggestion = "; ".join(suggestion_parts) if suggestion_parts else f"Fix the {'Clippy' if is_clippy else 'compile'} {'warning' if severity == Severity.warning else 'error'}"

            code_str = compiler_msg.get("code", {})
            code_val = code_str.get("code", "unknown") if isinstance(code_str, dict) else "unknown"
            prefix = "RUST-CLIPPY" if is_clippy else "RUST"

            findings.append(
                Finding(
                    category=Category.static_analysis,
                    severity=severity,
                    code=f"{prefix}-{code_val}",
                    title=f"{'Clippy' if is_clippy else 'Rust'}: {code_val}",
                    description=message_text,
                    file_path=file_path,
                    line=line_num,
                    column=col_num,
                    suggestion=suggestion,
                    language="rust",
                    metadata={"rust_code": code_val},
                )
            )

        return findings

    def _check_dependencies(self, ctx: ScanContext) -> list[Finding]:
        """Check Rust dependency health."""
        findings = []

        if ctx.rust_files and not ctx.has_cargo_toml:
            findings.append(
                Finding(
                    category=Category.dependency,
                    severity=Severity.warning,
                    code="RUST-DEP-001",
                    title="No Cargo.toml found",
                    description="Rust source files found but no Cargo.toml manifest.",
                    suggestion="Initialize a Cargo project: cargo init",
                    language="rust",
                )
            )
            return findings

        if not ctx.has_cargo_toml:
            return findings

        # Check for Cargo.lock
        if not (ctx.target / "Cargo.lock").is_file():
            findings.append(
                Finding(
                    category=Category.dependency,
                    severity=Severity.info,
                    code="RUST-DEP-002",
                    title="No Cargo.lock file",
                    description="Cargo.toml exists but Cargo.lock is missing. For applications, this should be committed.",
                    suggestion="Generate Cargo.lock: cargo generate-lockfile",
                    language="rust",
                )
            )

        return findings

    def _run_cargo_audit(self, ctx: ScanContext) -> list[Finding]:
        """Run cargo-audit to find vulnerable dependencies."""
        if not ctx.has_cargo_toml:
            return []

        result = run(
            ["cargo", "audit", "--json"],
            cwd=str(ctx.target),
            timeout=120,
        )

        if not result.ran:
            return []  # cargo-audit not installed

        try:
            data = json.loads(result.stdout) if result.stdout.strip() else {}
        except json.JSONDecodeError:
            return []

        findings = []
        vulns = data.get("vulnerabilities", {}).get("list", [])
        for vuln in vulns:
            adv = vuln.get("advisory", {})
            pkg_name = adv.get("package", "unknown")
            vuln_id = adv.get("id", "UNKNOWN")
            title = adv.get("title", f"Vulnerability in {pkg_name}")
            desc = adv.get("description", "")
            patched = vuln.get("versions", {}).get("patched", [])
            
            suggestion = f"Update '{pkg_name}'"
            if patched:
                suggestion += f" to a patched version: {', '.join(patched)}"
                
            findings.append(
                Finding(
                    category=Category.security,
                    severity=Severity.error,
                    code=f"RUST-AUDIT-{vuln_id}",
                    title=f"Cargo vulnerability: {title}",
                    description=desc[:500],
                    file_path="Cargo.toml",
                    suggestion=suggestion,
                    language="rust",
                    metadata={"cargo_audit_id": vuln_id},
                )
            )

        return findings
