"""Security analyzer — hardcoded secrets, exposed .env, debug mode."""

from __future__ import annotations

import re
from pathlib import Path

from repomedic.analyzers import register
from repomedic.analyzers.base import BaseAnalyzer
from repomedic.core.context import ScanContext
from repomedic.models import AnalyzerResult, Category, Finding, Severity

# Patterns for hardcoded secrets (name, regex)
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS Access Key", re.compile(r"""(?:"|')?(AKIA[0-9A-Z]{16})(?:"|')?""")),
    ("AWS Secret Key", re.compile(r"""(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*(?:"|')?([A-Za-z0-9/+=]{40})""")),
    ("OpenAI API Key", re.compile(r"""(?:"|')?(sk-(?:proj-)?[A-Za-z0-9]{20,})(?:"|')?""")),
    ("Stripe Secret Key", re.compile(r"""(?:"|')?(sk_(?:live|test)_[A-Za-z0-9]{20,})(?:"|')?""")),
    ("GitHub Token", re.compile(r"""(?:"|')?(ghp_[A-Za-z0-9]{36,})(?:"|')?""")),
    ("GitHub Token", re.compile(r"""(?:"|')?(github_pat_[A-Za-z0-9_]{22,})(?:"|')?""")),
    ("Generic Secret", re.compile(r"""(?:password|passwd|api_key|apikey|secret_key|secret)\s*[=:]\s*(?:"|')([^"'\s]{8,})(?:"|')""", re.IGNORECASE)),
]

# Safe placeholder values to ignore in generic secret detection
_SAFE_VALUES = {
    "changeme", "placeholder", "your-key-here", "your_key_here",
    "xxxxxxxx", "todo", "fixme", "example", "test1234", "password",
    "replace_me", "insert_here", "dummy_value",
}
_SAFE_PREFIXES = ("django-insecure-", "your-", "example-", "test-", "fake-", "dummy-")

# File extensions to scan for secrets
_CODE_EXTENSIONS = {".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".java", ".yaml", ".yml", ".toml", ".cfg", ".ini", ".conf"}


@register
class SecurityAnalyzer(BaseAnalyzer):
    name = "security"
    description = "Hardcoded secrets, exposed .env files, debug mode detection"

    def analyze(self, ctx: ScanContext) -> AnalyzerResult:
        findings: list[Finding] = []
        findings.extend(self._check_hardcoded_secrets(ctx))
        findings.extend(self._check_env_tracked(ctx))
        findings.extend(self._check_debug_mode(ctx))
        return AnalyzerResult(analyzer=self.name, findings=findings)

    def _check_hardcoded_secrets(self, ctx: ScanContext) -> list[Finding]:
        import json
        import tempfile
        from repomedic.utils.process import run

        # Try gitleaks first
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            report_path = tmp.name

        # gitleaks detect --no-git --report-format json --report-path <file> --source <dir>
        result = run(
            ["gitleaks", "detect", "--no-git", "--report-format", "json", "--report-path", report_path, "--source", str(ctx.target)],
            cwd=str(ctx.target),
            timeout=120,
        )

        findings: list[Finding] = []
        if result.ran:  # gitleaks is installed
            try:
                with open(report_path, encoding="utf-8") as f:
                    leaks = json.load(f)
                for leak in leaks:
                    try:
                        rel = str(Path(leak["File"]).relative_to(ctx.target))
                    except ValueError:
                        rel = str(leak.get("File", ""))
                    
                    findings.append(
                        Finding(
                            category=Category.security,
                            severity=Severity.error,
                            code="SEC-001",
                            title=f"Hardcoded secret: {leak.get('RuleID', 'Unknown')}",
                            description=f"Gitleaks detected {leak.get('Description', 'a secret')}.",
                            file_path=rel,
                            line=leak.get("StartLine"),
                            suggestion="Move this secret to a .env file and load it via environment variables. Never commit secrets to version control.",
                            metadata={"gitleaks_rule": leak.get("RuleID"), "match": leak.get("Match")},
                        )
                    )
            except (json.JSONDecodeError, FileNotFoundError, KeyError):
                pass
            finally:
                Path(report_path).unlink(missing_ok=True)

            # Also run regex fallback to catch patterns gitleaks might miss
            findings.extend(self._check_secrets_regex(ctx))
            # Deduplicate by file_path + line
            seen: set[tuple[str | None, int | None]] = set()
            deduped: list[Finding] = []
            for finding in findings:
                key = (finding.file_path, finding.line)
                if key not in seen:
                    seen.add(key)
                    deduped.append(finding)
            return deduped

        # Fallback to regex if gitleaks is not installed
        Path(report_path).unlink(missing_ok=True)
        return self._check_secrets_regex(ctx)

    def _check_secrets_regex(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        code_files = [f for f in ctx.files if f.suffix in _CODE_EXTENSIONS]
        for filepath in code_files:
            try:
                content = filepath.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_no, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue
                for secret_name, pattern in _SECRET_PATTERNS:
                    match = pattern.search(line)
                    if match:
                        # Skip safe placeholder values
                        matched_value = match.group(1) if match.lastindex else match.group(0)
                        if matched_value.lower() in _SAFE_VALUES or any(
                            matched_value.lower().startswith(p) for p in _SAFE_PREFIXES
                        ):
                            continue
                        try:
                            rel = str(filepath.relative_to(ctx.target))
                        except ValueError:
                            rel = str(filepath)
                        findings.append(
                            Finding(
                                category=Category.security,
                                severity=Severity.error,
                                code="SEC-001",
                                title=f"Hardcoded secret: {secret_name}",
                                description=f"Possible {secret_name} found in source code.",
                                file_path=rel,
                                line=line_no,
                                suggestion="Move this secret to a .env file and load it via environment variables. Never commit secrets to version control.",
                            )
                        )
                        break  # one finding per line
        return findings

    def _check_env_tracked(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        env_file = ctx.target / ".env"
        if not env_file.is_file():
            return findings

        # Check if .env is gitignored — prefer git check-ignore for accuracy
        from repomedic.utils.process import run
        env_ignored = False
        if ctx.has_git:
            result = run(["git", "check-ignore", "-q", ".env"], cwd=str(ctx.target), timeout=5)
            env_ignored = result.ok
        if not env_ignored:
            gitignore = ctx.target / ".gitignore"
            if gitignore.is_file():
                try:
                    content = gitignore.read_text(encoding="utf-8", errors="replace")
                    for line in content.splitlines():
                        line = line.strip()
                        if line.startswith("!"):
                            continue
                        if line in (".env", "*.env", ".env*", ".env.*", "**/.env"):
                            env_ignored = True
                            break
                except OSError:
                    pass

        if not env_ignored:
            findings.append(
                Finding(
                    category=Category.security,
                    severity=Severity.error,
                    code="SEC-002",
                    title=".env file not gitignored",
                    description="Your .env file is not listed in .gitignore. Secrets may be exposed if committed.",
                    file_path=".env",
                    suggestion="Add '.env' to your .gitignore file immediately. Run: echo '.env' >> .gitignore",
                )
            )
        return findings

    def _check_debug_mode(self, ctx: ScanContext) -> list[Finding]:
        findings = []
        debug_pattern = re.compile(r"""^\s*DEBUG\s*=\s*True\b""")
        for py_file in ctx.python_files:
            try:
                content = py_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line_no, line in enumerate(content.splitlines(), 1):
                if debug_pattern.match(line):
                    try:
                        rel = str(py_file.relative_to(ctx.target))
                    except ValueError:
                        rel = str(py_file)
                    findings.append(
                        Finding(
                            category=Category.security,
                            severity=Severity.warning,
                            code="SEC-003",
                            title="DEBUG mode enabled",
                            description="DEBUG = True found in code. This should be False in production.",
                            file_path=rel,
                            line=line_no,
                            suggestion="Set DEBUG = False for production. Use environment variables: DEBUG = os.getenv('DEBUG', 'False') == 'True'",
                        )
                    )
        return findings
