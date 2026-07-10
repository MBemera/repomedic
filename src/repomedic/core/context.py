"""ScanContext — discovers files and classifies the target project."""

from __future__ import annotations

from pathlib import Path

from repomedic.core.languages import detect_languages, language_for_path
from repomedic.utils.fs import discover_files


class ScanContext:
    """Holds information about the target directory being scanned."""

    def __init__(
        self,
        target: str | Path,
        skip_tests: bool = True,
        extra_ignore_dirs: set[str] | None = None,
        allow_exec: bool = True,
    ) -> None:
        self.target = Path(target).resolve()
        self.skip_tests = skip_tests
        self.extra_ignore_dirs = extra_ignore_dirs or set()
        # Whether analyzers may run tools that execute repo-controlled code
        # (cargo check runs build.rs, eslint loads eslint.config.js, ...).
        # False for untrusted targets, e.g. freshly cloned URLs.
        self.allow_exec = allow_exec
        if not self.target.is_dir():
            raise FileNotFoundError(f"Target directory not found: {self.target}")

        self._files: list[Path] | None = None
        self._by_language: dict[str, list[Path]] | None = None

    @property
    def files(self) -> list[Path]:
        if self._files is None:
            self._files = discover_files(
                self.target,
                skip_tests=self.skip_tests,
                extra_ignore_dirs=self.extra_ignore_dirs,
            )
        return self._files

    @property
    def files_by_language(self) -> dict[str, list[Path]]:
        """Map of language name -> files, per the language registry."""
        if self._by_language is None:
            grouped: dict[str, list[Path]] = {}
            for f in self.files:
                lang = language_for_path(f)
                if lang:
                    grouped.setdefault(lang, []).append(f)
            self._by_language = grouped
        return self._by_language

    def files_for(self, language: str) -> list[Path]:
        """Files belonging to a given language (empty list if none)."""
        return self.files_by_language.get(language, [])

    @property
    def python_files(self) -> list[Path]:
        return self.files_for("python")

    @property
    def js_ts_files(self) -> list[Path]:
        return self.files_for("javascript") + self.files_for("typescript")

    @property
    def go_files(self) -> list[Path]:
        return self.files_for("go")

    @property
    def rust_files(self) -> list[Path]:
        return self.files_for("rust")

    @property
    def shell_files(self) -> list[Path]:
        return self.files_for("shell")

    def has_file(self, name: str) -> bool:
        """True if a top-level file with this name exists in the target."""
        return (self.target / name).is_file()

    @property
    def has_git(self) -> bool:
        return (self.target / ".git").is_dir()

    @property
    def has_pyproject(self) -> bool:
        return self.has_file("pyproject.toml")

    @property
    def has_requirements_txt(self) -> bool:
        return self.has_file("requirements.txt")

    @property
    def has_package_json(self) -> bool:
        return self.has_file("package.json")

    @property
    def has_go_mod(self) -> bool:
        return self.has_file("go.mod")

    @property
    def has_cargo_toml(self) -> bool:
        return self.has_file("Cargo.toml")

    @property
    def has_tsconfig(self) -> bool:
        return self.has_file("tsconfig.json")

    @property
    def has_dockerfile(self) -> bool:
        return self.has_file("Dockerfile")

    @property
    def log_files(self) -> list[Path]:
        return [f for f in self.files if f.suffix == ".log"]

    @property
    def config_files(self) -> list[Path]:
        names = {
            "pyproject.toml",
            "setup.cfg",
            "setup.py",
            "package.json",
            "Dockerfile",
            ".env",
            "docker-compose.yml",
            "docker-compose.yaml",
            "Cargo.toml",
            "go.mod",
            "tsconfig.json",
        }
        return [f for f in self.files if f.name in names]

    @property
    def data_files(self) -> list[Path]:
        """JSON/YAML/TOML files across the project (for syntax validation)."""
        return [f for f in self.files if f.suffix.lower() in {".json", ".yaml", ".yml", ".toml"}]

    @property
    def language_counts(self) -> dict[str, int]:
        """Language name -> file count, sorted by count descending."""
        return detect_languages(self.files)

    @property
    def detected_languages(self) -> set[str]:
        """Return the set of programming languages detected in the project."""
        return set(self.language_counts)
