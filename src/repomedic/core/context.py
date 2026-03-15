"""ScanContext — discovers files and classifies the target project."""

from __future__ import annotations

from pathlib import Path

from repomedic.utils.fs import discover_files


class ScanContext:
    """Holds information about the target directory being scanned."""

    def __init__(self, target: str | Path, skip_tests: bool = True) -> None:
        self.target = Path(target).resolve()
        self.skip_tests = skip_tests
        if not self.target.is_dir():
            raise FileNotFoundError(f"Target directory not found: {self.target}")

        self._files: list[Path] | None = None

    @property
    def files(self) -> list[Path]:
        if self._files is None:
            self._files = discover_files(self.target, skip_tests=self.skip_tests)
        return self._files

    @property
    def python_files(self) -> list[Path]:
        return [f for f in self.files if f.suffix == ".py"]

    @property
    def js_ts_files(self) -> list[Path]:
        return [f for f in self.files if f.suffix in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}]

    @property
    def go_files(self) -> list[Path]:
        return [f for f in self.files if f.suffix == ".go"]

    @property
    def rust_files(self) -> list[Path]:
        return [f for f in self.files if f.suffix == ".rs"]

    @property
    def has_git(self) -> bool:
        return (self.target / ".git").is_dir()

    @property
    def has_pyproject(self) -> bool:
        return (self.target / "pyproject.toml").is_file()

    @property
    def has_requirements_txt(self) -> bool:
        return (self.target / "requirements.txt").is_file()

    @property
    def has_package_json(self) -> bool:
        return (self.target / "package.json").is_file()

    @property
    def has_go_mod(self) -> bool:
        return (self.target / "go.mod").is_file()

    @property
    def has_cargo_toml(self) -> bool:
        return (self.target / "Cargo.toml").is_file()

    @property
    def has_tsconfig(self) -> bool:
        return (self.target / "tsconfig.json").is_file()

    @property
    def has_dockerfile(self) -> bool:
        return (self.target / "Dockerfile").is_file()

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
    def detected_languages(self) -> set[str]:
        """Return the set of programming languages detected in the project."""
        langs: set[str] = set()
        if self.python_files:
            langs.add("python")
        if self.js_ts_files:
            langs.add("javascript")
        if self.go_files:
            langs.add("go")
        if self.rust_files:
            langs.add("rust")
        return langs
