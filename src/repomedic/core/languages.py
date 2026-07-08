"""Language registry — central knowledge of languages, extensions, and toolchains.

Every part of repomedic that needs to reason about languages (detection,
markdown fences, per-language verify commands) goes through this registry,
so adding a language is a one-line change here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class LanguageSpec:
    """Static knowledge about one programming language."""

    name: str
    extensions: tuple[str, ...]
    filenames: tuple[str, ...] = ()
    fence: str = ""  # markdown code-fence hint; defaults to name
    verify_commands: tuple[str, ...] = field(default=())

    @property
    def fence_hint(self) -> str:
        return self.fence or self.name


LANGUAGES: tuple[LanguageSpec, ...] = (
    LanguageSpec(
        "python",
        (".py", ".pyi", ".pyw"),
        verify_commands=("python -m compileall -q .", "ruff check ."),
    ),
    LanguageSpec(
        "javascript",
        (".js", ".jsx", ".mjs", ".cjs"),
        verify_commands=("npx --no-install eslint .",),
    ),
    LanguageSpec(
        "typescript",
        (".ts", ".tsx", ".mts", ".cts"),
        fence="typescript",
        verify_commands=("npx --no-install tsc --noEmit",),
    ),
    LanguageSpec("go", (".go",), ("go.mod",), verify_commands=("go build ./...", "go vet ./...")),
    LanguageSpec("rust", (".rs",), ("Cargo.toml",), verify_commands=("cargo check",)),
    LanguageSpec("java", (".java",), ("pom.xml", "build.gradle", "build.gradle.kts")),
    LanguageSpec("kotlin", (".kt", ".kts")),
    LanguageSpec("c", (".c", ".h")),
    LanguageSpec("cpp", (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx"), fence="cpp"),
    LanguageSpec("csharp", (".cs",), fence="csharp"),
    LanguageSpec("ruby", (".rb", ".rake"), ("Gemfile",), verify_commands=("ruby -c <file>",)),
    LanguageSpec("php", (".php",), ("composer.json",), verify_commands=("php -l <file>",)),
    LanguageSpec("swift", (".swift",), ("Package.swift",)),
    LanguageSpec("scala", (".scala", ".sbt")),
    LanguageSpec(
        "shell",
        (".sh", ".bash", ".zsh"),
        fence="bash",
        verify_commands=("bash -n <file>", "shellcheck <file>"),
    ),
    LanguageSpec("powershell", (".ps1", ".psm1"), fence="powershell"),
    LanguageSpec("sql", (".sql",)),
    LanguageSpec("html", (".html", ".htm")),
    LanguageSpec("css", (".css", ".scss", ".sass", ".less")),
    LanguageSpec("r", (".r", ".R"), fence="r"),
    LanguageSpec("lua", (".lua",)),
    LanguageSpec("perl", (".pl", ".pm")),
    LanguageSpec("dart", (".dart",), ("pubspec.yaml",)),
    LanguageSpec("elixir", (".ex", ".exs"), ("mix.exs",)),
    LanguageSpec("erlang", (".erl", ".hrl")),
    LanguageSpec("haskell", (".hs",)),
    LanguageSpec("zig", (".zig",)),
    LanguageSpec("clojure", (".clj", ".cljs", ".cljc")),
    LanguageSpec("julia", (".jl",)),
    LanguageSpec("objective-c", (".m", ".mm"), fence="objectivec"),
    LanguageSpec("terraform", (".tf", ".tfvars"), fence="hcl"),
    LanguageSpec("dockerfile", (), ("Dockerfile", "Containerfile"), fence="dockerfile"),
    LanguageSpec("make", (), ("Makefile", "makefile", "GNUmakefile"), fence="makefile"),
)

# Data/config formats — not counted as programming languages, but used for
# fence hints and universal syntax checking.
DATA_FORMATS: dict[str, str] = {
    ".json": "json",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".toml": "toml",
    ".xml": "xml",
    ".ini": "ini",
    ".cfg": "ini",
    ".md": "markdown",
    ".txt": "text",
}

_EXTENSION_MAP: dict[str, LanguageSpec] = {}
_FILENAME_MAP: dict[str, LanguageSpec] = {}
for _spec in LANGUAGES:
    for _ext in _spec.extensions:
        _EXTENSION_MAP.setdefault(_ext.lower(), _spec)
    for _fname in _spec.filenames:
        _FILENAME_MAP.setdefault(_fname, _spec)


def spec_for(name: str) -> LanguageSpec | None:
    """Look up a language spec by name."""
    return next((s for s in LANGUAGES if s.name == name), None)


def language_for_path(path: Path | str) -> str | None:
    """Return the language name for a file path, or None if unknown."""
    p = Path(path)
    spec = _FILENAME_MAP.get(p.name) or _EXTENSION_MAP.get(p.suffix.lower())
    return spec.name if spec else None


def fence_for_path(path: Path | str) -> str:
    """Return the markdown code-fence hint for a file path."""
    p = Path(path)
    spec = _FILENAME_MAP.get(p.name) or _EXTENSION_MAP.get(p.suffix.lower())
    if spec:
        return spec.fence_hint
    return DATA_FORMATS.get(p.suffix.lower(), "")


def detect_languages(files: list[Path]) -> dict[str, int]:
    """Count files per language, sorted by file count descending."""
    counts: dict[str, int] = {}
    for f in files:
        lang = language_for_path(f)
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: (-kv[1], kv[0])))


def verify_commands_for(languages: list[str] | set[str]) -> list[str]:
    """Collect per-language verification commands for the given languages."""
    commands: list[str] = []
    for lang in languages:
        spec = spec_for(lang)
        if spec:
            commands.extend(spec.verify_commands)
    return commands
