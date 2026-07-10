# RepoMedic: Review, Agent Workflows, VS Code Debugger, and V&V Framework

> **Status (2026-07-10): Phase 2 in progress (v0.4.0)** — Phases 0–1 are complete.
> Phase 2.1 is now implemented: bounded stdlib DAP transport, loopback-only
> `debugpy` crash capture, process-group deadline enforcement, bounded/redacted
> frames and locals, and real-adapter tests. Phase 0: CI bootstrap,
> ProcessResult redesign, scan_service extraction, per-analyzer timeouts, shared
> helpers, symlink containment + hardened git, --exec/--no-exec trust model,
> report sanitization + secret redaction, fingerprint v2 + schema 3, typed
> command payloads + py.typed. Phase 1: SARIF 2.1.0 output, baseline + inline
> suppressions (core/postprocess shared pass), MCP server (8 service-backed
> tools, exec off by default), agents-guide single-sourcing (data/AGENTS.md),
> composite GitHub Action + pre-commit hook + CI action-selftest, `schema`
> export command. Each numbered item maps to one commit on this branch.
> **Next: Phase 2.2** (runtime analyzer refactor and `repomedic debug` CLI).

## Context

RepoMedic (v0.2.0) is an **agent-first repo bug sniffer**: a Python 3.11+ CLI (typer / pydantic v2 / rich /
pyyaml, ~4,900 LOC, 13 analyzers, schema_version 2) that scans a repo and emits a markdown/JSON fix report
sized for an AI coding agent's context window. The user asked for four things: (1) a codebase review with
proposed changes, (2) more agent- and harness-compatible workflows, (3) a VS Code integration where RepoMedic
can drive the debugger for debugging/testing, and (4) a validation & verification framework that makes its
results "fundamentally sound and secure."

Three explore passes plus a design pass (all re-verified against source) found that the **core is well-built but
the tool has no security boundary and no output-validation story** — the two facts that dominate the plan:

- **Scanning executes repo-controlled code.** `cargo check`/`clippy` run `build.rs` + proc-macros (`rust.py:47,64`),
  `go build`/`vet` execute cgo pragmas (`golang.py:42,103`), `npx eslint`/`tsc` load `eslint.config.js`
  (`javascript.py:95,141,240`) — all unsandboxed with the **full inherited environment**. `repomedic <github-url>`
  makes this *clone-then-execute* untrusted code. `docs/AGENTS.md:16` falsely claims "Safe to run unattended."
- **Repo-controlled text flows unescaped into the agent report.** Finding `title`/`description`/`suggestion`
  render as raw markdown right under "Instructions for the coding agent" (`markdown_output.py:159-178, 25-30`),
  fed by log lines, script stderr, symlink targets, tool messages echoing source, and filenames — a textbook
  prompt-injection surface. Gitleaks secret matches are stored raw (`security.py:85`) and printed **verbatim** in
  JSON and in markdown snippets.

Other load-bearing findings: subprocess sentinels `NOT_FOUND=-1`/`TIMED_OUT=-2` **collide with signal-death
return codes** (a linter killed by SIGHUP reads as "not installed") across ~25 call sites; the fingerprint hashes
the line number so IDs break when code shifts (`models.py:55-60`); `cli._execute_scan` raises `typer.Exit` even on
success (`cli.py:257`) so orchestration can't be reused off the CLI; there is **no per-analyzer timeout**, **no
CI at all** (no `.github/`), no golden files, no accuracy corpus, and the subprocess output parsers have near-zero
test coverage (silently skipped when toolchains are absent). Symlinks escape the scan root (`fs.py:68-73`).

**Intended outcome:** a hardened, service-oriented RepoMedic that (a) is safe to point at untrusted repos, (b)
plugs into agent harnesses natively (MCP, SARIF, baseline/suppressions, GitHub Action), (c) can drive a real
debugger headlessly and from VS Code, and (d) is continuously validated for both accuracy and security.

The work is **four independently shippable phases**, ordered so each builds on the last. One deliberate
inversion: a minimal CI workflow is the *first commit of Phase 0*, because every later change refactors
load-bearing code and there is zero red/green signal today.

### Design principle: agents first, humans always (non-negotiable across all phases)

RepoMedic is dual-audience today — the agent path (`sniff`, `--output json/markdown/sarif`, exit codes, MCP) and
the human path (`repomedic [PATH]` rich TUI, `--interactive` analyzer picker, `doctor`/`explain`/`fix` rich output).
**Agents get priority — better defaults, structured output, native harness integration — but every capability
below remains usable by a human at the terminal.** Concretely, this plan guarantees:

- **No human command or flag is removed or hidden.** The rich TUI stays the default for bare `repomedic [PATH]`;
  `--interactive/-i`, `-o rich`, `doctor`, `explain`, `fix`, and `list-analyzers` keep their human-first rendering.
  Every new capability (SARIF, baseline, debug, selfcheck) is reachable from the CLI, not agent-only.
- **The two audiences get different *defaults*, not different *access*.** Local-target scans default `--exec` (a
  human debugging their own repo wants full toolchain power); URL scans and **every MCP tool** default `--no-exec`
  (untrusted/unattended). A human can always override with an explicit flag; an agent can pass `allow_exec=True`
  when it knows the target is trusted. Same code path, policy differs only in the default.
- **Sanitization (0.8) must not degrade the human read.** Fencing/quarantining untrusted text is applied to the
  *markdown/JSON/SARIF* agent surfaces; the **rich TUI keeps its clean, scannable tables and panels** (untrusted
  fields rendered with `markup=False` for safety, but *not* wrapped in visible ```` ``` ```` fences — a human sees
  normal text, styling-injection is neutralized invisibly). The health-score badge, severity buckets, and Next
  Steps panel are untouched.
- **The VS Code extension and `repomedic debug` are explicitly human surfaces too** — the debugger integration
  serves a developer clicking "Debug this finding" just as much as an agent calling the DAP capture headlessly.
- **`repomedic fix` stays interactive-safe for humans** (keeps `--dry-run` and rich output); only the *MCP*
  `fix_preview` tool is hard-wired to dry-run, because an unattended agent must never silently mutate a repo.

**Schema policy (all phases):** bump `SCHEMA_VERSION` 2 → 3 exactly once, in Phase 0 (fingerprint semantics +
report shape + new `skipped_checks`). Later phases are additive-only (new optional fields never bump). Non-scan
command payloads get their own independent `schema_version: 1`.

---

## Phase 0 — Correctness & security hardening (largest PR; splittable into 0a/0b)

Goal: make the tool safe against untrusted input, fix the correctness bugs, and extract the reusable service
layer that Phases 1–3 all depend on.

**0.1 Bootstrap CI** — `.github/workflows/ci.yml`: `lint` (ruff), `test` (matrix py3.11/3.12/3.13, `pytest -q`),
`typecheck` (mypy, lenient). No toolchains yet (tests already skip gracefully when tools absent).

**0.2 `ProcessResult` contract redesign** — rewrite `utils/process.py`. Replace the colliding int sentinels with a
`ProcessStatus` enum (`ok`/`not_found`/`timed_out`/`failed_to_start`) and `returncode: int | None` (real code only
when `ok`); add `.ran`/`.ok`/`.tool_missing` properties. `run()` gains `env_mode="isolated"` (default; builds env
from an `ENV_ALLOWLIST` so `AWS_*`/`GITHUB_TOKEN`/`OPENAI_API_KEY` never reach repo tools) vs `"inherit"` (only
`repomedic run`), plus a `max_output_bytes` cap (default 1 MiB/stream, sets `truncated`) via `Popen` +
bounded reader threads + `start_new_session=True` so timeouts `os.killpg` the whole process group. **Delete
`NOT_FOUND`/`TIMED_OUT`** so stale references fail at import. Migrate ~25 call sites per a mechanical table
(`returncode < 0` → `not result.ran`; `== NOT_FOUND` → `.tool_missing`; `>= 0` → `.ran`; `== 0` → `.ok`;
`!= 0` → `not result.ok`) across `static/javascript/golang/rust/shell/semgrep/security/runtime/fix/cli/vcs/doctor`.
Signal deaths now correctly read as "ran and crashed."

**0.3 `scan_service` extraction** — new `core/service.py` with `ScanRequest`/`ScanOutcome`/`run_scan(req, progress=)`
and `exit_code_for()` (moved from `cli.py:147`). `run_scan` does everything `_execute_scan` does *except* rendering
and `typer.Exit`: target resolve (incl. hardened clone `git clone --depth 1 -- <url> <dest>` with
`GIT_TERMINAL_PROMPT=0`), config merge, analyzer validation, changed-files, `Scanner().scan()`. `cli._execute_scan`
shrinks to build-request → `run_scan` → output branch → `raise typer.Exit(outcome.exit_code)` in
`try/finally: outcome.cleanup()`. The **human `--interactive/-i` analyzer picker stays in the CLI layer** — it
resolves names *before* the `ScanRequest` is built, so the service stays prompt-free for agents while humans keep
the picker. Remove dead code here: `get_analyzer_names()`, `run_fix()`, `run_doctor()`; keep `scan --all` as an
honest no-op.

**0.4 Per-analyzer timeout + cache warmup** — `core/scanner.py`: warm `ctx.files`/`ctx.files_by_language` on the
main thread (removes the fragile implicit cross-thread lazy-init); replace `pool.map` with `submit` +
`futures.wait(timeout=)` keyed to a per-analyzer deadline (default 120s); timed-out futures become
`AnalyzerResult(error="timed out …")`, executor `shutdown(cancel_futures=True, wait=False)`. New
`--analyzer-timeout` flag + config key. Documented limitation: threads can't be killed, so the real bound is that
*every* `run()` call carries an explicit subprocess timeout (audited in this commit).

**0.5 Shared helpers** — kill the dominant duplication: `run_json_tool()` (the NamedTemporaryFile→run→json→unlink
ceremony, adopted in bandit/gitleaks/semgrep/eslint/npm-audit/ruff); `TOOL_SEVERITY` table + `map_severity()` in
`analyzers/base.py` (6 ad-hoc sites); adopt existing `BaseAnalyzer._rel()` at the ~18 inline
`relative_to`/`except ValueError` sites; `fs.read_text_capped()` at the uncapped `read_text()` sites
(`security/git/logs/hygiene`).

**0.6 Symlink containment + file-walk rewrite** — rewrite `fs.discover_files` on `os.walk(followlinks=False)` with
in-place dir pruning (perf win too) and a `resolved.is_relative_to(root)` check for symlinked files (version-stable
for 3.11–3.13). Same containment guard in `markdown_output._snippet_for`. Git hardening: `vcs.run_git()` always
injects `-c core.fsmonitor=false -c core.hooksPath=` + isolated env (blocks the local-`.git/config` execution
vector); switch `changed_files` to `git status --porcelain -z -uall` with NUL parsing.

**0.7 Trust model `--exec/--no-exec`** — `ScanContext(allow_exec=...)`; gate only the code-executing checks inside
`rust`/`golang`/`javascript` (safe parse-only checks like `node --check`, go.mod/lockfile parsing stay). Gated
checks append to a new additive `AnalyzerResult.skipped_checks`. **Policy: local targets default `--exec`; GitHub-URL
targets default `--no-exec`;** `allow_exec` is deliberately **not** a `.repomedic.toml` key (a scanned repo must not
grant itself execution). Fix the `AGENTS.md:16` "safe to run unattended" claim with an honest exec-model paragraph.

**0.8 Output sanitization + secret redaction** — new `output/sanitize.py` with `sanitize_inline()` (collapse
newlines, neutralize backticks/pipes, length-cap — for headings/titles), `fenced_block()` (dynamic fence longer
than any backtick run in the payload — for descriptions/suggestions/analyzer errors), and `yaml_scalar()`
(`json.dumps` — unbreakable front matter). Apply per an explicit per-element table so untrusted text is quarantined
as *data* while the report stays readable; add one sentence to `AGENT_INSTRUCTIONS` telling the agent fenced blocks
are untrusted repo data. `rich_output.py` prints untrusted fields with `markup=False`. New `utils/redact.py`
`mask_secret()`; `security.py` stores `match_masked` (never raw `Match`), all secret-bearing findings set
`metadata["contains_secret"]`, and `_snippet_for` withholds the snippet for those findings.

**0.9 Fingerprint v2 + schema bump to 3** — `Finding.fingerprint` becomes a plain field; new `core/fingerprint.py`
`assign_fingerprints(results, root)` computes `"RM-"+sha1("2|"+code+"|"+file_path+"|"+normalized_line_content+"|"+occurrence)[:10]`
in one pass (per-file line cache). **Line-independent**: inserting/deleting lines above a finding keeps its ID;
editing the flagged line changes it (correct). Called before any filtering so a fingerprint is a property of repo
state, not flags. `SCHEMA_VERSION = 3`; drift-resistance test ships in the same commit. No dual-emit needed —
nothing persists fingerprints until Phase 1, which is exactly why v2 lands now.

**0.10 Typed command payloads + `py.typed`** — new `models_commands.py` (pydantic `DoctorReport`/`ExplainReport`/
`FixReport`/`AnalyzerInfo`, each `schema_version: 1`); `collect_doctor/explain/fixes` return models; `cli.py` emits
`model_dump_json` instead of ad-hoc dicts. Add `src/repomedic/py.typed`.

**pyproject:** dev += `mypy`; lenient `[tool.mypy]`; version → `0.3.0`.

**Verify:** `ruff check . && mypy src && pytest -q`; `repomedic sniff tests/fixtures/broken_imports` (exit 1,
renders); JSON asserts `schema_version==3`; scan a GitHub URL and observe `exec: disabled` + populated
`skipped_checks`; `repomedic doctor . -o json` typed; and a signal-death sanity check
(`run(["bash","-c","kill -SEGV $$"])` → `status ok`, `returncode == -11`).

---

## Phase 1 — Agent & harness workflows (PR: SARIF, baseline, suppressions, MCP, action/pre-commit)

**1.1 SARIF** — `output/sarif_output.py` `to_sarif(report)` (SARIF 2.1.0, single run): rules per unique `code`;
severity→`error/warning/note`; `message.text` = description + fix; relative POSIX `physicalLocation`;
`partialFingerprints = {"repomedicFingerprint/v2": fingerprint}` (v2's line-independence is what makes GitHub
code-scanning dedup work across pushes); `invocations` carry analyzer failures/`skipped_checks`. Add `--output
sarif` to scan/sniff.

**1.2 Baseline + inline suppressions** — `core/baseline.py` (`.repomedic-baseline.json` of fingerprints,
`write/load/apply_baseline`) + `core/suppress.py` (`# repomedic: ignore[CODE]` trailing or line-above; bare/exact/
prefix-wildcard). Both run in `Scanner.scan` right after `assign_fingerprints` (shared line-cache pass →
`core/postprocess.py`). New `ReportSummary.suppressed_findings` (additive). CLI: `repomedic baseline [PATH]
--file …`; scan/sniff `--baseline PATH`/`--no-baseline` (auto-detects the file). No `--fail-on-new` flag —
baseline + existing `--fail-on error` *is* fail-on-new; documented in AGENTS.md.

**1.3 MCP server** — `mcp_server.py` on `mcp.server.fastmcp.FastMCP` (optional extra `mcp = ["mcp>=1.2"]`); CLI
`repomedic mcp` (stdio) with import-guard + actionable install hint. Tools all call the Phase 0 service layer and
return structured pydantic dumps (never markdown unless the tool is `fix_report`): `scan`, `fix_report`,
`run_script`, `doctor`, `explain`, `fix_preview` (**always dry-run — MCP never mutates**), `baseline_write`,
`list_analyzers`. **`allow_exec` defaults `False` for every MCP tool** (a client may point the server anywhere).
FastMCP owns stdout; service progress → logging (stderr).

**1.4 Agents guide single-sourcing** — move canonical text to `src/repomedic/data/AGENTS.md` (loaded via
`importlib.resources`, deleting the inline string in `commands/agents.py:10-63`); `docs/AGENTS.md` becomes a
generated copy with a `tests/test_docs_sync.py` byte-equality guard. Update both with exec model, SARIF, baseline,
MCP, schema 3.

**1.5 GitHub Action + pre-commit** — composite `action.yml` (scan → SARIF → optional `upload-sarif@v3` → propagate
exit) and `.pre-commit-hooks.yaml` (`repomedic sniff --changed --fail-on error --no-snippets`). CI gains an
`action-selftest` job (`uses: ./` against a fixture, expect exit 1 + valid SARIF).

**1.6 Schema export** — `repomedic schema [--kind report|baseline|doctor|…]` prints `model_json_schema()` (consumed
by Phase 3 contract tests + external validators).

**pyproject:** extras += `mcp`; package-data for `data/*.md`; version → `0.4.0`.

**Verify:** SARIF validates (sarif-multitool / jsonschema); baseline round-trip suppresses all findings → exit 0;
suppression unit test; in-process MCP client round-trip asserts schema 3; `pre-commit try-repo`.

---

## Phase 2 — Debugger integration (PR: headless DAP core + `repomedic debug` + VS Code extension)

This is the part that turns the shallow regex-post-mortem runtime analyzer into a real debugger driver, headless
(for agents/CI) with a thin VS Code layer on top.

**2.1 Headless DAP client** — new `src/repomedic/debug/`. `dap.py` (~250 LOC, stdlib only): Content-Length framed
JSON-RPC client (`DapClient.request/wait_for_event/close`, reader thread, seq-keyed pending futures, event queue).
`session.py`: `capture_python_crash(script, args, cwd, timeout=60, bounds)` → `DebugCapture | None` with
`exception_type/message`, bounded `frames[CapturedFrame(file,line,function,locals)]`, stdout/stderr tails.
**Adapter: Python attach via `python -m debugpy --listen 127.0.0.1:<port> --wait-for-client <script>`** (ephemeral
port with bind-probe retry), DAP sequence `initialize → attach → setExceptionBreakpoints(["uncaught"]) →
configurationDone → wait stopped(exception) → threads/stackTrace/scopes/variables(depth 1, truncated) →
exceptionInfo → continue`, whole-session wall-clock deadline with `os.killpg` on expiry. **Node deferred**
(decisive) — Python-first; node keeps the existing `RUN-003` regex path; js-debug adapter is a documented follow-up.

**2.2 Runtime analyzer refactor + CLI** — split `analyze_script` into `_execute` + `_findings_from_failure` (shared
by plain and debug paths); add `analyze_script(..., debug=False, bounds=None)`. Debug crashes emit new **`RUN-004`
"Uncaught exception (debugger capture)"** anchored at the deepest *user* frame (filter out site-packages), with
`metadata["debug"] = {exception, frames:[{file,line,function,locals}]}` (additive). `_append_finding` renders a
"Debug state" section inside a `fenced_block` (locals are untrusted → Phase 0 sanitizer mandatory). New command
`repomedic debug SCRIPT [ARGS…] --timeout --max-frames --max-vars -o json|rich|markdown`; plus `repomedic run
--debug`.

**2.3 VS Code extension (thin)** — new `editors/vscode/` (TypeScript, `@types/vscode` only, built with `tsc`; **no
marketplace publish this round** — F5 dev host + `vsce package` docs). `package.json` contributes commands
(`scanWorkspace`, `debugCurrentFile`, `clearDiagnostics`) + config (`repomedic.path`, `repomedic.extraArgs` default
`["--no-exec"]`, `repomedic.maxFindings`). `report.ts` (pure, testable) maps `--output json` findings →
`DiagnosticCollection` (severity/code/range/source); status-bar shows the health score. `debugCurrentFile` launches
`vscode.debug.startDebugging({type:"python",request:"launch",…})` for interactive debugging **and** offers a
"Capture crash state" action running `repomedic debug` in the integrated terminal. A `CodeActionProvider` surfaces
those on `repomedic` diagnostics in runnable files.

**pyproject:** extras += `debug = ["debugpy>=1.8"]`; dev += `debugpy` (CI exercises DAP for real); version → `0.5.0`.

**Tests:** `test_dap_client.py` (codec vs scripted fake server), `test_debug_session.py` (real debugpy: crash
fixture → exception type + ≥1 user frame + truncated locals; hang fixture → process-group kill within deadline;
missing-debugpy → graceful fallback), `test_cli_debug.py` (exit 1, JSON has `RUN-004` + `metadata.debug`),
`editors/vscode` mapper unit tests.

**Verify:** `repomedic debug crash_value_error.py -o json` shows `RUN-004` with frames/locals; `debug hang.py
--timeout 3` returns promptly; `run … --debug -o markdown` shows a fenced Debug-state block; `cd editors/vscode &&
npm ci && npm run compile && npm test`; F5 dev host populates Problems panel and launches the debugger.

---

## Phase 3 — V&V framework (PR: ground-truth corpus, contract + adversarial suites, selfcheck, full CI)

Goal: prove RepoMedic's findings are **true** (precision/recall) and the tool is **safe** (injection/redaction/
subprocess), continuously.

**3.1 Ground-truth corpus + scorer** — new top-level `vv/` (excluded from wheel + self-scan). `vv/corpus/<case>/`
each with a seeded-bug `project/` + `expected.yaml` (`requires:` toolchains, `expect:` [code,file,line-range,
severity], `forbid:` false-positive codes, `allow_extra`). Cases span every analyzer incl. a `clean-project`
false-positive control and secrets using AWS's documented example key (push-protection-safe). `vv/scorer.py`
(`score_case`/`aggregate`/`check_thresholds`) runs `Scanner` via `core.service`, computes per-analyzer precision/
recall vs `vv/thresholds.yaml`. **Primary runner is pytest-integrated** (`tests/vv/test_corpus.py`, parametrized,
`@pytest.mark.corpus`, per-case `requires` skips); `python -m vv.scorer` prints the table for CI artifacts.

**3.2 Output-contract tests** (`tests/contract/`) — JSON schema drift vs committed snapshot + live validation;
full exit-code matrix (0/1/2 across scan/sniff/run/doctor/baseline); stdout-purity via **real subprocess** (json =
one doc, sniff = markdown only, progress on stderr, mcp = protocol only); fingerprint v2 drift/occurrence/stability
at contract level.

**3.3 Adversarial suite** (`tests/adversarial/`) — `payloads.py` (heading/fence/front-matter escapes, plain-text
"ignore all previous instructions", rich markup, pipe/table breakage, long lines) seeded via `make_project` into
log lines, TODOs, filenames, `.env` values, script stderr, package names, symlink targets. Assert: every payload
sits inside a strictly-longer fence; no heading carries raw payload; front matter round-trips `yaml.safe_load`;
symlink-escape target never read (absent from all outputs, excluded from `files_scanned`); secret raw bytes absent
from JSON/markdown/SARIF while masked form present; huge (10 MB) + binary files complete under budget with no
snippet; monkeypatched signal-death/timeout `ProcessResult`s never read as "not installed"; debug-path locals
fenced.

**3.4 `repomedic selfcheck`** — new command + `SelfcheckReport` model. Named pass/fail checks: import-integrity
(all 13 analyzers import, unique names), env-basics (python/git resolvable via isolated `run`), pipeline-roundtrip
(scan a bundled `data/selfcheck/` mini-fixture, assert expected codes present + forbidden absent),
schema-self-validation, render-integrity (canary payload stays fenced, front matter parses), extras-status
(informational). Exit 0/1; `-o json|rich`. CI runs it against the **built wheel**.

**3.5 CI completion** — `ci.yml` grows: `lint`, blocking `typecheck`, `test` matrix (no toolchains → proves graceful
degradation), **`test-toolchains`** (one leg with node/go/rust/shellcheck/gitleaks/semgrep+bandit — finally
exercises the subprocess parsers and `requires` corpus cases; also builds+tests the VS Code extension), `coverage`
(`--cov-fail-under=75`, ratchet later), `corpus` (scorer gate + table artifact), `dogfood` (`repomedic selfcheck`
+ `repomedic scan . --no-exec --fail-on error` with a repo-root `.repomedic.toml` excluding `vv`/fixtures/editors),
`action-selftest`.

**pyproject:** dev += `pytest-cov`, `jsonschema`; pytest markers `corpus`/`adversarial`/`toolchain`; coverage
config; ruff excludes `vv/corpus`; repo-root `.repomedic.toml`; version → `0.6.0`.

**Verify:** `pytest -q -m "not toolchain"`; `pytest -q -m corpus && python -m vv.scorer` (thresholds green);
`pytest -q -m adversarial`; `pip wheel . && pip install …whl && repomedic selfcheck -o json`; `repomedic scan .
--no-exec --fail-on error` (dogfood green); push → all CI jobs green.

---

## Explicitly out of scope (deferred, with rationale)

1. **Analyzer `entry_points` plugin system** — no external-plugin demand; a registry rewrite mid-hardening
   multiplies V&V surface. The `@register` + hardcoded import list stays. Revisit post-1.0.
2. **Container/jail sandboxing for `--exec`** — the trust flag with URL-default-off closes the clone-then-execute
   vector; real sandboxing is an infra dependency. Documented as roadmap so the posture is honest.
3. **LSP server** — the thin extension + SARIF cover editor UX at a fraction of the maintenance cost.
4. **Node/CDP DAP adapter** — explicit follow-up after the Python-first DAP core proves out.
5. **VS Code Marketplace publish + extension e2e (`@vscode/test-electron`) harness** — `vsce package` docs only.
6. **Cross-analyzer dedup engine / `--analyzers security` category-vs-name mismatch** — partially mitigated
   (fingerprint v2 makes a future dedup pass cheap); a `--category` filter is a good post-Phase-1 quick win.
7. **Windows CI leg** — POSIX-specific bits (`os.killpg`, `start_new_session`) already isolated behind
   `sys.platform` guards.

## Top risks & mitigations

1. **Sentinel migration regressions** (wrong `.ok` vs `.ran` at one of ~25 sites). → Delete the old constants so
   stale refs crash at import; `returncode: int | None` makes mypy flag bad comparisons; per-status unit tests per
   analyzer; the migration table is the PR checklist.
2. **Fingerprint v2 instability poisoning baselines.** → Lands a full phase before anything persists fingerprints,
   with drift tests in the same commit; algo version hashed into the input so a future v3 can dual-emit.
3. **Sanitization breaking harnesses that scrape the report.** → Headings/fingerprint layout unchanged; front
   matter stays `key: value` (quoted scalars); schema bump announced in the front matter; golden-file snapshots
   lock the new shape; AGENTS.md examples updated in the same PR.
4. **Soft analyzer timeouts can't kill threads.** → Audit that every `run()` has an explicit subprocess timeout
   (the only real blocking primitive), so "hung" converges to "slow but bounded"; process-group kill covers trees;
   limitation documented + tested with a slow fake analyzer.
5. **Optional-extra / toolchain-absent CI drift** (mcp SDK churn, debugpy port races, parsers silently skipped). →
   Import-guards with actionable errors; `selfcheck` reports extras status; DAP port retries with jitter; the
   toolchain CI leg **fails** (not skips) if a required tool is missing (`REPOMEDIC_VV_STRICT=1`).

## Critical files

- `src/repomedic/utils/process.py` — `ProcessResult` contract, env allowlist, output caps, `run_json_tool`; every
  phase builds on it.
- `src/repomedic/cli.py` — `_execute_scan` gutted into the service layer; all CLI surface changes.
- `src/repomedic/core/service.py` *(new)* — `run_scan`; reused by MCP, VS Code, and the corpus scorer.
- `src/repomedic/core/scanner.py` — timeouts, post-processing (fingerprint/suppression) hooks, cache warmup.
- `src/repomedic/output/markdown_output.py` + `output/sanitize.py` *(new)* — fencing/sanitization contract, snippet
  containment, secret withholding, debug-state rendering.
- `src/repomedic/models.py` — fingerprint field change, `SCHEMA_VERSION = 3`, `skipped_checks`/`suppressed_findings`.
- `src/repomedic/debug/` *(new)* + `analyzers/runtime.py` — headless DAP core and the runtime refactor.
- `vv/` *(new)* + `tests/contract/` + `tests/adversarial/` + `.github/workflows/ci.yml` *(new)* — the V&V framework.
