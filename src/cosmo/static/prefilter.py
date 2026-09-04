"""Static pre-filter: which scanners run, and what it means when one doesn't.

Deterministic, cheap, high-confidence first pass, before the LLM stage — its
output is passed forward as context so the model doesn't re-derive what a tool
already caught.

Two things this file is responsible for.

**Coverage honesty.** Every tool in `TOOLS` that does not run produces a line in
`skipped`, whether it is absent, disabled, or broken. A scanner nobody installed
is not a scanner that found nothing, and the report must never let those look
alike. This is why the registry is data: a tool added to it is automatically
accounted for whether or not it is present on the box.

**The trust boundary.** Which scanners run is a *safety* setting, not a taste
one. A repo able to write `static: {tools: [semgrep]}` into its own `cosmo.yaml`
could switch off the secret scanner that would have found its credentials. So
`config.static.tools` is clamped: a repo may add a scanner, never remove one the
operator enabled. See `config.SAFETY_SECTIONS`.

The runners themselves are in `runners.py`.
"""
from __future__ import annotations

import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..findings import Finding
from .runners import (_run_bandit, _run_findsecbugs, _run_gitleaks,
                      _run_opengrep, _run_semgrep, _run_trivy, _run_trufflehog,
                      terminate_running_scanners)

Runner = Callable[..., list[Finding]]


@dataclass(frozen=True)
class Tool:
    """One scanner cosmo knows how to drive."""

    name: str          # config id, and the `static:<name>` prefix in skipped lines
    binaries: tuple[str, ...]   # accepted executable names, first match wins
    runner: Runner
    covers: str        # one line, for the skipped message and `cosmo tools`
    install: str       # how to get it, so a skip line is actionable
    # Attribution. cosmo finds almost nothing on its own — it runs other
    # people's scanners and normalizes what they return. Keeping the credit in
    # the registry rather than only in CREDITS.md means adding a tool without
    # naming its authors fails a test instead of quietly shipping.
    project: str = ""       # the upstream project's name
    author: str = ""        # who maintains it
    license: str = ""       # SPDX id, as published by the project
    homepage: str = ""
    # How `cosmo tools` asks this tool its version, and where it looks up the
    # newest published one. An empty `version_argv` means the tool has no usable
    # version flag — reported as unknown, never silently treated as current.
    version_argv: tuple[str, ...] = ("--version",)
    latest: str = ""        # "pypi:<pkg>" or "github:<owner>/<repo>"
    # Scanners that share a lineage. Two tools finding the same thing is
    # corroboration only when they are independent — opengrep is a fork of
    # semgrep and inherits its rules, so their agreement says almost nothing,
    # while gitleaks and trufflehog agreeing is two separate detector sets.
    family: str = ""

    def __post_init__(self) -> None:
        if not self.family:
            object.__setattr__(self, "family", self.name)

    def resolve(self) -> str | None:
        """The executable to run, or None if none of its names is on PATH.

        Resolved per scan rather than at import: find-sec-bugs ships a `.sh`
        wrapper that some installs rename, and freezing the answer when the
        module loads would report a tool as absent that the operator installed
        a moment later.
        """
        for name in self.binaries:
            if shutil.which(name):
                return name
        return None


TOOLS: tuple[Tool, ...] = (
    Tool("semgrep", ("semgrep",), _run_semgrep,
         "multi-language taint/pattern rules",
         "pip install semgrep",
         project="Semgrep", author="Semgrep, Inc. and contributors",
         license="LGPL-2.1", homepage="https://semgrep.dev",
         latest="pypi:semgrep"),
    Tool("gitleaks", ("gitleaks",), _run_gitleaks,
         "secrets in the working tree and in git history",
         "https://github.com/gitleaks/gitleaks/releases",
         project="Gitleaks", author="Zachary Rice and contributors",
         license="MIT", homepage="https://gitleaks.io",
         # `gitleaks --version` is not a flag it has; the subcommand is.
         version_argv=("version",), latest="github:gitleaks/gitleaks"),
    Tool("bandit", ("bandit",), _run_bandit,
         "Python AST security checks",
         "pip install bandit",
         project="Bandit", author="PyCQA", license="Apache-2.0",
         homepage="https://bandit.readthedocs.io", latest="pypi:bandit"),
    Tool("trivy", ("trivy",), _run_trivy,
         "dependency CVEs and IaC misconfiguration",
         "https://github.com/aquasecurity/trivy/releases",
         project="Trivy", author="Aqua Security and contributors",
         license="Apache-2.0", homepage="https://trivy.dev",
         latest="github:aquasecurity/trivy"),
    Tool("opengrep", ("opengrep",), _run_opengrep,
         "the semgrep fork's rule set (and the matched source semgrep's OSS "
         "engine withholds)",
         "https://github.com/opengrep/opengrep/releases", family="semgrep",
         project="Opengrep", author="the Opengrep project", license="LGPL-2.1",
         homepage="https://github.com/opengrep/opengrep",
         latest="github:opengrep/opengrep"),
    Tool("trufflehog", ("trufflehog",), _run_trufflehog,
         "secrets, with an optional live check against the credential's provider",
         "https://github.com/trufflesecurity/trufflehog/releases",
         project="TruffleHog", author="Truffle Security Co. and contributors",
         license="AGPL-3.0", homepage="https://trufflesecurity.com",
         latest="github:trufflesecurity/trufflehog"),
    Tool("find-sec-bugs", ("findsecbugs", "findsecbugs.sh"), _run_findsecbugs,
         "Java taint analysis (needs compiled bytecode)",
         "https://github.com/find-sec-bugs/find-sec-bugs/releases",
         # A SpotBugs plugin: the analysis engine underneath is SpotBugs
         # (LGPL-2.1), credited separately in CREDITS.md.
         project="Find Security Bugs", author="Philippe Arteau and contributors",
         license="LGPL-3.0", homepage="https://find-sec-bugs.github.io/",
         # The distributed launcher swallows -version and prints nothing,
         # so the installed version is not knowable from the CLI.
         version_argv=(), latest="github:find-sec-bugs/find-sec-bugs"),
)

TOOLS_BY_NAME: dict[str, Tool] = {t.name: t for t in TOOLS}

# The default set. Every tool cosmo can drive is on by default: leaving one off
# would mean shipping a quieter scan than the tool is capable of, and the ones
# that are not installed already report themselves as skipped.
DEFAULT_TOOLS: tuple[str, ...] = tuple(t.name for t in TOOLS)

# Scanners are subprocesses — the work is in another process, so this bounds how
# many of those run at once, not Python threads doing anything. Four, because
# semgrep and trivy are each happy to saturate a machine on their own.
DEFAULT_CONCURRENCY = 4


def selected_tools(config=None) -> list[Tool]:
    """The tools this run will attempt, in registry order.

    Order is fixed by `TOOLS` rather than by config, so two runs with the same
    set produce findings in the same order regardless of how the list was
    written or how the threads happened to finish.
    """
    if config is None:
        names = set(DEFAULT_TOOLS)
    else:
        requested = config.get("static.tools", None)
        names = set(DEFAULT_TOOLS) if requested is None else {
            str(n) for n in requested}
    return [t for t in TOOLS if t.name in names]


def static_ruleset_id(config=None) -> str:
    """Identifies the active tool set for the incremental cache key.

    Without this, enabling a scanner and re-running would replay the cached
    findings of the *old* set against unchanged files — presenting a narrower
    scan as the wider one the operator just asked for.
    """
    return "+".join(t.name for t in selected_tools(config)) or "none"


def _concurrency(config=None) -> int:
    if config is None:
        return DEFAULT_CONCURRENCY
    try:
        return max(1, int(config.get("static.concurrency", DEFAULT_CONCURRENCY)))
    except (TypeError, ValueError):
        return DEFAULT_CONCURRENCY


def _runner_kwargs(tool: Tool, config) -> dict:
    """Per-tool options the orchestrator has to pass through.

    Only trufflehog has one, and it is deliberately not a generic passthrough:
    `verify` makes the scanner send candidate credentials to third-party
    providers, so it is an operator decision with its own key, not something a
    repo can switch on by writing a config block.
    """
    if tool.name != "trufflehog" or config is None:
        return {}
    return {"verify": bool(config.get("static.trufflehog_verify", False))}


def _run_one(tool: Tool, root: str, ev, config=None) -> tuple[list[Finding], list[str]]:
    """Run one scanner. Never raises: a broken tool must not sink the scan.

    Returns its findings and its own skipped lines, kept per-tool rather than
    appended to a shared list — several of these run at once, and a plain
    `list.append` race would be a silent coverage bug of exactly the kind this
    stage exists to prevent.
    """
    own: list[str] = []
    try:
        found = tool.runner(root, ev, own, **_runner_kwargs(tool, config))
        ev.output(f"{tool.name}: {len(found)} finding(s)", stage="static",
                  tool=tool.name, findings=len(found))
        return found, own
    except subprocess.TimeoutExpired as exc:
        note = (f"static:{tool.name} timed out after {exc.timeout}s — "
                f"NOT scanned ({tool.covers})")
        # `tool=` on every static-stage event, success or not — a caller
        # tallying scanners_run/succeeded/failed/skipped has to tell them apart
        # by more than parsing English out of `message`.
        ev.stage_skipped("static", note, tool=tool.name)
        return [], own + [note]
    except Exception as exc:
        note = f"static:{tool.name} (error: {exc})"
        ev.error(f"{tool.name} failed: {exc}", stage="static", tool=tool.name)
        return [], own + [note]


def run_static_prefilter(target_dir: str, events=None,
                         config=None) -> tuple[list[Finding], list[str]]:
    """Returns (findings, skipped_stages)."""
    from ..events import Emitter
    ev = events if isinstance(events, Emitter) else Emitter(events)

    root = Path(target_dir)
    if root.is_file():
        root = root.parent

    selected = selected_tools(config)
    for tool in TOOLS:
        if tool not in selected:
            note = (f"static:{tool.name} (not enabled in static.tools) — "
                    f"{tool.covers} NOT scanned")
            ev.stage_skipped("static", note, tool=tool.name)

    runnable: list[Tool] = []
    skipped: list[str] = []
    for tool in selected:
        if tool.resolve() is None:
            skipped.append(f"static:{tool.name} (not installed — {tool.covers} "
                           f"NOT scanned; install: {tool.install})")
            ev.stage_skipped("static",
                             f"{tool.name} not installed — {tool.covers} not scanned",
                             tool=tool.name)
        else:
            runnable.append(tool)

    findings: list[Finding] = []
    if runnable:
        # `map` preserves input order, so the findings list is the registry
        # order regardless of which scanner finishes first.
        with ThreadPoolExecutor(max_workers=min(_concurrency(config), len(runnable)),
                                thread_name_prefix="cosmo-static") as pool:
            try:
                for found, notes in pool.map(
                        lambda t: _run_one(t, str(root), ev, config), runnable):
                    findings += found
                    skipped += notes
            except KeyboardInterrupt:
                # Ctrl-C reaches the main thread; the workers are blocked
                # reading a scanner's output and the pool's shutdown waits for
                # them. Handled *inside* the `with`, because leaving the block
                # runs that shutdown first — so the children have to be stopped
                # here or the interrupt looks like a hang.
                terminate_running_scanners()
                pool.shutdown(wait=False, cancel_futures=True)
                raise

    # Dependency auditing is trivy's job. Said plainly when trivy did not run,
    # because "no CVEs reported" and "nothing looked at the dependencies" are
    # the two readings this stage exists to keep apart.
    if not any(t.name == "trivy" for t in runnable):
        skipped.append("static:dep-audit (no dependency scanner ran — "
                       "install trivy, or enable it in static.tools)")
        ev.stage_skipped("static", "no dependency scanner ran")

    return findings, skipped


def source_family(source: str) -> str:
    """Group a finding's `source` for corroboration purposes.

    `static:opengrep` and `static:semgrep` collapse to one family; everything
    else stands alone. Non-static sources are returned unchanged, so a model
    agreeing with a scanner still counts as independent.
    """
    tool = str(source or "").split(":", 1)
    if len(tool) == 2 and tool[0] == "static":
        found = TOOLS_BY_NAME.get(tool[1])
        return f"static:{found.family}" if found else str(source)
    return str(source)
