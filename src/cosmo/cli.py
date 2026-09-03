"""CLI trigger adapter (architecture §2). A thin caller of run_review — no scan
logic lives here, only how a scan is invoked and how results are rendered.
"""
from __future__ import annotations

import argparse
import json
import os.path as _osp
import sys

from .config import load_config
from .diff import resolve_diff
from .engine import run_review
from .output import render_cli, render_pr_comment, render_report, render_sarif
from .store import TrendStore, map_report
from .triggers import install_hook, render_hook_output, run_git_hook, run_github_action
from .waiver import Baseline, fingerprint


# Conventional shell code for "killed by SIGINT" (128 + 2). Distinct from
# cosmo's own 0/1/2 so a CI job can tell an interrupted run from a failed one.
INTERRUPTED = 130


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Ctrl-C is an ordinary way to stop, not a crash."""
    try:
        return _main(argv)
    except KeyboardInterrupt:
        # A traceback here says cosmo broke. It didn't — you stopped it. Any
        # scanner still running was signalled on the way out by the static
        # stage, so nothing is left working in the background.
        print("\ninterrupted — no report written; nothing was posted or changed.",
              file=sys.stderr)
        return INTERRUPTED


def _main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cosmo", description="cosmo security review + zero-day discovery (full build, steps 1–20)")
    from . import __version__
    parser.add_argument("--version", action="version",
                        version=f"cosmo {__version__}",
                        help="print cosmo's version and exit")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_review = sub.add_parser(
        "review", help="review a local path or GitHub PR (--live for a live UI)")
    p_review.add_argument("target", help="local path, or PR ('owner/repo#123' / PR URL)")
    p_review.add_argument("--format", choices=["cli", "sarif", "pr"], default="cli")
    p_review.add_argument("--model", choices=["claude", "claude-cli", "codex", "deepseek", "llama"],
                          help="review provider (claude-cli uses the Claude Code subscription, no API key)")
    p_review.add_argument("--audit", action="store_true",
                          help="whole-project AI audit: review every file with the LLM "
                               "(bounded by llm_audit.max_files), not just the diff")
    p_review.add_argument("--verbose", "-v", action="store_true",
                          help="stream progress to stderr as each stage/file runs")
    p_review.add_argument("--live", action="store_true",
                          help="live review UI on stderr: objective, workflow stages, "
                               "and what the engine is doing right now (stdout stays "
                               "clean for --format sarif/pr)")
    p_review.add_argument("--threshold", choices=["info", "low", "medium", "high", "critical"])
    p_review.add_argument("--operator-config", help="path to the operator/org config (the ceiling)")
    p_review.add_argument("--no-cache", action="store_true", help="force a full re-scan")
    p_review.add_argument("--no-color", action="store_true")
    p_review.add_argument("--report", metavar="FILE",
                          help="write a full Markdown report to FILE: every finding "
                               "with its evidence, remediation and waive command, "
                               "untruncated, plus what did not run ('-' for stdout)")
    p_review.add_argument("--record", action="store_true",
                          help="record this scan in the trend store for lifecycle tracking")

    p_waive = sub.add_parser("waive", help="waive a finding by fingerprint into the baseline")
    p_waive.add_argument("target")
    p_waive.add_argument("fingerprint")
    p_waive.add_argument("--reason", default="")

    p_base = sub.add_parser("baseline", help="list or clear waived findings")
    p_base.add_argument("target")
    p_base.add_argument("--unwaive", metavar="FINGERPRINT")

    p_hook = sub.add_parser("hook", help="run the git-hook review over the staged diff")
    p_hook.add_argument("--path", default=".", help="repo path (default: cwd)")
    p_hook.add_argument("--blocking", action="store_true", help="abort the commit on findings")
    p_hook.add_argument("--operator-config")

    p_install = sub.add_parser("install-hook", help="install a git pre-commit hook that runs cosmo")
    p_install.add_argument("--path", default=".", help="repo path (default: cwd)")
    p_install.add_argument("--type", default="pre-commit", choices=["pre-commit", "pre-push"])
    p_install.add_argument("--blocking", action="store_true")

    p_action = sub.add_parser("action", help="GitHub Action trigger: review a PR")
    p_action.add_argument("target", help="PR ref 'owner/repo#123'")
    p_action.add_argument("--post", action="store_true", help="post the gated PR comment")
    p_action.add_argument("--sarif", metavar="FILE", help="write SARIF to FILE")
    p_action.add_argument("--no-block", action="store_true", help="don't fail the job on findings")
    p_action.add_argument("--operator-config")

    p_fuzz = sub.add_parser("fuzz", help="manual-only zero-day fuzzing campaign")
    p_fuzz.add_argument("target", help="local repo path (fuzzes cosmo's own sandbox build only)")
    p_fuzz.add_argument("--language", default="python",
                        help="entry-point language, to select the integrated engine")
    p_fuzz.add_argument("--duration", help="hard time cap, e.g. 30m/2h (required — never defaults)")
    p_fuzz.add_argument("--confirm", action="store_true",
                        help="acknowledge a duration above fuzzing.confirm_above")
    p_fuzz.add_argument("--operator-config")

    p_int = sub.add_parser("interactive", help="live session — same engine, slash-commands")
    p_int.add_argument("target", help="local path or GitHub PR to open a session on")
    p_int.add_argument("--operator-config")
    p_int.add_argument("--no-scan", action="store_true", help="don't scan on start")
    p_int.add_argument("--plain", action="store_true",
                       help="line-based session instead of the full-screen UI")

    p_agent = sub.add_parser("agent", help="natural-language session, harness-agnostic")
    p_agent.add_argument("target", help="local path or GitHub PR to open a session on")
    p_agent.add_argument("--operator-config")
    p_agent.add_argument("--no-scan", action="store_true", help="don't scan on start")

    p_hist = sub.add_parser("history",
                            help="sweep a repo's commit history for vulnerabilities")
    p_hist.add_argument("target",
                        help="local git repo path, or 'owner/repo' to read the "
                             "history straight off GitHub with no clone (needs gh)")
    p_hist.add_argument("--since", help="only commits after this date, e.g. '2024-01-01' or '6 months ago'")
    p_hist.add_argument("--until", help="only commits before this date")
    p_hist.add_argument("--author", help="only commits by this author (git --author pattern)")
    p_hist.add_argument("--range", dest="rev_range", metavar="REV..REV",
                        help="a git revision range, e.g. v1.2.0..HEAD")
    p_hist.add_argument("--path", action="append", dest="paths", metavar="PATH",
                        help="limit to commits touching PATH (repeatable)")
    p_hist.add_argument("--max-commits", type=int,
                        help="commits to review (clamped by history.max_commits)")
    p_hist.add_argument("--include-merges", action="store_true",
                        help="also review merge commits (off: their diffs restate branch work)")
    p_hist.add_argument("--live-only", action="store_true",
                        help="only report findings whose code is still present at HEAD")
    p_hist.add_argument("--model", choices=["claude", "claude-cli", "codex", "deepseek", "llama"])
    p_hist.add_argument("--threshold", choices=["info", "low", "medium", "high", "critical"])
    p_hist.add_argument("--format", choices=["cli", "sarif"], default="cli")
    p_hist.add_argument("--report", metavar="FILE",
                        help="write a full Markdown report to FILE ('-' for stdout)")
    p_hist.add_argument("--live", action="store_true", help="live UI on stderr")
    p_hist.add_argument("--no-color", action="store_true")
    p_hist.add_argument("--operator-config")

    p_tools = sub.add_parser(
        "tools", help="show the static scanners: installed, version, up to date")
    p_tools.add_argument("--check-updates", action="store_true",
                         help="also ask PyPI/GitHub for the newest published "
                              "version of each tool (the only part that uses "
                              "the network)")
    p_tools.add_argument("--format", choices=["cli", "json"], default="cli")
    p_tools.add_argument("--no-color", action="store_true")

    p_trends = sub.add_parser("trends", help="show lifecycle/trend + compliance rollup")
    p_trends.add_argument("target", help="local path previously scanned with --record")
    p_trends.add_argument("--disclosure", action="store_true",
                          help="show the coordinated-disclosure queue instead")

    p_ext = sub.add_parser("extensions", help="list discovered custom extensions (plugins/skills)")
    p_ext.add_argument("--path", default=".", help="repo path for repo cosmo.yaml (default: cwd)")
    p_ext.add_argument("--operator-config", help="operator config that may enable extensions")

    p_plugin = sub.add_parser("plugin", help="manage the Claude Code plugin surface")
    p_plugin.add_argument("action", choices=["sync", "check"],
                          help="sync: regenerate manifest+commands from code; "
                               "check: report drift (non-zero exit if any)")
    p_plugin.add_argument("--root", default=".", help="plugin repo root (default: cwd)")

    args = parser.parse_args(argv)

    if args.cmd == "review":
        return _cmd_review(args)
    if args.cmd == "waive":
        b = Baseline.load(args.target)
        b.waive(args.fingerprint, args.reason)
        b.save()
        print(f"waived {args.fingerprint}")
        return 0
    if args.cmd == "baseline":
        b = Baseline.load(args.target)
        if args.unwaive:
            b.unwaive(args.unwaive)
            b.save()
            print(f"unwaived {args.unwaive}")
            return 0
        if not b.waived:
            print("no waived findings")
        for fp, meta in b.waived.items():
            print(f"{fp}  {meta.get('reason', '')}")
        return 0
    if args.cmd == "hook":
        config = load_config(args.path, operator_config=args.operator_config)
        report, code = run_git_hook(
            config, staged_path=args.path,
            blocking_override=True if args.blocking else None)
        print(render_hook_output(report, code))
        return code
    if args.cmd == "install-hook":
        path = install_hook(args.path, hook_type=args.type, blocking=args.blocking)
        mode = "blocking" if args.blocking else "non-blocking"
        print(f"installed {mode} {args.type} hook at {path}")
        return 0
    if args.cmd == "action":
        config = load_config(".", operator_config=args.operator_config)
        report, code = run_github_action(
            config, args.target, post=args.post, sarif_path=args.sarif,
            blocking_override=False if args.no_block else None)
        print(render_cli(report, color=False))
        if args.sarif:
            print(f"wrote SARIF to {args.sarif}")
        return code
    if args.cmd == "interactive":
        from .interactive import run_repl
        run_repl(args.target, operator_config=args.operator_config,
                 autoscan=not args.no_scan, plain=args.plain)
        return 0
    if args.cmd == "agent":
        # Model-agnostic orchestration. The planner is resolved from config: a
        # live provider (Claude/Codex/DeepSeek/local Llama) when one is available
        # and allowed by the §8 gate, otherwise the no-model rule-based planner —
        # so it runs out of the box either way.
        from .interactive import run_agent
        run_agent(args.target, operator_config=args.operator_config, autoscan=not args.no_scan)
        return 0
    if args.cmd == "fuzz":
        return _cmd_fuzz(args)
    if args.cmd == "history":
        return _cmd_history(args)
    if args.cmd == "tools":
        return _cmd_tools(args)
    if args.cmd == "trends":
        return _cmd_trends(args)
    if args.cmd == "extensions":
        from .extensions import load_enabled
        cfg = load_config(args.path, operator_config=args.operator_config)
        loaded = load_enabled(cfg)
        if loaded.active:
            print("active (operator-enabled):")
            for ext in loaded.active:
                print(f"  {ext.name} v{ext.version} — {ext.description or '(no description)'}")
                print(f"    {len(ext.skills)} skill(s), {len(ext.detectors)} detector(s), "
                      f"{len(ext.commands)} command(s)")
        if loaded.disabled:
            print("discovered but NOT enabled (add the name to operator extensions.enabled):")
            for n in loaded.disabled:
                print(f"  {n}")
        if loaded.errors:
            print("failed to load:")
            for n, e in loaded.errors.items():
                print(f"  {n}: {e}")
        if not (loaded.active or loaded.disabled or loaded.errors):
            print("no extensions discovered (set extensions.paths / install a "
                  "cosmo.extensions entry point)")
        return 0
    if args.cmd == "plugin":
        from .plugin import check_plugin, sync_plugin
        if args.action == "sync":
            changed = sync_plugin(args.root)
            if not changed:
                print("plugin already up to date")
            for c in changed:
                print(f"wrote {c}")
            return 0
        drift = check_plugin(args.root)
        if not drift:
            print("plugin surface matches the guarded command registry")
            return 0
        print("plugin surface is out of date — run `cosmo plugin sync`:")
        for d in drift:
            print(f"  {d}")
        return 1
    return 2


def _cmd_fuzz(args) -> int:
    from .config import _parse_duration
    from .fuzz import select_engine
    from .fuzz.campaign import ConfirmationRequired, DurationNotSet, resolve_duration
    from .fuzz.engines import NoEngineForLanguage

    config = load_config(_target_dir(args.target), operator_config=args.operator_config)
    if not config.get("fuzzing.enabled", False):
        print("fuzzing is disabled in config (safety tier); enable fuzzing.enabled to run")
        return 2
    try:
        max_seconds = resolve_duration(config, args.duration, confirmed=args.confirm)
    except DurationNotSet:
        cap = config.get("fuzzing.max_duration", "8h")
        print(f"no --duration set. A fuzz campaign never defaults silently; "
              f"pass e.g. --duration 30m (cap: {cap}).")
        return 2
    except ConfirmationRequired:
        print(f"--duration exceeds fuzzing.confirm_above ({config.get('fuzzing.confirm_above')}); "
              f"re-run with --confirm to acknowledge the long run.")
        return 2
    try:
        engine = select_engine(args.language)
    except NoEngineForLanguage as exc:
        print(str(exc))
        return 2

    print(f"campaign ready: engine={engine.name}, cap={max_seconds}s, "
          f"target=sandbox-internal only.")
    print("harness generation + engine execution require the configured sandbox "
          "toolchain; run via cosmo.fuzz.run_campaign with a fuzz_runner wired to "
          "the sandbox (§6). No external target is reachable from this command.")
    return 0


def _write_report(path: str, text: str) -> None:
    """Write the Markdown report, or send it to stdout for `-`.

    The path is announced on stderr so it stays out of a piped `--format sarif`
    stream, and so a `--live` run's last line is where to look next.
    """
    if path == "-":
        print(text)
        return
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote report to {path}", file=sys.stderr)


def _cmd_review(args) -> int:
    # A local target must exist. (A PR ref 'owner/repo#N' or URL is resolved
    # remotely, so skip the path check for those.) Catches e.g. an unset $VAR
    # expanding to a bogus path before we scan the wrong tree.
    is_remote = "#" in args.target or args.target.startswith("http")
    if not is_remote and not _osp.exists(args.target):
        print(f"error: target path does not exist: {args.target!r}\n"
              f"(for a GitHub PR use 'owner/repo#123' or a pull-request URL)")
        return 2

    config = load_config(_target_dir(args.target), operator_config=args.operator_config)
    if args.threshold:
        config.data["threshold"] = args.threshold  # CLI flag beats config for this preference
    if args.no_cache:
        config.data.setdefault("incremental", {})["enabled"] = False

    # Live progress → stderr (keeps stdout clean for --format sarif/pr). The audit
    # path streams per-file progress; always on for --audit (it's slow), and
    # --verbose additionally announces the run.
    progress = None
    # --live owns stderr; the plain progress stream would corrupt its repaints.
    if (args.audit or args.verbose) and not args.live:
        def progress(msg: str) -> None:
            print(msg, file=sys.stderr, flush=True)
    if args.verbose and not args.live:
        progress(f"cosmo: reviewing {args.target}"
                 + (f" (audit, model={args.model or 'default'})" if args.audit else ""))

    ui = None
    if args.live:
        from .live import LiveUI
        # None = auto-detect (TTY + NO_COLOR); --no-color forces it off. Passing
        # True here would paint escape codes into a redirected stderr.
        ui = LiveUI(color=False if args.no_color else None)
        ui.start()

    # --model enters at the CLI tier of the §8 resolution order (outranks the
    # configured default, still gated by data sensitivity).
    try:
        report = run_review(args.target, config, model=args.model, audit=args.audit,
                            progress=progress, events=ui)
    except BaseException:
        if ui is not None:
            ui.finish(None)
        raise

    # Non-zero exit if any non-waived finding survived the threshold (CI-friendly).
    exit_code = 1 if any(not f.waived for f in report.findings) else 0
    if ui is not None:
        ui.finish(report, exit_code, report_path=args.report)

    # The verdict screen is a summary — top eight titles, clipped to a column.
    # It was suppressing the text report on an attached terminal, which left a
    # --live run with nothing to triage from. Both are printed now: the panel
    # says how it went, the report says what was found.
    if args.format == "cli":
        print(render_cli(report, color=not args.no_color))
    elif args.format == "sarif":
        print(render_sarif(report))
    elif args.format == "pr":
        print(render_pr_comment(report))

    if args.report:
        _write_report(args.report, render_report(
            report, threshold=config.get("threshold", "") or ""))

    # The store is a side layer: run_review stays pure, the CLI records the scan.
    if args.record:
        store = TrendStore.for_target(args.target)
        try:
            s = store.record_scan(args.target, report.findings)
            print(f"recorded: {s.introduced} new, {s.reopened} reopened, "
                  f"{s.fixed} fixed, {s.open_total} open")
        finally:
            store.close()

    return exit_code


def _cmd_history(args) -> int:
    """Sweep a repo's commit history — local clone or straight off GitHub."""
    from .engine import _dedupe
    from .events import HISTORY_STAGES, Emitter
    from .findings import Report
    from .history import (
        HeadStatus,
        Selection,
        clamp_requested,
        resolve_source,
        run_history_sweep,
    )
    from .providers import resolve_primary
    from .severity import Severity, meets_threshold

    config = load_config(_target_dir(args.target), operator_config=args.operator_config)
    if args.threshold:
        config.data["threshold"] = args.threshold
    if args.max_commits is not None:
        config.data.setdefault("history", {})["max_commits"] = clamp_requested(
            config, args.max_commits)

    ui = None
    if args.live:
        from .live import LiveUI
        ui = LiveUI(color=False if args.no_color else None, stages=HISTORY_STAGES)
        ui.start()
    ev = Emitter(ui)
    ev.objective_started(f"Commit-history sweep of {args.target}",
                         target=args.target, threshold=config.threshold)

    # Resolve the history source first: a bad path should say so, rather than
    # failing later with an unrelated complaint about the model.
    try:
        source = resolve_source(args.target)
    except Exception as exc:
        ev.error(str(exc), stage="select")
        if ui is not None:
            ui.finish(None, 2)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2

    provider, warns = resolve_primary(config, cli_model=args.model)
    for w in warns:
        ev.warning(w, stage="select")
    if getattr(provider, "broker", None) is None:
        from .providers.egress import provider_broker_from_config
        try:
            provider.broker = provider_broker_from_config(config)
        except AttributeError:
            pass
    if not provider.available():
        from .providers import describe_unavailable
        msg = (f"{describe_unavailable(provider)} A history sweep is an LLM "
               f"review, so there is nothing to run without one.")
        ev.error(msg, stage="llm")
        if ui is not None:
            ui.finish(None, 2)
        else:
            print(f"error: {msg}", file=sys.stderr)
        return 2

    sel = Selection(since=args.since, until=args.until, author=args.author,
                    rev_range=args.rev_range, paths=args.paths,
                    include_merges=args.include_merges)
    try:
        sweep = run_history_sweep(args.target, provider, config,
                                  selection=sel, source=source, events=ev)
    except Exception as exc:
        ev.error(str(exc), stage="select")
        if ui is not None:
            ui.finish(None, 2)
        else:
            print(f"error: {exc}", file=sys.stderr)
        return 2

    findings = sweep.findings
    if args.live_only:
        before = len(findings)
        findings = sweep.live
        sweep.notes.append(f"history: --live-only kept {len(findings)} of {before} "
                           f"finding(s) whose code is still in HEAD")

    ev.stage_started("dedupe")
    before = len(findings)
    findings = _dedupe(findings)
    ev.stage_completed("dedupe", f"{before} → {len(findings)} after dedupe")

    ev.stage_started("waiver")
    baseline = Baseline.load(_target_dir(args.target))
    # Fingerprints were stamped per commit during the sweep; apply() keeps them
    # and only marks what the baseline waives.
    findings = baseline.apply(findings, _empty_diff(args.target))
    ev.stage_completed("waiver",
                       f"{sum(1 for f in findings if f.waived)} waived by baseline")

    ev.stage_started("threshold")
    floor = Severity.parse(config.threshold)
    findings = [f for f in findings if f.waived or meets_threshold(f.severity, floor)]
    ev.stage_completed("threshold", f"{len(findings)} at or above {config.threshold}")

    report = Report(target=f"{args.target}@history", findings=findings,
                    skipped_stages=sweep.skipped, notes=sweep.notes)
    actionable = [f for f in findings if not f.waived]
    for f in sorted(actionable, key=lambda f: f.severity, reverse=True):
        ev.finding(f"{f.severity} {f.title}", detail=f"{f.file}:{f.line}",
                   severity=str(f.severity), file=f.file, line=f.line)
    ev.objective_completed(f"Swept {sweep.commits_reviewed} commit(s) — "
                           f"{len(actionable)} actionable finding(s)")

    exit_code = 1 if actionable else 0
    if ui is not None:
        ui.finish(report, exit_code, report_path=args.report)

    # As in `review`: the verdict panel summarises, the text report is the
    # result. Printing only the panel left --live with nothing to triage from.
    if args.format == "sarif":
        print(render_sarif(report))
    else:
        print(render_cli(report, color=not args.no_color))
        print(f"\ncommits reviewed: {sweep.commits_reviewed}"
              + (f" of {sweep.commits_total}+ matched" if sweep.commits_total > sweep.commits_reviewed else "")
              + f"   source: {sweep.source_kind}")
        if sweep.by_status:
            print("still in HEAD: " + ", ".join(
                f"{n} {s}" for s, n in sorted(sweep.by_status.items())))

    if args.report:
        _write_report(args.report, render_report(
            report, threshold=config.threshold))
    return exit_code


_TOOL_MARK = {
    "current": ("✓", "up to date"),
    "outdated": ("↑", "update available"),
    "unknown": ("?", "version unknown"),
    "missing": ("⊘", "not installed"),
    "unchecked": ("·", ""),
    "check-failed": ("!", "could not check"),
}


def _cmd_tools(args) -> int:
    """Show what the static stage can actually run, and whether it is current.

    Offline unless `--check-updates` is passed. Exit 1 when something wants
    attention (a scanner missing, or one behind its latest release) so the
    command is usable as a CI gate; an *unknown* version is not a failure,
    because not knowing is a fact about the tool, not a verdict on it.
    """
    from .versions import check_cosmo, check_tools

    statuses = check_tools(check_updates=args.check_updates)
    own = check_cosmo(check_updates=args.check_updates)

    if args.format == "json":
        import dataclasses
        print(json.dumps({"cosmo": dataclasses.asdict(own),
                          "tools": [dataclasses.asdict(t) for t in statuses]},
                         indent=2))
        return 1 if any(t.needs_attention for t in statuses) else 0

    rows = []
    for t in statuses:
        glyph, label = _TOOL_MARK.get(t.state, ("·", t.state))
        version = t.version or "—"
        latest = t.latest or ("—" if args.check_updates else "")
        rows.append((glyph, t.name, version, latest, label or "", t.note))

    # Widths cover the headers too, or "INSTALLED" overflows its own column.
    name_w = max([len(r[1]) for r in rows] + [len("TOOL")])
    ver_w = max([len(r[2]) for r in rows] + [len(r[3]) for r in rows]
                + [len("INSTALLED")])
    head = f"  {'':1} {'TOOL':<{name_w}}  {'INSTALLED':<{ver_w}}"
    if args.check_updates:
        head += f"  {'LATEST':<{ver_w}}"
    print(head + "  STATUS")
    for glyph, name, version, latest, label, note in rows:
        line = f"  {glyph} {name:<{name_w}}  {version:<{ver_w}}"
        if args.check_updates:
            line += f"  {latest:<{ver_w}}"
        print(line + f"  {label}")
        if note:
            print(f"  {'':1} {'':<{name_w}}  └ {note}")

    print()
    own_glyph, own_label = _TOOL_MARK.get(own.state, ("·", own.state))
    own_line = f"  {own_glyph} cosmo {own.version}"
    if own.latest:
        own_line += f"  (latest {own.latest})"
    print(own_line + (f"  {own_label}" if own_label else ""))
    if own.note:
        print(f"    └ {own.note}")

    missing = [t for t in statuses if t.state == "missing"]
    outdated = [t for t in statuses if t.state == "outdated"]
    if missing:
        print()
        print(f"  {len(missing)} scanner(s) not installed — every finding they "
              f"would have caught is missed, and named under `skipped:` on "
              f"every run:")
        for t in missing:
            print(f"    {t.name}: {t.install}")
    if outdated:
        print()
        print(f"  {len(outdated)} scanner(s) behind their latest release. Old "
              f"rules miss new vulnerability classes.")
    if not args.check_updates:
        print()
        print("  Versions above are what is installed here. Add --check-updates "
              "to compare against the newest published release (the only part "
              "of this command that uses the network).")
    return 1 if (missing or outdated) else 0


def _cmd_trends(args) -> int:
    store = TrendStore.for_target(args.target)
    try:
        if args.disclosure:
            rows = store.disclosure_queue(args.target)
            if not rows:
                print("disclosure queue empty")
                return 0
            for r in rows:
                print(f"[{r['disclosure_status']}] {r['severity']}  {r['title']}  ({r['fingerprint']})")
            return 0

        open_rows = store.open_findings(args.target)
        print(f"open findings: {len(open_rows)}")

        trend = store.weekly_trend(args.target)
        if trend:
            print("\nweekly:")
            for week, d in trend.items():
                print(f"  {week}: +{d['introduced']} introduced, -{d['fixed']} fixed")

        noisy = store.noisiest_rules(args.target)
        if noisy:
            print("\nnoisiest rules:")
            for cat, n, frac in noisy:
                print(f"  {cat}: {n} findings, {frac:.0%} waived")

        rollup = map_report(open_rows)
        if rollup:
            print("\nOWASP Top 10 (open):")
            for row in rollup:
                print(f"  {row.owasp_id} {row.name}: {row.count}")
        return 0
    finally:
        store.close()


def _empty_diff(target: str):
    """A placeholder diff for a stage that has no single one (history sweeps)."""
    from .diff import Diff
    return Diff(source="local", target=str(target), files=[])


def _target_dir(target: str) -> str:
    # For PR targets and remote 'owner/repo' history sweeps there is no local
    # dir; config and baseline fall back to the cwd + operator defaults.
    if "#" in target or target.startswith("http") or not _osp.exists(target):
        return "."
    return target


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
