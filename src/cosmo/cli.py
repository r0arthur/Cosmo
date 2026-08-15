"""CLI trigger adapter (architecture §2). A thin caller of run_review — no scan
logic lives here, only how a scan is invoked and how results are rendered.
"""
from __future__ import annotations

import argparse
import sys

from .config import load_config
from .diff import resolve_diff
from .engine import run_review
from .output import render_cli, render_pr_comment, render_sarif
from .store import TrendStore, map_report
from .triggers import install_hook, render_hook_output, run_git_hook, run_github_action
from .waiver import Baseline, fingerprint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cosmo", description="cosmo security review + zero-day discovery (full build, steps 1–20)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_review = sub.add_parser("review", help="review a local path or GitHub PR")
    p_review.add_argument("target", help="local path, or PR ('owner/repo#123' / PR URL)")
    p_review.add_argument("--format", choices=["cli", "sarif", "pr"], default="cli")
    p_review.add_argument("--threshold", choices=["info", "low", "medium", "high", "critical"])
    p_review.add_argument("--operator-config", help="path to the operator/org config (the ceiling)")
    p_review.add_argument("--no-cache", action="store_true", help="force a full re-scan (§15)")
    p_review.add_argument("--no-color", action="store_true")
    p_review.add_argument("--record", action="store_true",
                          help="record this scan in the trend store (§14) for lifecycle tracking")

    p_waive = sub.add_parser("waive", help="waive a finding by fingerprint into the baseline")
    p_waive.add_argument("target")
    p_waive.add_argument("fingerprint")
    p_waive.add_argument("--reason", default="")

    p_base = sub.add_parser("baseline", help="list or clear waived findings")
    p_base.add_argument("target")
    p_base.add_argument("--unwaive", metavar="FINGERPRINT")

    p_hook = sub.add_parser("hook", help="run the git-hook review over the staged diff (§2)")
    p_hook.add_argument("--path", default=".", help="repo path (default: cwd)")
    p_hook.add_argument("--blocking", action="store_true", help="abort the commit on findings")
    p_hook.add_argument("--operator-config")

    p_install = sub.add_parser("install-hook", help="install a git pre-commit hook that runs cosmo")
    p_install.add_argument("--path", default=".", help="repo path (default: cwd)")
    p_install.add_argument("--type", default="pre-commit", choices=["pre-commit", "pre-push"])
    p_install.add_argument("--blocking", action="store_true")

    p_action = sub.add_parser("action", help="GitHub Action trigger: review a PR (§2)")
    p_action.add_argument("target", help="PR ref 'owner/repo#123'")
    p_action.add_argument("--post", action="store_true", help="post the gated PR comment")
    p_action.add_argument("--sarif", metavar="FILE", help="write SARIF to FILE")
    p_action.add_argument("--no-block", action="store_true", help="don't fail the job on findings")
    p_action.add_argument("--operator-config")

    p_fuzz = sub.add_parser("fuzz", help="manual-only zero-day fuzzing campaign (§7)")
    p_fuzz.add_argument("target", help="local repo path (fuzzes cosmo's own sandbox build only)")
    p_fuzz.add_argument("--language", default="python",
                        help="entry-point language, to select the integrated engine")
    p_fuzz.add_argument("--duration", help="hard time cap, e.g. 30m/2h (required — never defaults)")
    p_fuzz.add_argument("--confirm", action="store_true",
                        help="acknowledge a duration above fuzzing.confirm_above")
    p_fuzz.add_argument("--operator-config")

    p_int = sub.add_parser("interactive", help="live session — same engine, slash-commands (§7)")
    p_int.add_argument("target", help="local path or GitHub PR to open a session on")
    p_int.add_argument("--operator-config")
    p_int.add_argument("--no-scan", action="store_true", help="don't scan on start")

    p_trends = sub.add_parser("trends", help="show lifecycle/trend + compliance rollup (§14/§15)")
    p_trends.add_argument("target", help="local path previously scanned with --record")
    p_trends.add_argument("--disclosure", action="store_true",
                          help="show the coordinated-disclosure queue (§13) instead")

    p_ext = sub.add_parser("extensions", help="list discovered custom extensions (plugins/skills)")
    p_ext.add_argument("--path", default=".", help="repo path for repo cosmo.yaml (default: cwd)")
    p_ext.add_argument("--operator-config", help="operator config that may enable extensions")

    p_plugin = sub.add_parser("plugin", help="manage the Claude Code plugin surface (§17)")
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
        run_repl(args.target, operator_config=args.operator_config, autoscan=not args.no_scan)
        return 0
    if args.cmd == "fuzz":
        return _cmd_fuzz(args)
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
          f"target=sandbox-internal only (§7 scope constraint).")
    print("harness generation + engine execution require the configured sandbox "
          "toolchain; run via cosmo.fuzz.run_campaign with a fuzz_runner wired to "
          "the sandbox (§6). No external target is reachable from this command.")
    return 0


def _cmd_review(args) -> int:
    config = load_config(_target_dir(args.target), operator_config=args.operator_config)
    if args.threshold:
        config.data["threshold"] = args.threshold  # CLI flag beats config for this preference
    if args.no_cache:
        config.data.setdefault("incremental", {})["enabled"] = False

    report = run_review(args.target, config)

    if args.format == "cli":
        print(render_cli(report, color=not args.no_color))
    elif args.format == "sarif":
        print(render_sarif(report))
    elif args.format == "pr":
        print(render_pr_comment(report))

    # The store is a side layer: run_review stays pure, the CLI records the scan.
    if args.record:
        store = TrendStore.for_target(args.target)
        try:
            s = store.record_scan(args.target, report.findings)
            print(f"recorded: {s.introduced} new, {s.reopened} reopened, "
                  f"{s.fixed} fixed, {s.open_total} open")
        finally:
            store.close()

    # Non-zero exit if any non-waived finding survived the threshold (CI-friendly).
    return 1 if any(not f.waived for f in report.findings) else 0


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
            print("\nnoisiest rules (feeds §10):")
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


def _target_dir(target: str) -> str:
    # For PR targets there's no local dir; config falls back to operator defaults.
    return "." if "#" in target or target.startswith("http") else target


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
