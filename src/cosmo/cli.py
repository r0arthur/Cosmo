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
from .waiver import Baseline, fingerprint


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cosmo", description="cosmo security review (MVP, steps 1–6)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_review = sub.add_parser("review", help="review a local path or GitHub PR")
    p_review.add_argument("target", help="local path, or PR ('owner/repo#123' / PR URL)")
    p_review.add_argument("--format", choices=["cli", "sarif", "pr"], default="cli")
    p_review.add_argument("--threshold", choices=["info", "low", "medium", "high", "critical"])
    p_review.add_argument("--operator-config", help="path to the operator/org config (the ceiling)")
    p_review.add_argument("--no-cache", action="store_true", help="force a full re-scan (§15)")
    p_review.add_argument("--no-color", action="store_true")

    p_waive = sub.add_parser("waive", help="waive a finding by fingerprint into the baseline")
    p_waive.add_argument("target")
    p_waive.add_argument("fingerprint")
    p_waive.add_argument("--reason", default="")

    p_base = sub.add_parser("baseline", help="list or clear waived findings")
    p_base.add_argument("target")
    p_base.add_argument("--unwaive", metavar="FINGERPRINT")

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
    return 2


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

    # Non-zero exit if any non-waived finding survived the threshold (CI-friendly).
    return 1 if any(not f.waived for f in report.findings) else 0


def _target_dir(target: str) -> str:
    # For PR targets there's no local dir; config falls back to operator defaults.
    return "." if "#" in target or target.startswith("http") else target


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
