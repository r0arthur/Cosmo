---
description: Run a cosmo security review over the current diff or a GitHub PR
allowed-tools: Bash(cosmo:*), Bash(python -m cosmo:*), Bash(git diff:*), Bash(gh pr diff:*)
---

Run a cosmo security review (static pre-filter + LLM review) and report findings.

Steps:

1. Determine the target:
   - If the user named a PR (`owner/repo#123` or a PR URL), use that.
   - Otherwise use the current working directory (local working-tree diff vs HEAD).

2. Run the review:
   ```
   cosmo review <target> --format cli
   ```
   (Use `--format sarif` for CI, `--format pr` to preview the gated public comment.)

3. Summarize the findings for the user. Note any `skipped:` stages (e.g. semgrep
   not installed, or the model provider unavailable) so results aren't mistaken
   for a clean bill of health.

4. Do NOT post anything to GitHub. Public posting is governed by the fail-closed
   disclosure gate (§12); the `--format pr` output already shows what would and
   would not be posted. Confirmed/high-sensitivity findings are withheld by design.

Notes:
- cosmo's own guardrails are authoritative — this command cannot relax the config
  trust tiers or the disclosure gate.
- MVP scope: no sandbox execution, no fuzzing, no external-target scanning.
