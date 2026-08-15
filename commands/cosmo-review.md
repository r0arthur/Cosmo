---
description: Run a cosmo security review over the current diff or a GitHub PR
allowed-tools: Bash(cosmo:*), Bash(python -m cosmo:*)
---

Run a cosmo security review over the current diff or a GitHub PR and report findings.

Steps:
1. Determine the target: a PR the user named (`owner/repo#123` or URL), else the current working-tree diff vs HEAD.
2. Run the review:
   ```
   cosmo review <target> --format cli
   ```
   (`--format sarif` for CI; `--format pr` to preview the *gated* public comment.)
3. Summarize findings. Surface any `skipped:` stages (semgrep missing, provider unavailable) so a partial run is not mistaken for a clean bill of health.
4. Do NOT post anything to GitHub. Public posting is governed by the fail-closed disclosure gate (§11); `--format pr` already shows what would and would not be posted, with confirmed/high-sensitivity findings withheld by design.

cosmo's own guardrails are authoritative — this command cannot relax the config trust tiers or the disclosure gate. Sandbox confirmation (§6), fuzzing (§7), disclosure (§13), and external-target recon (§9) are reached through their own `/cosmo-*` commands, each still enforced inside cosmo.
