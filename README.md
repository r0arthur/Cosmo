# cosmo

**A security review and zero-day discovery tool that never lets an unchecked result look like a clean one.**

[![CI](https://github.com/r0arthur/Cosmo/actions/workflows/ci.yml/badge.svg)](https://github.com/r0arthur/Cosmo/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)

cosmo reviews a diff, a GitHub pull request, a whole project, or a repository's
entire commit history. It runs a static pre-filter, hands that output to an LLM
review so the model doesn't re-derive it, suppresses known findings by
content-based fingerprint, and renders CLI / SARIF / PR-comment output behind a
fail-closed disclosure gate.

What makes it different is the discipline: the repository under review is treated
as untrusted input, every stage that *didn't* run is named in the report, and no
finding is disclosed publicly or waived automatically without evidence.

---

## Quick start

```bash
git clone git@github.com:r0arthur/Cosmo.git
cd Cosmo
make install          # venv + semgrep + a `cosmo` on your PATH
```

```bash
cosmo review .                       # your working-tree changes
cosmo review . --model claude-cli    # add the AI review, on your Claude subscription
cosmo review owner/repo#123          # a GitHub PR, online — no clone
cosmo history . --since '6 months ago'   # sweep the repo's past for old flaws
cosmo review . --report report.md    # full findings + coverage, as Markdown
```

No API key is needed for the static scan. Full options in
**[docs/installation.md](docs/installation.md)**.

---

## Documentation

| Guide | For |
|---|---|
| **[Installation](docs/installation.md)** | Every install method, prerequisites, upgrade, uninstall |
| **[Getting started](docs/getting-started.md)** | First run, what the output means, smallest example |
| **[Usage reference](docs/usage.md)** | Every command and flag, with examples and real output |
| **[Configuration](docs/configuration.md)** | `cosmo.yaml`, env vars, and the two-tier trust model |
| **[Examples](docs/examples.md)** | End-to-end workflows |
| **[Architecture](docs/architecture.md)** | Modules, pipeline, and the design decisions behind them |
| **[FAQ & troubleshooting](docs/faq-troubleshooting.md)** | When something goes wrong |
| **[Extensions](docs/EXTENSIONS.md)** | Ship a custom detector, skill, or command |
| **[Contributing](CONTRIBUTING.md)** | Dev setup, conventions, how to submit a PR |
| **[Build log](docs/build-log.md)** | The 20-step implementation record |

---

## What it does

- **Reviews diffs, PRs, projects, and history.** `cosmo review` for the present,
  `cosmo history` for the past — including remote repositories with no clone.
- **Static + AI, in that order.** semgrep and gitleaks run first; their output
  becomes context for the model rather than work it repeats.
- **Model-pluggable, not model-locked.** Claude by default, plus Codex,
  DeepSeek, and a local Llama endpoint. Mark a repo `sensitive` and only local
  providers are eligible — source that must not leave your network never does.
- **Fail-closed public output.** A confirmed or sensitive finding is withheld
  from a PR comment and routed to private coordinated disclosure. The gate fails
  closed on unknown sensitivity.
- **Waivers that survive refactors.** Fingerprints are content-based, not
  line-based.
- **Runs anywhere you already work.** Git hook, GitHub Action, live terminal
  session, or a Claude Code plugin surface generated from the command registry.
- **Extensible without forking.** Custom detectors, skills, and `/x-*` commands
  load as operator-gated extensions.

## What it refuses to do

These are enforced in code, not documented as guidance:

- **Trust the repository it is reviewing.** `cosmo.yaml` can set preferences but
  can only *tighten* safety settings; repo-provided skills are injected as
  explicitly untrusted and cannot suppress findings.
- **Hide what it skipped.** A missing tool or unavailable model is named in the
  report. "No findings" and "nothing was checked" never look alike.
- **Assume absence of evidence is evidence of absence.** A sandbox probe that
  didn't reproduce, or history code that has since disappeared, is annotated —
  never auto-waived.
- **Disclose anything without a human.** Advisories are drafted and *queued*;
  delivery needs explicit approval and an operator-configured endpoint.
- **Fire an unbounded number of model calls.** Whole-project audits and history
  sweeps are capped by an operator ceiling applied before any call is made.

---

## Requirements

Python **3.10+** and `PyYAML`. Everything else — `semgrep`, `gitleaks`, a model
provider, the `gh` CLI — is optional, and cosmo reports what's missing rather
than failing.

**No Claude account is required.** The static scan runs with no account at all,
and the AI stage takes whichever provider you configure. Claude is the default
because it is the fallback when a configured provider is unavailable; cosmo also
*ships as* a Claude Code plugin, which is a distribution surface rather than a
dependency.

---

## Contributing

Researchers welcome — new detectors, skill packs, bug fixes, and sharpenings of
the safety model. Extend from the outside with an
**[extension](docs/EXTENSIONS.md)** (no core changes needed), or contribute to
the core following **[CONTRIBUTING.md](CONTRIBUTING.md)**.

Anything touching a safety property needs a test proving the property still
holds. **Report a guardrail bypass in cosmo itself privately** — see
[CONTRIBUTING.md](CONTRIBUTING.md#reporting-security-issues-in-cosmo-itself).

## License

[MIT](LICENSE) © r0arthur
