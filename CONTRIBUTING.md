# Contributing to cosmo

cosmo is a Claude-Code-based security review and zero-day discovery tool. It is
built by security researchers, for security researchers — contributions from the
community are welcome, whether that's a new detector, a skill pack, a bug fix, or
a sharpening of the safety model.

There are two very different ways to contribute, and they have different bars:

- **Extend cosmo from the outside** — ship a [custom extension](docs/EXTENSIONS.md)
  (a detector, skill, or command). This needs no changes to cosmo itself and no
  review from us; you own and distribute it.
- **Contribute to cosmo's core** — change the engine, the guardrails, an adapter,
  or the architecture. This goes through the workflow below, and core changes
  that touch a **safety property** get extra scrutiny.

---

## Ground rules

cosmo's whole value is that its safety properties hold *by construction*. Every
contribution is measured against them. The load-bearing ones, each traceable to a
design-review finding:

| ID | Property | Where it's enforced |
|---|---|---|
| RISK-01 | A scanned repo can only *tighten* safety config, never loosen it | `config.py` trust tiers |
| RISK-02 | Every network touch goes through one guarded egress broker | `broker/` |
| RISK-03 | Untrusted input (README, skills, issues, extensions) can't override the reviewer | `skills/inject.py`, extensions |
| RISK-04 | Absence of evidence never auto-waives a finding | sandbox confirmation; history reachability |
| RISK-05 | The public-comment gate fails **closed** on unknown sensitivity | `output/` gate |
| RISK-06 | Nothing is disclosed without explicit human approval | `disclose/` |
| RISK-07 | Waiver fingerprints are content/AST-based, not line-based | `waiver/` |

**If your change touches one of these, say so explicitly in the PR description and
add a test that proves the property still holds.** A PR that weakens a guardrail
without a very good, stated reason will be declined.

---

## Development setup

```bash
git clone git@github.com:r0arthur/Cosmo.git
cd Cosmo
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'          # + '.[claude]' for the live LLM stage
pytest -q                        # the full suite must pass
```

The test suite is **hermetic** — no network, no live model, no external tools
required. The static tools (`semgrep`, `gitleaks`) and the Anthropic SDK are all
optional; when absent, the relevant stage is reported under `skipped:` rather than
failing. Keep it that way: new tests must not reach the network or require a
binary that isn't already a soft dependency.

## Workflow

1. **Open an issue first** for anything beyond a small fix — especially anything
   touching the architecture or a safety property — so we can agree on the
   approach before you build it.
2. **Branch** from `main`: `feature/<short-name>` or `fix/<short-name>`.
3. **Build with tests.** Every change lands with real code *and* a hermetic unit
   test. We don't merge behavior that isn't proven under test.
4. **Match the house style.** Read the module you're editing first; mirror its
   naming, comment density, and idiom. Docstrings explain the *why* (and cite the
   architecture section / RISK id where relevant), not the *what*.
5. **Keep the plugin surface in sync.** If you add or rename an interactive
   command, run `cosmo plugin sync` and commit the regenerated files; CI runs
   `cosmo plugin check` and fails on drift.
6. **Open a PR** describing what changed, which architecture section / RISK id it
   touches, and how you tested it.

## Commit & PR conventions

- One logical change per PR. Small, reviewable diffs merge fast.
- Commit messages: imperative subject, a body explaining *why*, and cite the
  architecture section (e.g. `§9a`) or RISK id when relevant.
- Reference the issue the PR closes.

## What makes a great contribution

- **New detectors / skill packs** — the highest-leverage, lowest-friction
  contribution. Prefer shipping them as [extensions](docs/EXTENSIONS.md); propose
  core inclusion only once a detector has proven itself broadly useful.
- **Coverage for a vulnerability class cosmo handles weakly** — bring a repro and
  a test.
- **Sharpening a guardrail** — a case where a safety property *could* be bypassed,
  with a failing test that demonstrates it. These are especially valuable; see
  Security below for how to report the sensitive ones.
- **Docs and examples** — a clearer authoring guide or a new worked example under
  `examples/` helps every future contributor.

## Reporting security issues in cosmo itself

If you find a way to make cosmo **bypass one of its own guardrails** — exfiltrate a
scanned repo, disclose without approval, post through the gate, escape the egress
broker, or have an untrusted repo override the reviewer — please **do not open a
public issue**. Report it privately to the maintainer
(<karthur0822@gmail.com>) with a repro, and give us a chance to fix it under a
coordinated-disclosure window before publishing. cosmo holds itself to the same
disclosure discipline (§13) it applies to the code it reviews.

## Code of conduct

Be direct, be kind, assume good faith. This is a security project — expect
adversarial thinking about *code*, not about *people*.
