# Contributing to cosmo

cosmo is a security review and zero-day discovery tool. It is
built by security researchers, for security researchers — contributions from the
community are welcome, whether that's a new detector, a skill pack, a bug fix, or
a sharpening of the safety model.

There are two very different ways to contribute, and they have different bars:

- **Extend cosmo from the outside** — ship a [custom extension](docs/extensions.md)
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
| RISK-03 | Untrusted input (README, skills, issues, extensions) can't override the reviewer | `skills/inject.py`, extensions, `config.OPERATOR_ONLY_PREFERENCE_KEYS` |
| RISK-04 | Absence of evidence never auto-waives a finding | sandbox confirmation; history reachability |
| RISK-05 | The public-comment gate fails **closed** on unknown sensitivity | `output/` gate |
| RISK-06 | Nothing is disclosed without explicit human approval | `disclose/` |
| RISK-07 | Waiver fingerprints are content/AST-based, not line-based | `waiver/` |

**If your change touches one of these, say so explicitly in the PR description and
add a test that proves the property still holds.** A PR that weakens a guardrail
without a very good, stated reason will be declined.

---

## Development setup

Requires Python **3.10+** (CI tests 3.10 – 3.13).

```bash
git clone git@github.com:r0arthur/Cosmo.git
cd Cosmo
python -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'          # + '.[claude]' for the live LLM stage
pytest -q                        # the full suite must pass
```

`.[dev]` adds `pytest`. The only runtime dependency is `PyYAML`.

### The commands you'll actually use

| Command | Does |
|---|---|
| `pytest -q` | The full suite |
| `pytest tests/test_engine_smoke.py -q` | One file |
| `pytest -k reachability -q` | Match by name |
| `make test` | Same suite via `PYTHONPATH=src` — no install needed |
| `make plugin-check` | Fail if the plugin surface drifted from the registry |
| `make deb` | Build the `.deb` into `dist/` |
| `make install` / `make uninstall` | Install to `~/.local` from source |
| `make help` | List every target |

Run your change end to end before opening a PR:

```bash
PYTHONPATH=src python -m cosmo review . --live
```

### The test suite is hermetic — keep it that way

No network, no live model, no external binary. Every static scanner
(`semgrep`, `opengrep`, `gitleaks`, `trufflehog`, `bandit`, `trivy`,
`find-sec-bugs`) and the Anthropic SDK are optional; when one is absent it is
reported under `skipped:` rather than failing. Scanner tests feed the mapper the
JSON that tool really returns and stub the subprocess — capture it from a real
run rather than writing it from memory.

New tests must not reach the network or require a binary that isn't already a
soft dependency. Fake providers are the established pattern — see
`tests/test_audit.py` for a counting provider and `tests/test_history.py` for
tests that build real throwaway git repos with `subprocess`.

### There is no linter or type checker configured

`.gitignore` anticipates `ruff` and `mypy`, but neither is set up and CI runs
neither. Match the surrounding code by reading it rather than by running a tool.

### What CI checks

`.github/workflows/ci.yml` runs on every PR:

- `pytest` on Python 3.10, 3.11, 3.12, 3.13
- `make plugin-check` — plugin surface drift
- Builds the `.deb`, installs it, runs it, removes it
- Runs `scripts/install.sh` and verifies `cosmo` lands on `PATH`
- Asserts `pyproject.toml` and `src/cosmo/__init__.py` declare the same version

All of it must pass before a merge.

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

- **Branch** from `main`: `feature/<short-name>` or `fix/<short-name>`.
- **One logical change per PR.** Small, reviewable diffs merge fast.
- **Commit messages**: imperative subject, a body explaining *why*, and cite the
  architecture section (e.g. `§9a`) or RISK id when relevant. Recent history uses
  a conventional-commit prefix (`feat:`, `fix:`, `ci:`, `docs:`) — follow it.
- Reference the issue the PR closes.

There are no issue or PR templates in `.github/`; describe what changed, which
RISK id or architecture section it touches, and how you tested it.

## Adding a test for a new feature

Every change lands with real code *and* a hermetic test. Where it goes:

| You changed | Test lives in |
|---|---|
| The pipeline in `engine.py` | `tests/test_engine_smoke.py`, or a topic file |
| A config key or trust tier | `tests/test_config_tiers.py` |
| A safety property (RISK-01…07) | Alongside the property, asserting it still holds |
| A CLI command or flag | The topic file for that command |
| A new module | A new `tests/test_<module>.py` |

If your change touches a **safety property**, say so in the PR description and
add a test that proves the property still holds. That test should fail if the
guardrail is removed — a test that passes either way isn't protecting anything.

Concurrency changes need a test that would actually catch a race:
`tests/test_audit.py::test_reviews_actually_run_concurrently` uses a
`threading.Barrier` that cannot be satisfied by sequential execution.

## What makes a great contribution

- **New detectors / skill packs** — the highest-leverage, lowest-friction
  contribution. Prefer shipping them as [extensions](docs/extensions.md); propose
  core inclusion only once a detector has proven itself broadly useful.
- **Coverage for a vulnerability class cosmo handles weakly** — bring a repro and
  a test.
- **Sharpening a guardrail** — a case where a safety property *could* be bypassed,
  with a failing test that demonstrates it. These are especially valuable; see
  Security below for how to report the sensitive ones.
- **Docs and examples** — a clearer authoring guide or a new worked example under
  `examples/` helps every future contributor.
- **A new static scanner** — add a runner in `src/cosmo/static/runners.py` and an
  entry in the `TOOLS` registry. Two things are not optional: build the parser
  against the tool's **real output** (capture a run; do not write it from
  memory), and fill in the attribution fields — `project`, `author`, `license`,
  `homepage` — then add the tool to [CREDITS.md](CREDITS.md). A test enforces
  both, because cosmo's detection is other people's work and shipping it
  uncredited is not acceptable. Set `version_argv` and `latest` too, or
  `cosmo tools` has nothing to say about your scanner and its silence reads as
  "fine"; if the tool genuinely cannot report a version, pass `version_argv=()`
  so it is reported as unknown rather than assumed current.

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

Full text: [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

## Where the docs are

| Guide | For |
|---|---|
| [installation.md](docs/installation.md) | Every install method |
| [getting-started.md](docs/getting-started.md) | First run |
| [usage.md](docs/usage.md) | Every command and flag |
| [configuration.md](docs/configuration.md) | Config keys and trust tiers |
| [architecture.md](docs/architecture.md) | Modules, pipeline, design decisions |
| [examples.md](docs/examples.md) | End-to-end workflows |
| [faq-troubleshooting.md](docs/faq-troubleshooting.md) | Error messages |
| [extensions.md](docs/extensions.md) | Authoring extensions |
| [build-log.md](docs/build-log.md) | The 20-step implementation record |
| [CREDITS.md](CREDITS.md) | The upstream projects cosmo runs, and their licenses |

If your change alters a command, flag, config key, or safety property, **update
the relevant doc in the same PR**. Docs drifting from behaviour is a defect in a
tool whose value rests on reporting exactly what it did.
