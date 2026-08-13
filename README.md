# cosmo (MVP)

A Claude-Code-based security review tool. This is the **MVP scaffold — build
steps 1–6** of [`../cosmo-architecture.md`](../cosmo-architecture.md): a
diff-driven reviewer that runs a static pre-filter, hands its output to an LLM
review (Claude default), suppresses known findings, and renders CLI / SARIF /
PR-comment output behind a fail-closed disclosure gate.

Deliberately **out of scope** (later build steps, each a separate product behind
the gate): the dynamic-analysis sandbox (§6), zero-day fuzzing (§7), and
authorized external-target mode (§9). None of those code paths exist here.

**Step 7 — the egress broker (§9a) — is present** (`cosmo.broker`), built ahead
of the sandbox/external-target modes that depend on it. It is the single guarded
network chokepoint: mode gate → scope resolution on the resolved host (redirects
re-checked per hop) → one global rate-limit budget → logging. It is not wired
into the MVP pipeline, since steps 1–6 do no untrusted or external egress; it is
the boundary those later steps will stand behind. See `tests/test_broker.py`.

**Step 8 — the dynamic analysis sandbox (§6) — is present** (`cosmo.sandbox`),
the first consumer of the broker. It confirms suspected findings against a build
cosmo itself provisioned, in a hardened rootless container (read-only source,
no network by default, no docker socket, clean env, resource caps — all in
`build_run_args`, unit-tested). All egress runs through the broker in SANDBOX
mode. Provisioning happens in a narrow egress window with lifecycle scripts
suppressed (RISK-02), LLM-drafted commands are allowlist-validated (RISK-03),
and `not_reproducible` only feeds the waiver when a capable probe was used
(RISK-04). Teardown runs even on crash; a provisioning failure degrades findings
to `unconfirmed` rather than blocking the review. Invoked explicitly via
`confirm_findings` — never on the MVP default path. See `tests/test_sandbox.py`.

**Step 9 — the multi-model provider layer (§8) — is present** (`cosmo.providers`),
on top of the built-in Claude default. Hosted alternates (Codex/DeepSeek) and
local Llama share one OpenAI-compatible implementation; `resolve_primary`
applies the resolution order (session → CLI → repo → org → Claude) and falls
back to Claude on an unavailable provider rather than skipping review. The
**data-governance gate** (`vendor_allowed`) enforces that at
`data_sensitivity: sensitive` (a safety-tier setting a repo can only raise), only
local providers and operator-accepted vendors are eligible — a sensitive repo
never has its source fanned out to a third party. Optional `cross_check` requires
a second model to agree before a high-severity finding is surfaced as
high-confidence. The layer is wired into `run_review`; with nothing configured it
resolves to Claude, unchanged. See `tests/test_provider_layer.py`.

**Step 10 — the skills system (§10) — is present** (`cosmo.skills`). Org- and
repo-level skill files (`.cosmo/skills/*.md`, SKILL.md-style frontmatter), a
matcher that injects only skills relevant to the changed files, and a feedback
loop that *proposes* edits to noisy skills (never auto-writes) and flags
low-noise repo skills for org promotion. Security property: **repo skills are
checked into the scanned repo, so they're untrusted** — the injector puts org
skills in an authoritative section and repo skills in a clearly-labeled untrusted
section with a directive that they cannot suppress findings or override the
reviewer (same discipline as the untrusted README, RISK-03). Wired into
`run_review`; an example skill is in `examples/skills/`. See `tests/test_skills.py`.

**Step 11 — context ingestion (§4) — is present** (`cosmo.context`). Reads
issues/comments (via `gh`) to prioritize review: extracts security keywords, CVE
references, stack-trace indicators, and referenced paths into a structured signal
set, then nudges the confidence of findings located in files those issues call
out, and surfaces partial-fix hints from closed issues. Two boundaries hold:
issue text is **attacker-controllable, so it's a signal set — never raw text into
the reviewer and never ground truth** — and prioritization only ever *raises*
attention (capped), never creating or suppressing a finding. Reading only; never
posts (§12). Wired into `run_review` for GitHub targets. See `tests/test_context.py`.

**Step 12 — incremental scanning (§15) — is present** (`cosmo.cache`). Caches
expensive stage results so only what changed since the last scan re-runs;
`run_review` reuses cached static/model results when the changed files' content
is unchanged. The design point the review flagged is the **cache-key split**:
static/LLM key on the changed files' content (+ stage/prompt version), which is
sound; **dynamic keys on a composite** (file set + dependency-lockfile hash +
toolchain version), because an unchanged file can still start/stop reproducing
when a lockfile or toolchain moves — a single file hash would cache a stale
verdict. Cache lives under `.cosmo/` (gitignored). Prerequisite for the step-13
git hook to run fast inline. See `tests/test_cache.py`.

## What's implemented

| Step | Area | Status |
|---|---|---|
| 1 | Core engine `run_review(target, config)` + built-in Claude provider | real |
| 2 | Config + severity, **two-tier trust model** (RISK-01) | real, tested |
| 3 | Diff resolver — local `git diff` + GitHub PR via `gh` | real |
| 4 | Output adapters (CLI / SARIF / PR) + **fail-closed gate** (RISK-05) | real, tested |
| 5 | Waiver/baseline — **content-based fingerprint** (RISK-07) | real, tested |
| 6 | Static pre-filter — semgrep, gitleaks (dep-audit stubbed) | real (tools optional) |

The three load-bearing safety properties from the design review are implemented
and unit-tested: a scanned repo cannot loosen safety-tier config, the public
gate withholds by default on unknown sensitivity, and the waiver fingerprint
survives line shifts without suppressing genuinely new instances.

## Install & run

```bash
pip install -e .            # core (PyYAML only)
pip install -e '.[claude]'  # + Anthropic SDK for the LLM stage
export ANTHROPIC_API_KEY=…  # optional; without it the LLM stage is skipped, not failed

cosmo review .                         # local working-tree diff
cosmo review owner/repo#123            # a GitHub PR (needs the gh CLI)
cosmo review . --format sarif          # CI output
cosmo review . --format pr             # preview the gated public comment
```

The static tools (`semgrep`, `gitleaks`) are optional — if absent, that stage is
listed under `skipped:` rather than failing the scan.

### Waivers

```bash
cosmo review .                  # note a finding's fingerprint in the output
cosmo waive . <fingerprint> --reason "false positive: test fixture"
cosmo baseline .                # list waived
cosmo baseline . --unwaive <fingerprint>
```

## Config trust tiers (§15/§16)

`cosmo.yaml` lives in the repo under scan and is **untrusted**. Preference keys
(threshold, ignore_paths, providers) override the operator config; safety keys
(`sandbox.*`, `fuzzing.*`, `external_targets.*`, …) can only be *tightened* by a
repo — loosening values are clamped and warned at load. Operator/org config is
the ceiling, supplied via `--operator-config` or `COSMO_OPERATOR_CONFIG`. See
[`cosmo.example.yaml`](cosmo.example.yaml).

## As a Claude Code plugin

Ships with `.claude-plugin/plugin.json` and a `/cosmo-review` command
(`commands/cosmo-review.md`). §17: cosmo depends on Claude Code, it does not fork
it.

## Tests

```bash
pip install -e '.[dev]' && pytest
```
