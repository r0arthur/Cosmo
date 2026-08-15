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

**Step 13 — the git hook adapter (§2) — is present** (`cosmo.triggers`). A thin
caller of `run_review` over the **staged** diff (`git diff --cached`), with the
§2 defaults: `critical` threshold, short output, opt-in blocking, static + LLM
only (no sandbox/fuzzing), leaning on the step-12 cache to stay fast. Install it
with `cosmo install-hook` (writes `.git/hooks/pre-commit`); it runs `cosmo hook`,
which prints a short summary and — only when `--blocking` — aborts the commit on
an actionable finding. A non-blocking hook never fails a commit. See
`tests/test_git_hook.py`.

```bash
cosmo install-hook            # non-blocking pre-commit hook
cosmo install-hook --blocking # abort commits on critical findings
cosmo hook                    # run manually over the staged diff
```

**Step 14 — the GitHub Action adapter (§2) — is present** (`cosmo.triggers`). A
thin caller of `run_review` for the PR-diff trigger: `medium+` threshold, SARIF
output for the Security tab, a PR comment, and configurable blocking. This is
where the **fail-closed gate (RISK-05) governs a real outbound post** — the PR
comment is rendered through `render_pr_comment`, so a confirmed/sensitive finding
(and its PoC) is withheld and only a generic acknowledgment is posted; the
finding still lands in SARIF for the operator. Tested that a hardcoded-secret
finding and a confirmed-critical RCE never appear in the posted body. A ready-to-
copy workflow is in `examples/github/`. See `tests/test_github_action.py`.

```bash
cosmo action "owner/repo#123" --post --sarif cosmo.sarif   # (runs in CI)
```

**Step 15 — the trend + findings store (§14) and compliance mapping (§15) — is
present** (`cosmo.store`). A lightweight SQLite side layer: `run_review` stays
pure, and a trigger (or `cosmo review --record`) records each scan so cosmo can
report a finding's lifecycle — introduced, reopened, or fixed over time — per
target. It also computes the **noisiest rules** (categories with a high waived
fraction), which is the signal that feeds the §10 skills feedback loop, and holds
the coordinated-disclosure queue (§13). The compliance layer rolls findings up to
**OWASP Top 10 2021** by CWE; unmapped CWEs fall through to A04 (Insecure Design)
rather than vanishing from the rollup, and an operator can layer an org mapping on
top without editing code. It only ever *reports* — it never changes a finding's
severity or whether it surfaces. See `tests/test_trends.py`.

```bash
cosmo review . --record       # record this scan's findings for trend tracking
cosmo trends .                # lifecycle, noisiest rules, OWASP rollup
cosmo trends . --disclosure   # the coordinated-disclosure queue
```

**Step 16 — the zero-day fuzzing campaign (§7) — is present** (`cosmo.fuzz`), a
separate, **manual-only** capability (`cosmo fuzz`) for surfacing genuinely
unknown vulnerabilities against cosmo's *own sandboxed build*. cosmo orchestrates
an existing engine per language (Atheris/libFuzzer/AFL++/go-fuzz/Jazzer) — it
never reimplements one — over an LLM-drafted harness per entry point, a
content-addressed persistent seed corpus, and stack-hash crash triage with input
minimization. The design-review constraints are load-bearing and tested:

- **Hard scope constraint** — no code path accepts an external URL as a target;
  a campaign refuses anything but the sandbox-internal instance, and all engine
  egress is stamped `SANDBOX` mode through the broker (§9a).
- **Novelty is never asserted** — a crash the check can't match against a known
  CVE/issue is *unverified-novel*, never "novel"; a failed lookup does not get
  read as "no match ⇒ novel." Matches only *flag* likely duplicates for review.
- **Coverage is never assumed** — the campaign runs against the fraction of entry
  points whose harness actually built, surfaced as `coverage_fraction`.
- **Duration never defaults silently** — an unset `--duration` prompts; the cap
  is a safety-tier config a repo can only lower, and a run above
  `fuzzing.confirm_above` needs explicit `--confirm`.
- **No scheduler, no daemon; always tears down** — `run_campaign` is a plain
  function, and teardown runs even when the engine crashes mid-run.

`fuzzing.enabled` is off by default and a repo cannot widen it past the operator
ceiling. See `tests/test_fuzz.py`.

```bash
cosmo fuzz . --duration 30m --operator-config op.yaml   # manual-only, sandbox build
```

**Step 17 — the interactive command layer (§7) — is present** (`cosmo.interactive`).
Cosmo as a live session (`cosmo interactive <target>`): the **same engine** as
batch mode, answering follow-ups from in-session findings state without
re-scanning. Slash-commands — `/duration`, `/model`, `/threshold`, `/skills`,
`/confirm`, `/waive`, `/baseline`, `/status`, `/report`, `/help` — each delegate
to the same guarded code batch mode runs. The load-bearing property from the
design review is that **the command layer cannot bypass the guardrails**, tested
directly:

- `/duration` is capped by `fuzzing.max_duration`; `/duration extend` stays
  clamped, and a run above `fuzzing.confirm_above` needs `--confirm`. Raising the
  ceiling requires editing config, never a chat command.
- `/model` resolves through the §8 data-governance gate — a sensitive repo's
  source is never fanned to a disallowed vendor from a session command; it
  reports the refusal and stays on the safe default.
- `/report pr` renders through the fail-closed public-comment gate (RISK-05),
  withholding a sensitive/confirmed finding and its PoC exactly as the Action does.
- `/threshold` only moves the session's severity floor — it never writes a
  safety-tier key.

`/scope` (§9, step 19) and `/disclose` (§13, step 18) register into this same
dispatcher when those steps land. See `tests/test_interactive.py`.

```bash
cosmo interactive .            # live session; /help for commands
```

**Step 18 — the coordinated disclosure workflow (§13) — is present**
(`cosmo.disclose`). For **confirmed, high-severity, unpatched** findings from any
source, cosmo drafts a private advisory to the maintainer contact from the repo's
`SECURITY.md` and **queues** it. The load-bearing property from the design review
is that **nothing leaves the machine without explicit human approval**, tested
directly:

- `queue_disclosure` gates on eligibility (confirmed + `HIGH`+ + not waived),
  drafts the advisory, and enqueues it as `queued` in the findings store — it
  **sends nothing**.
- `send_disclosure` refuses without a `HumanApproval` that matches *this*
  finding (a bare truthy value or an approval for another finding won't do), and
  the transport is never touched when approval is missing.
- Every send routes through the egress broker (§9a) in `DISCLOSURE` mode, so the
  delivery endpoint must be an **operator-configured** disclosure endpoint —
  a `SECURITY.md` pointing at an arbitrary host is refused even *with* approval
  (it's untrusted repo input, RISK-03).
- CVE is left `pending` — assignment is routed via the maintainer/CNA, never
  self-announced. Status lifecycle (`queued`→`reported`→`acknowledged`→`patched`
  →`disclosed`) lives in the store (§14).

Triggered manually with `/disclose <finding-id>` from an interactive session,
which drafts + queues and reports that nothing was sent. See
`tests/test_disclose.py`.

**Step 19 — authorized external-target mode (§9) — is present** (`cosmo.external`).
Testing a live target the user is *separately authorized* to test (a bug-bounty
program, an approved pentest) — distinct from §6/§7, which only ever touch a build
cosmo provisioned itself, with **no code path between the two**. All enforcement
already lives in the egress broker (§9a, step 7); this layer adds `/scope`
declaration parsing and a thin recon driver. The §9 guarantees hold under test:

- **`/scope` is mandatory** — recon is refused (`ScopeRequired`) until a scope is
  declared, and the declaration must be complete (program, non-empty in-scope
  list, an explicit rate limit read from the program's terms, never inferred).
- **Out-of-scope is hard-excluded, not warned** — an excluded or non-included
  host raises `EgressDenied` and the tool runner never runs; the SSRF net still
  refuses the metadata IP even under a wildcard scope.
- **One global rate-limit budget** sits in front of *all* tools — a second tool
  shares the first's budget, so combined concurrency can't exceed the declared
  limit.
- **Every request is logged** (allowed and denied alike) — the record a program
  owner may ask for.
- **Operator clamps** — `external_targets.enabled` is a safety-tier switch a repo
  can't flip on; the operator's `mandatory_excludes` are unioned into every
  declaration and a `max_rate_limit_per_sec` ceiling clamps the declared rate down.

Findings normalize to the shared `Finding` shape (`source="external"`) and flow
into the same aggregator/waiver/disclosure paths. `/scope` is wired into the
interactive session, completing the §7 command set. See `tests/test_external.py`.

**Step 20 — Claude Code plugin/skill integration (§17) — is present**
(`cosmo.plugin`), the final build step. Cosmo ships as a Claude Code plugin: a
`/cosmo-review` umbrella command plus a `/cosmo-*` family (scope, disclose,
confirm, waive, report, …). It **reuses Claude Code's auth/session/tool-use** by
shelling to the same `cosmo` binary the CLI, git hook, and GitHub Action use — it
does **not** fork Claude Code, and importing the package never requires Claude
Code to be installed (reuse, not fork; §17). The load-bearing property is that the
plugin surface *cannot widen past the enforced layer*:

- **The surface is generated from the one guarded registry.** `command_specs()`
  derives every slash command from `interactive.commands._COMMANDS`; a command
  that is not in the enforced dispatcher cannot be exposed, and `cosmo plugin
  check` fails CI if the on-disk `commands/*.md` drift from it.
- **Every command is tool-narrowed.** Each generated command file restricts
  `allowed-tools` to `Bash(cosmo:*)` — never a bare shell, a raw network tool, or
  a `gh … comment` posting tool. Public posting stays behind the §11 gate *inside*
  cosmo; the plugin can never grant itself that capability.
- **The in-process bridge routes through the same `dispatch`.** `PluginBridge`
  holds the same `Session` the REPL uses and forwards each line to the guarded
  dispatcher — an unknown/refused command is refused identically. `open_session`
  loads config through `load_config`, so a plugin invocation gets the operator
  config as the §15 ceiling and cannot inject a safety-tier value.

`cosmo plugin sync` regenerates `.claude-plugin/plugin.json` and the command
files from code; `cosmo plugin check` reports drift without writing. See
`tests/test_plugin.py`. **This completes the 20-step build order.**

## What's implemented

| Step | Area | Status |
|---|---|---|
| 1 | Core engine `run_review(target, config)` + built-in Claude provider | real |
| 2 | Config + severity, **two-tier trust model** (RISK-01) | real, tested |
| 3 | Diff resolver — local `git diff` + GitHub PR via `gh` | real |
| 4 | Output adapters (CLI / SARIF / PR) + **fail-closed gate** (RISK-05) | real, tested |
| 5 | Waiver/baseline — **content-based fingerprint** (RISK-07) | real, tested |
| 6 | Static pre-filter — semgrep, gitleaks (dep-audit stubbed) | real (tools optional) |
| 7 | Egress broker (§9a) — single chokepoint, mode gate + scope + rate + log (RISK-02) | real, tested |
| 8 | Dynamic sandbox — provision/health/confirm/evidence/teardown (§6) | real, tested |
| 9 | Multi-model provider layer — alternates, resolution order, ensemble, §8 gate | real, tested |
| 10 | Skills system + enhancement feedback loop (RISK-03) | real, tested |
| 11 | Context ingestion — issues/comments feeding prioritization (RISK-03) | real, tested |
| 12 | Incremental scanning — per-file / composite-key caching (§15) | real, tested |
| 13 | Git-hook adapter (pre-commit / pre-push) | real, tested |
| 14 | GitHub Action adapter — gated PR comment (RISK-05) | real, tested |
| 15 | Trend store + CWE→OWASP compliance mapping (§14) | real, tested |
| 16 | Zero-day fuzzing — harness gen, engines, triage, novelty-never-asserted (§7) | real, tested |
| 17 | Interactive command layer — `/…` over a live session, no guardrail bypass (§7) | real, tested |
| 18 | Coordinated disclosure — drafts-and-**queues**, human approval required (RISK-06) | real, tested |
| 19 | Authorized external-target mode — `/scope`, exclusions, logging (§9) | real, tested |
| 20 | Claude Code plugin/skill integration — generated surface, no bypass (§17) | real, tested |

The load-bearing safety properties from the design review are implemented and
unit-tested end to end: a scanned repo cannot loosen safety-tier config, the
public gate withholds by default on unknown sensitivity, the waiver fingerprint
survives line shifts without suppressing genuinely new instances, every network
touch funnels through one guarded broker, fuzzing never asserts novelty, nothing
is disclosed without explicit human approval, and the plugin surface cannot widen
past the enforced command layer. **174 tests pass.**

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
