# Configuration

Every environment variable, config file key, and behaviour-affecting flag, with
defaults and what happens when you omit them.

See also: **[installation.md](installation.md)** ·
**[usage.md](usage.md)** · **[faq-troubleshooting.md](faq-troubleshooting.md)**

---

## The two-tier trust model

This is the single most important thing to understand about cosmo's config, and
it exists because **`cosmo.yaml` lives inside the repository being reviewed** —
which is untrusted input.

```
operator config  ──►  the ceiling (trusted; yours)
                          │
repo cosmo.yaml  ──►  may set preferences freely,
                      may only TIGHTEN safety keys
```

| Tier | Sections | Rule |
|---|---|---|
| **Preference** | `threshold`, `ignore_paths`, `providers`, `context_ingestion`, `output`, `skills` | Repo overrides the operator |
| **Safety** | `sandbox`, `fuzzing`, `external_targets`, `disclosure`, `triggers`, `providers_policy`, `extensions`, `llm_audit`, `history` | Operator is the ceiling; a repo may only tighten |

A repo value that would loosen a safety key is **clamped back and warned** at
load, not silently accepted. Without this, a malicious repository ships
`sandbox: {network: bridge}` and relaxes the very isolation meant to contain it.

Warnings appear in the report's `note:` lines and in `--live`.

### Which safety keys accept a repo value at all

Only these. Every *other* key under a safety section is operator-only — a repo
value is ignored and warned.

| Key | A repo may |
|---|---|
| `sandbox.enabled` | turn off, never on |
| `sandbox.confirmation` | turn off, never on |
| `sandbox.network` | choose an equal-or-more-restrictive mode |
| `sandbox.timeout_seconds` | lower |
| `fuzzing.enabled` | turn off, never on |
| `fuzzing.max_duration` | lower |
| `fuzzing.confirm_above` | lower |
| `providers_policy.data_sensitivity` | **raise** (tightening = more restrictive) |
| `llm_audit.max_files` | lower |
| `llm_audit.concurrency` | lower |
| `history.max_commits` | lower |

### One reserved key inside a preference section

`skills.org_dir` names the directory whose skills are injected as
**authoritative**. It is a trust designation, not a taste, so despite `skills`
being a preference section a repo value for this key is dropped and warned — and
the operator's value survives a repo `skills` block rather than being erased by
it.

Without that, a repository could point `org_dir` inside its own tree and have its
own skills loaded as trusted, handing the code under audit a direct channel to
instruct the reviewer.

---

## Where config comes from

Resolution order, lowest priority first:

1. **Built-in operator defaults** (see the table below)
2. **Operator config** — `--operator-config FILE`, or `$COSMO_OPERATOR_CONFIG`
3. **Repo `cosmo.yaml`** — in the scanned target, merged under the tier rules
4. **CLI flags** — highest, but still tier-bound (`--max-commits` may only lower
   the ceiling, it cannot raise it)

```bash
cosmo review . --operator-config /etc/cosmo/operator.yaml
export COSMO_OPERATOR_CONFIG=/etc/cosmo/operator.yaml
```

A starting point with every key annotated ships as
[`cosmo.example.yaml`](../cosmo.example.yaml).

---

## Environment variables

| Variable | Used for | Default / if unset |
|---|---|---|
| `COSMO_OPERATOR_CONFIG` | Path to the operator config (the ceiling) | Built-in defaults only |
| `ANTHROPIC_API_KEY` | The built-in `claude` provider | Provider reports unavailable; LLM stage `skipped:` |
| `OPENAI_API_KEY` | The `codex` provider | That provider is unavailable |
| `DEEPSEEK_API_KEY` | The `deepseek` provider | That provider is unavailable |
| `NO_COLOR` | Any value disables ANSI colour in `--live` | Colour on when stderr is a TTY |
| `COSMO_NO_TUI` | Any value forces `cosmo interactive` to the line-based session | Full-screen on a terminal |
| `GH_TOKEN` | Consumed by the `gh` CLI in CI for PR reads/comments | `gh`'s own auth is used |

Each built-in provider reads a fixed variable — the pairing is in
`providers/registry.py` (`REQUIREMENTS`), which is also what the `skipped:` line
quotes back at you when a provider is unavailable. `llama` reads no key: a local
endpoint is assumed reachable.

---

## Full key reference

Defaults below are the **built-in operator defaults**, used when no operator
config is supplied.

### `threshold` — *preference*

```yaml
threshold: medium        # info | low | medium | high | critical
```

The severity floor. Findings below it are dropped from the report (waived ones
are retained internally so `cosmo baseline` can list them). Overridden per-run by
`--threshold`.

### `ignore_paths` — *preference*

```yaml
ignore_paths:
  - "vendor/**"
  - "**/*.generated.*"
```

Glob patterns excluded from review. Default: empty.

### `static` — *safety*

```yaml
static:
  tools: [semgrep, gitleaks, bandit, trivy, opengrep, trufflehog, find-sec-bugs]
  concurrency: 4              # scanner subprocesses in flight at once
  trufflehog_verify: false    # OPERATOR-ONLY — see below
```

Default: every scanner cosmo can drive. A tool that is not installed reports
itself under `skipped:` rather than quietly narrowing the scan, so the default
costs nothing on a machine that has none of them.

This is a **safety** section, and `tools` clamps in the opposite direction to
every other one here: for a scanner list, tightening means scanning *more*. A
repo may **add** a tool, never remove one the operator enabled — otherwise a
scanned repo could write `static: {tools: [semgrep]}` and switch off the secret
scanner that would have found its own credentials.

`trufflehog_verify` has no tightening rule at all, which makes it operator-only:
a repo value is ignored and warned. Verification sends candidate credentials to
their providers to see whether they still work, which is egress the broker never
sees.

The active tool set is part of the incremental cache key, so enabling a scanner
re-runs the stage instead of replaying the narrower set's cached results.

### `providers` — *preference*

```yaml
providers:
  claude:   { default: true }     # exactly one provider may carry default: true
  on_failure: fallback            # fallback (to Claude) | hard_fail
```

Built-in names: `claude`, `claude-cli`, `codex`, `deepseek`, `llama`. Only two
keys here are read — `default:` on a provider, and `on_failure:`. Endpoints,
models and key variables are fixed per provider in `providers/registry.py`; there
is no config surface for them yet.

Default: `{claude: {default: true}}`. Resolution order is
session → CLI (`--model`) → repo → operator → the Claude default. An unavailable
provider **falls back rather than skipping review**, unless `on_failure:
hard_fail`.

Providers are also subject to the data-governance gate below.

### `providers_policy` — *safety*

```yaml
providers_policy:
  data_sensitivity: normal          # normal | sensitive   (repo may only RAISE)
  sensitive_allowed_vendors: []     # operator-only
  allowed_provider_hosts: []        # operator-only; for self-hosted endpoints
```

At `sensitive`, only **local** providers and operator-listed vendors are
eligible — a sensitive repository never has its source fanned out to a third
party. `allowed_provider_hosts` extends the egress broker's allow-list beyond the
built-in vendor hosts plus loopback.

### `skills` — *preference (with one reserved key)*

```yaml
skills:
  org_dir: /etc/cosmo/skills     # OPERATOR-ONLY — see the trust note above
```

Repo skills live in `.cosmo/skills/*.md` and need no config at all. See
[usage.md § Review skills](usage.md#review-skills) for the file format and the
trust split.

### `llm_audit` — *safety*

```yaml
llm_audit:
  max_files: 50        # files one whole-project audit sends to the model
  concurrency: 4       # reviews in flight at once
```

A hard cost guard for `--audit`. The file list is truncated to `max_files`
*before* any review is dispatched, so `concurrency` changes how fast the capped
set is worked through — never how many calls are made. Files past the budget are
reported as un-audited, never silently dropped.

`concurrency` is shared with `cosmo history`; it is the same resource.

### `history` — *safety*

```yaml
history:
  max_commits: 200     # commits one `cosmo history` sweep reviews
```

One model call per commit makes this the sharpest cost ceiling cosmo has.
`--max-commits` may lower it, never raise it.

### `incremental` — *preference*

```yaml
incremental:
  enabled: true
```

Caches expensive stage results under `<target>/.cosmo/cache.json` so only what
changed re-runs. Disable per-run with `--no-cache`. When a cached static result
is reused, the skipped-stage records from that run are replayed too, so a warm
run reports the same coverage as a cold one.

### `sandbox` — *safety*

```yaml
sandbox:
  enabled: true
  network: none            # none | internal | bridge | host  (repo may only tighten)
  timeout_seconds: 300
  confirmation: true
```

Hardened rootless container used to confirm suspected findings. `network: none`
is the default and a repo cannot open it.

### `fuzzing` — *safety*

```yaml
fuzzing:
  enabled: false
  max_duration: "8h"
  confirm_above: "4h"
```

Off by default. `cosmo fuzz` refuses to default a duration silently, and a run
longer than `confirm_above` requires `--confirm`.

### `external_targets` — *safety, operator-only*

```yaml
external_targets:
  enabled: false
  require_scope_declaration: true
  rate_limit_source: scope_declared
  max_rate_limit_per_sec: <operator ceiling>
  mandatory_excludes: []
```

Authorized live-target mode. A repo block here is ignored entirely.

### `disclosure` — *safety, operator-only*

```yaml
disclosure:
  contact: security.md
  embargo_days: 90
```

Coordinated disclosure. Delivery endpoints must be operator-configured — a
`SECURITY.md` pointing at an arbitrary host is refused even with human approval,
because it is untrusted repo input.

### `context_ingestion` — *preference*

```yaml
context_ingestion:
  issues: true
```

Reads issues/comments via `gh` for GitHub targets to prioritise review.
Prioritisation only ever *raises* attention on a file — it never creates or
suppresses a finding. Default: enabled; a local target skips it automatically.

### `extensions` — *safety, operator-only*

```yaml
extensions:
  paths: ["/opt/cosmo-ext"]
  enabled: ["my-ext"]
  reference_only: ["untrusted-ext"]
```

Extensions run in-process, so *enabling* one is a full-trust act only the
operator can make. Discovery is not activation: only names in `enabled` are
imported and run. See [extensions.md](extensions.md).

### `output` and `triggers`

`output` is a preference section reserved for renderer settings. `triggers` is
safety-tier and operator-only, covering hook/Action defaults. Neither has
built-in defaults beyond what the code applies per trigger.

---

## Flags that change behaviour

Full reference in **[usage.md](usage.md)**. The ones that alter config rather
than just output:

| Flag | Effect | Tier-bound? |
|---|---|---|
| `--threshold` | Sets the session severity floor | No — a preference |
| `--model` | Enters at the CLI tier of provider resolution | Still passes the governance gate |
| `--operator-config FILE` | Supplies the ceiling | — |
| `--no-cache` | Sets `incremental.enabled: false` | No |
| `--max-commits N` | Lowers `history.max_commits` | **Yes** — may only lower |
| `--no-color` | Disables ANSI in `--live` | No |

---

## Worked example

`/etc/cosmo/operator.yaml` — the trusted ceiling:

```yaml
threshold: medium
llm_audit:
  max_files: 200
  concurrency: 8
history:
  max_commits: 500
providers_policy:
  data_sensitivity: normal
  sensitive_allowed_vendors: []
skills:
  org_dir: /etc/cosmo/skills
```

`cosmo.yaml` in a scanned repo:

```yaml
threshold: high            # preference — accepted
llm_audit:
  max_files: 25            # tightening — accepted
history:
  max_commits: 9999        # loosening — CLAMPED to 500, warned
skills:
  org_dir: .cosmo/mine     # reserved key — IGNORED, warned
sandbox:
  network: host            # loosening — CLAMPED to none, warned
```

Effective result: `threshold: high`, `max_files: 25`, `max_commits: 500`,
`org_dir: /etc/cosmo/skills`, `network: none` — plus three warnings on the
report.
