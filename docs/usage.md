# Usage reference

Every command, subcommand, and flag cosmo exposes.

Prerequisites: **[installation.md](installation.md)** → **[getting-started.md](getting-started.md)**.
Config keys live in **[configuration.md](configuration.md)**; workflows in
**[examples.md](examples.md)**; errors in
**[faq-troubleshooting.md](faq-troubleshooting.md)**.

---

## Command overview

| Command | Purpose |
|---|---|
| [`review`](#cosmo-review) | Review a local path or GitHub PR — the core command |
| [`history`](#cosmo-history) | Sweep a repository's commit history for vulnerabilities |
| [`waive`](#cosmo-waive) | Waive a finding by fingerprint into the baseline |
| [`baseline`](#cosmo-baseline) | List or clear waived findings |
| [`hook`](#cosmo-hook) | Run the review over the staged diff (git-hook trigger) |
| [`install-hook`](#cosmo-install-hook) | Install a git pre-commit/pre-push hook |
| [`action`](#cosmo-action) | CI trigger: review a PR, post a gated comment, emit SARIF |
| [`interactive`](#cosmo-interactive) | Live session with slash-commands |
| [`agent`](#cosmo-agent) | Live session driven in natural language |
| [`fuzz`](#cosmo-fuzz) | Manual-only zero-day fuzzing campaign |
| [`trends`](#cosmo-trends) | Lifecycle, noisiest rules, OWASP rollup, disclosure queue |
| [`extensions`](#cosmo-extensions) | List discovered custom extensions |
| [`plugin`](#cosmo-plugin) | Manage the Claude Code plugin surface |

---

## Exit codes

| Code | Meaning | Applies to |
|---|---|---|
| `0` | Ran successfully; nothing actionable survived the threshold | all |
| `1` | Ran successfully; at least one non-waived finding survived | `review`, `history`, `hook --blocking`, `action` |
| `2` | Could not run — bad target, no reviewer available, disabled capability, missing required flag | `review`, `history`, `fuzz`, `plugin check` |

`plugin check` returns non-zero on drift.

---

## `cosmo review`

The core command. Runs the pipeline once and prints the result.

```bash
cosmo review <target> [options]
```

### Target forms

| Form | Example | Resolution |
|---|---|---|
| Local git repo | `cosmo review .` | `git diff HEAD`, falling back to `git diff` |
| Local non-git path | `cosmo review ./app` | Whole-tree — every file treated as newly added |
| Single file | `cosmo review ./app.py` | Whole-file |
| GitHub PR | `cosmo review owner/repo#123` | `gh pr diff` — no clone needed |
| GitHub PR URL | `cosmo review https://github.com/o/r/pull/1` | Same |

To review the **staged** diff, use [`cosmo hook`](#cosmo-hook) rather than
`review`. The resolver understands a `staged:` target prefix, but `cosmo review`
rejects it — the command validates that the target exists on disk before the
resolver is reached, so the prefix is only usable internally by the git-hook
trigger.

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `<target>` | string | — | **Required.** One of the forms above |
| `--format` | `cli` \| `sarif` \| `pr` | `cli` | Output renderer |
| `--model` | `claude` \| `claude-cli` \| `codex` \| `deepseek` \| `llama` | config | Review provider |
| `--audit` | flag | `false` | Whole-project AI audit: review **every file**, not just the diff |
| `--verbose`, `-v` | flag | `false` | Stream per-stage/per-file progress to stderr |
| `--live` | flag | `false` | Live workflow UI on stderr |
| `--threshold` | `info` \| `low` \| `medium` \| `high` \| `critical` | config | Severity floor for this run |
| `--operator-config` | path | `$COSMO_OPERATOR_CONFIG` | The trusted ceiling |
| `--no-cache` | flag | `false` | Force a full re-scan |
| `--no-color` | flag | `false` | Disable ANSI colour |
| `--record` | flag | `false` | Record this scan in the trend store |

### Examples

```bash
cosmo review .                                  # working-tree changes
cosmo review owner/repo#123                     # a GitHub PR, online
cosmo review ./some-folder                      # whole local folder
cosmo review . --model claude-cli               # add the AI review
cosmo review . --threshold high                 # only high+ this run
cosmo review . --format sarif > cosmo.sarif     # SARIF for a Security tab
cosmo review . --format pr                      # preview the GATED comment
cosmo review . --no-cache                       # ignore the incremental cache
cosmo review . --record                         # also store for trend tracking
cosmo review . --live                           # watch it run
cosmo review . --verbose                        # plain progress lines instead
cosmo review ./app --audit --model claude-cli   # AI-audit every file
cosmo review . --audit --live                   # watch the audit fan out
cosmo review . --operator-config /etc/cosmo/op.yaml
```

Combining `--live` with `--verbose` is accepted, but `--live` wins — the plain
progress stream would corrupt the UI's repaints, so it is suppressed.

### Output — `--format cli`

```
cosmo — ./shop
============================================================
 CRITICAL  SQL injection in order lookup
          shop/orders.py:88  ·  model:claude-cli  ·  CWE-89  ·  conf=90%
          ↳ Attacker controls `user_id` via query string.
          fix: Use a parameterized query.

   HIGH    Secret leaked: aws-access-key
          shop/config.py:12  ·  static  ·  CWE-798  ·  conf=90%

Summary: 1 critical, 1 high
  skipped: static:semgrep (not installed)
  note: skills matched: 1 (0 repo/untrusted)
```

### Output — `--format sarif`

SARIF 2.1.0 for a CI Security tab. Findings become `results`, CWE categories
become `rules`:

```json
{
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "cosmo",
          "version": "0.1.0",
          "rules": [{ "id": "CWE-89", "name": "CWE-89" }]
        }
      },
      "results": [
        {
          "ruleId": "CWE-89",
          "level": "error",
          "message": { "text": "SQL injection in order lookup" },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": { "uri": "shop/orders.py" },
                "region": { "startLine": 88 }
              }
            }
          ]
        }
      ]
    }
  ]
}
```

### Output — `--format pr` (the fail-closed gate)

Shows exactly what would be posted publicly. Confirmed or security-sensitive
findings and their PoCs are **withheld by default**; the full detail stays in the
CLI/SARIF output for the operator:

```
## cosmo security review

### CRITICAL — SQL injection in order lookup
`shop/orders.py:88` · model:claude-cli · CWE-89

Attacker controls `user_id` via query string.

**Fix:** Use a parameterized query.

---
> 1 additional finding(s) were withheld from this public comment by the
> disclosure gate and routed to private coordinated disclosure. No technical
> detail, PoC, or severity is shown here by design (§12).
```

The gate fails **closed**: a finding whose sensitivity is unknown is withheld,
not published.

### Whole-project audit (`--audit`)

By default the LLM review sends the target as one prompt — good for a diff or a
small target, but a whole large codebase overflows the context window. `--audit`
reviews the project **file by file**, several at a time.

```bash
cosmo review ./app --audit --model claude-cli
```

A **hard call budget** protects you from firing thousands of calls:
`llm_audit.max_files` (default **50**). Files past it are reported as un-audited,
never silently skipped. Concurrency is `llm_audit.concurrency` (default **4**) —
it changes the rate, never the call count, because the file list is truncated
before any review is dispatched.

Each file is reviewed independently, so results do not depend on which review
finishes first: findings always come back in file order.

> **Do not point `--audit` at a large tree with an LLM and no budget.** Raise
> `llm_audit.max_files` deliberately, in the operator config.

---

## `cosmo history`

Sweeps a repository's **past**, commit by commit — for a flaw introduced long ago
and never fixed, or one quietly patched without an advisory.

```bash
cosmo history <target> [options]
```

### Flags

| Flag | Type | Default | Description |
|---|---|---|---|
| `<target>` | string | — | **Required.** Local git repo path, or `owner/repo` to read from GitHub with no clone |
| `--since` | string | — | Only commits after this date |
| `--until` | string | — | Only commits before this date |
| `--author` | string | — | Only commits by this author (`git --author` pattern) |
| `--range` | `REV..REV` | — | A git revision range |
| `--path` | path | — | Limit to commits touching PATH — **repeatable** |
| `--max-commits` | int | config | Commits to review; may only *lower* `history.max_commits` |
| `--include-merges` | flag | `false` | Also review merge commits |
| `--live-only` | flag | `false` | Only report findings whose code is still in HEAD |
| `--model` | choice | config | Review provider |
| `--threshold` | choice | config | Severity floor |
| `--format` | `cli` \| `sarif` | `cli` | Output renderer |
| `--live` | flag | `false` | Live UI on stderr |
| `--no-color` | flag | `false` | Disable ANSI colour |
| `--operator-config` | path | env | The trusted ceiling |

### Examples

```bash
cosmo history . --since '6 months ago' --model claude-cli
cosmo history . --range v1.2.0..HEAD --live
cosmo history . --author alice --path src/auth --max-commits 50
cosmo history . --path src/auth --path src/session      # repeatable
cosmo history owner/repo --since 2024-01-01 --live-only # no clone
cosmo history . --format sarif > history.sarif
```

### Local vs remote

A local path is swept with `git`. An `owner/repo` reference is read straight off
the GitHub API through `gh` — the same access pattern the PR reviewer uses.

**A path that exists on disk always wins**, so a directory that happens to be
named `owner/repo` is never silently swapped for a repository on the internet.

The GitHub API takes **ISO dates** for `--since`/`--until`, not git's relative
forms like `'6 months ago'`.

### Reachability — the important part

Every finding names the commit that introduced it and whether the code is still
in HEAD:

```
history-4a1c9de-1 | src/auth/token.py:88
  introduced in 4a1c9de by Alice Chen on 2024-03-11 — add order lookup endpoint
  still in HEAD: present
```

Status is three-valued:

| Status | Meaning |
|---|---|
| `present` | The flagged line is still there — actionable |
| `absent` | The line is gone. **May be a fix, may be a refactor** |
| `unknown` | Could not be determined — never read as safe |

**`absent` never auto-waives a finding.** Code being gone is not proof it was
ever fixed. Use `--live-only` to filter to what is still reachable.

Reachability is per *commit*, not per file — the same file can be `absent` for
the line a fix removed and `present` for the line that replaced it.

### Coverage note

A sweep reviews commit diffs, so the tree-level static tools never run. That is
reported under `skipped:` rather than letting a clean sweep imply a clean tree.

Merge commits are skipped by default; their diffs restate work already reviewed
on the branch.

---

## `cosmo waive`

Silence a known or false-positive finding by fingerprint.

```bash
cosmo waive <target> <fingerprint> [--reason TEXT]
```

| Flag | Type | Default |
|---|---|---|
| `<target>` | string | **Required** |
| `<fingerprint>` | string | **Required** |
| `--reason` | string | `""` |

```bash
cosmo waive . a1b2c3d4e5f60789 --reason "false positive — input is validated upstream"
```

Fingerprints are **content/AST-based, not line-based**, so a waiver survives the
file moving or lines shifting around it. They are printed with each finding.

Waived findings are stored in `<target>/.cosmo/baseline.json`.

---

## `cosmo baseline`

```bash
cosmo baseline <target> [--unwaive FINGERPRINT]
```

| Flag | Type | Default |
|---|---|---|
| `<target>` | string | **Required** |
| `--unwaive` | fingerprint | — |

```bash
cosmo baseline .                              # list waived findings
cosmo baseline . --unwaive a1b2c3d4e5f60789   # un-waive one
```

---

## `cosmo hook`

Runs the review over the **staged** diff (`git diff --cached`). Defaults tuned
for speed: `critical` threshold, short output, static + LLM only, leaning on the
incremental cache.

```bash
cosmo hook [--path DIR] [--blocking] [--operator-config FILE]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--path` | dir | `.` | Repo path |
| `--blocking` | flag | `false` | Abort the commit on an actionable finding |
| `--operator-config` | path | env | The ceiling |

```bash
cosmo hook              # print a summary, never fail
cosmo hook --blocking   # abort the commit on a critical finding
```

A non-blocking hook **never fails a commit**.

---

## `cosmo install-hook`

```bash
cosmo install-hook [--path DIR] [--type TYPE] [--blocking]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `--path` | dir | `.` | Repo path |
| `--type` | `pre-commit` \| `pre-push` | `pre-commit` | Which hook to write |
| `--blocking` | flag | `false` | Make the installed hook blocking |

```bash
cosmo install-hook                      # non-blocking pre-commit
cosmo install-hook --blocking           # abort commits on critical findings
cosmo install-hook --type pre-push
```

Writes `.git/hooks/pre-commit` (or `pre-push`), which invokes `cosmo hook`.

---

## `cosmo action`

The CI trigger. `medium+` threshold, SARIF for the Security tab, a PR comment,
configurable blocking.

```bash
cosmo action <target> [--post] [--sarif FILE] [--no-block] [--operator-config FILE]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `<target>` | `owner/repo#123` | — | **Required** |
| `--post` | flag | `false` | Post the gated PR comment |
| `--sarif` | path | — | Write SARIF to FILE |
| `--no-block` | flag | `false` | Do not fail the job on findings |

```bash
cosmo action "owner/repo#123" --post --sarif cosmo.sarif
```

`--post` renders through the **fail-closed public-comment gate**, so a confirmed
or sensitive finding and its PoC are withheld and only a generic acknowledgment
is posted. The finding still lands in SARIF for the operator.

Needs `GH_TOKEN` (or `gh` auth) and `pull-requests: write` permission. A
copy-paste workflow is at
[`examples/github/cosmo-review.yml`](../examples/github/cosmo-review.yml).

---

## `cosmo interactive`

A live session on the same engine as batch mode, answering follow-ups from
in-session state without re-scanning.

```bash
cosmo interactive <target> [--no-scan] [--operator-config FILE]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `<target>` | string | — | **Required.** Local path or GitHub PR |
| `--no-scan` | flag | `false` | Open without an initial scan |
| `--operator-config` | path | env | The ceiling |

### Slash commands

| Command | Does |
|---|---|
| `/help` | Full command list |
| `/status` | Session snapshot: findings, running campaigns, threshold, model |
| `/threshold [level]` | View or set the session severity floor |
| `/model [provider]` | Switch model — passes the data-governance gate |
| `/duration [value \| extend <value>]` | View/set the fuzz duration cap |
| `/skills [add <path>]` | List matched skills, or load one ad hoc |
| `/audit [wait]` | AI-audit every file in the background |
| `/confirm <finding-id>` | Trigger sandbox confirmation for one finding |
| `/waive <finding-id> [reason]` | Waive a finding into the baseline |
| `/baseline [unwaive <fp>]` | List or clear waived findings |
| `/scope [program=… includes=… rate=N]` | Declare an authorized external target |
| `/disclose <finding-id>` | Draft + **queue** a disclosure — sends nothing |
| `/report [cli\|sarif\|pr]` | Export findings |
| `/extensions` | List activated extensions and their `/x-*` commands |

**The command layer cannot bypass the guardrails.** `/duration` is capped by
`fuzzing.max_duration`; `/model` resolves through the data-governance gate;
`/report pr` renders through the fail-closed gate; `/threshold` only moves the
session floor and never writes a safety key.

`/audit` runs on a background thread — several files at once — so the prompt
stays responsive. `/status` shows progress (`audit: running (3/12 files)`).

---

## `cosmo agent`

The same session, driven in natural language rather than slash-commands.

```bash
cosmo agent <target> [--no-scan] [--operator-config FILE]
```

Flags are identical to `interactive`.

---

## `cosmo fuzz`

A separate, **manual-only** capability for surfacing genuinely unknown
vulnerabilities against cosmo's *own sandboxed build*.

```bash
cosmo fuzz <target> --duration <time> [--language LANG] [--confirm] [--operator-config FILE]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `<target>` | path | — | **Required.** Local repo — sandbox build only |
| `--language` | string | `python` | Selects the integrated engine |
| `--duration` | e.g. `30m`, `2h` | **none** | Hard time cap — never defaults silently |
| `--confirm` | flag | `false` | Acknowledge a duration above `fuzzing.confirm_above` |

```bash
cosmo fuzz . --duration 30m --operator-config op.yaml
cosmo fuzz . --language c --duration 6h --confirm
```

Constraints that are enforced, not advisory:

- **`fuzzing.enabled` is off by default** — a repo cannot widen it
- **No code path accepts an external URL** as a fuzz target
- **Novelty is never asserted** — an unmatched crash is *unverified-novel*
- **Coverage is never assumed** — surfaced as `coverage_fraction`
- **Duration never defaults** — an unset `--duration` is an error, not a guess
- **Always tears down**, even when the engine crashes mid-run

---

## `cosmo trends`

```bash
cosmo trends <target> [--disclosure]
```

| Flag | Type | Default | Description |
|---|---|---|---|
| `<target>` | path | — | **Required.** Previously scanned with `--record` |
| `--disclosure` | flag | `false` | Show the coordinated-disclosure queue instead |

```bash
cosmo trends .                # lifecycle, noisiest rules, OWASP rollup
cosmo trends . --disclosure   # the disclosure queue
```

Reports a finding's lifecycle — introduced, reopened, fixed — plus the
**noisiest rules** (categories with a high waived fraction) and an **OWASP Top 10
2021** rollup by CWE. Unmapped CWEs fall through to A04 rather than vanishing.

This layer only ever *reports*. It never changes a finding's severity or whether
it surfaces.

---

## `cosmo extensions`

```bash
cosmo extensions [--path DIR] [--operator-config FILE]
```

| Flag | Type | Default |
|---|---|---|
| `--path` | dir | `.` |
| `--operator-config` | path | env |

Lists discovered extensions. **Discovery is not activation** — only names in the
operator's `extensions.enabled` are imported and run. See
[EXTENSIONS.md](EXTENSIONS.md).

---

## `cosmo plugin`

```bash
cosmo plugin {sync|check} [--root DIR]
```

| Argument | Type | Default | Description |
|---|---|---|---|
| `<action>` | `sync` \| `check` | — | **Required** |
| `--root` | dir | `.` | Plugin repo root |

```bash
cosmo plugin sync    # regenerate manifest + commands from the code
cosmo plugin check   # report drift; non-zero exit if any
```

The plugin surface is **derived from the guarded interactive registry**, not
hand-written. If you add or rename a slash-command, run `sync` and commit the
result — CI runs `check` and fails on drift.

---

## Review skills

A **skill** is a markdown file adding targeted review guidance for the LLM stage.
Only skills matching the changed files are injected.

Drop one in `.cosmo/skills/` in the repo being reviewed:

```markdown
---
name: python-taint
description: Flag request data reaching a shell or SQL sink
applies_to:
  - "**/*.py"
---
Trace values from request parameters, argv, and environment variables into
`os.system`, `subprocess.*` with `shell=True`, and string-built SQL. Report the
source and the sink by name. Parameterized queries and `shell=False` with a list
argument are safe — do not flag them.
```

`applies_to` is a list of globs matched against changed file paths. A worked
example ships in [`examples/skills/`](../examples/skills/).

### The trust split

| Origin | Trust | Why |
|---|---|---|
| **Org** — `skills.org_dir` | authoritative | You own it; not in the repo under review |
| **Repo** — `.cosmo/skills/*.md` | **untrusted** | Ships with the code you are auditing |

A repo skill is still loaded and still useful, but it is injected in a labelled
untrusted section carrying a directive that it **cannot suppress findings,
downgrade severity, or override the reviewer** — and that an instruction
attempting to is itself a reason to scrutinise the surrounding code harder.

`skills.org_dir` is **operator-only and enforced** — see
[configuration.md](configuration.md#one-reserved-key-inside-a-preference-section).

Inspect what was injected with `/skills` in a session, or watch the `context`
stage under `--live`.

---

## Automation

### Git hook

```bash
cosmo install-hook --blocking
```

### GitHub Actions

```yaml
name: cosmo security review
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  cosmo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: actions/setup-python@v5
        with: { python-version: "3.12" }
      - run: pip install -e .
      - run: >
          cosmo action "${{ github.repository }}#${{ github.event.number }}"
          --post --sarif cosmo.sarif
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GH_TOKEN: ${{ github.token }}
      - if: always()
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: cosmo.sarif }
```

### Any CI, via exit code

```bash
cosmo review . --threshold high || exit 1
```

---

## Edge cases worth knowing

- **A non-git directory** is reviewed in whole-tree mode — every file treated as
  newly added. Cloning and deleting `.git` is the supported way to force this.
- **An empty diff** is not an error; the report is simply empty.
- **A read-only target** cannot be cached. You get a `note:`, not a failure.
- **A broken extension detector** is isolated and reported under `skipped:`,
  never crashing the review.
- **One failing file in an `--audit`** is recorded under `skipped:`; the rest of
  the audit continues.
- **`--format sarif` with `--live`** is safe — the UI is on stderr, stdout stays
  machine-readable.
- **`cosmo review` on a path that does not exist** exits `2` with a message
  naming the path, before any scan begins.
