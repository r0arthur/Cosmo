# Running cosmo

A practical guide to every way you can run cosmo — from a one-shot review to a
live session, a git hook, CI, fuzzing, and the Claude Code plugin. For *what each
piece does and why it's safe*, see [`architecture.html`](architecture.html); for
config, [`../cosmo.example.yaml`](../cosmo.example.yaml).

---

## Quickstart (60 seconds)

```bash
# 1. install into a virtualenv (with semgrep for the static stage)
python -m venv ~/cosmo-venv
~/cosmo-venv/bin/pip install -e /path/to/cosmo semgrep

# 2. put cosmo on your PATH
ln -s ~/cosmo-venv/bin/cosmo ~/.local/bin/cosmo     # ~/.local/bin is usually on PATH

# 3. review something
cosmo review .                          # your local uncommitted changes
cosmo review owner/repo#123             # a GitHub PR, online (needs the gh CLI)
```

That's it. No API key required for the static scan. To turn on the AI review, see
**[Turn on the AI review](#turn-on-the-ai-review)** below.

---

## 1. Install

Use a virtualenv so cosmo and `semgrep` live together and stay on the same PATH:

```bash
python -m venv ~/cosmo-venv
~/cosmo-venv/bin/pip install -e /path/to/cosmo semgrep   # cosmo + the static scanner
ln -s ~/cosmo-venv/bin/cosmo ~/.local/bin/cosmo          # so plain `cosmo` works
```

Everything else is **optional** — cosmo degrades gracefully, never fails, if a
piece is missing (it just lists that stage under `skipped:`):

| Add this | To enable | If missing |
|---|---|---|
| `semgrep` (installed above) | the static pre-filter | that stage is `skipped:` |
| the AI review (below) | LLM findings | LLM stage is `skipped:` |
| `gh` CLI, authenticated | reviewing a GitHub PR online | local review still works |
| `gitleaks` on PATH | secret detection | that stage is `skipped:` |

> **PATH matters.** cosmo finds `semgrep`, `claude`, and `gh` on your `PATH`. If
> you run cosmo from a minimal shell that drops `~/.local/bin` or the venv's
> `bin`, those stages silently show as `skipped:`. Keep both on PATH:
> `export PATH="$HOME/.local/bin:$HOME/cosmo-venv/bin:$PATH"`.

Verify: `cosmo --help`.

---

## Turn on the AI review

The static scan runs with no account. To add the LLM review, pick **one**:

**A. Use your Claude Code subscription — no API key** (recommended). If the
`claude` CLI (Claude Code) is installed and logged in:

```bash
cosmo review . --model claude-cli
```

cosmo shells out to `claude` on your subscription — no separate API billing.

**B. Use an Anthropic API key.** Get one from console.anthropic.com (billed
separately from any Claude subscription), then:

```bash
~/cosmo-venv/bin/pip install anthropic
export ANTHROPIC_API_KEY=sk-ant-...
cosmo review .                          # the built-in `claude` provider is the default
```

Either way, a `sensitive`-marked repo still won't send its source to a third
party unless the operator explicitly allows it (the §8 data-governance gate).

---

## Online vs. local — what cosmo can review

This trips people up, so it's worth being explicit:

| You want to review | Needs a clone? | Command |
|---|---|---|
| A GitHub **pull request** | ❌ **No — runs online** via `gh` | `cosmo review owner/repo#123` |
| Your **local changes** | already local | `cosmo review .` |
| A **whole repo/app** | ✅ **Yes — files must be local** | `git clone … && rm -rf .git`, then `cosmo review ./dir` |

There is **no** "scan a whole remote repo from its URL" mode — a bare repo URL
like `github.com/org/app` is not a PR, so cosmo can't fetch it online. Clone it,
delete `.git` (that switches cosmo into whole-tree mode: every file is treated as
new), then point cosmo at the folder.

> **Don't add `--model claude-cli` (or any LLM) to a *large* whole-tree scan.**
> The LLM review sends the whole target as one prompt; an entire large codebase
> overflows it. Use the LLM on a **PR, your local diff, or a single file** — and
> plain `cosmo review ./big-repo` (static only) for a whole app.

---

## 2. Review something (the core command)

`cosmo review` runs the pipeline once and prints the result.

```bash
cosmo review .                       # your local working-tree changes
cosmo review owner/repo#123          # a GitHub PR, online (needs gh)
cosmo review ./some-folder           # a whole local folder (whole-tree if non-git)
```

Useful flags:

```bash
cosmo review . --model claude-cli    # add the AI review on your subscription
cosmo review ./app --audit --model claude-cli   # AI-audit EVERY file (whole project)
cosmo review . --audit --verbose     # stream per-file progress as the audit runs
cosmo review . --threshold high      # only surface high+ (overrides config)
cosmo review . --format sarif        # SARIF for a CI Security tab
cosmo review . --format pr           # preview the GATED public comment
cosmo review . --no-cache            # force a full re-scan (ignore the cache)
cosmo review . --record              # also store findings for trend tracking
cosmo review . --operator-config op.yaml   # apply the operator/org ceiling
```

**Exit code:** `1` if any non-waived finding survived the threshold, else `0` —
so `cosmo review` drops straight into a CI gate.

`--format pr` is worth knowing: it shows exactly what would be posted publicly.
Confirmed/sensitive findings and their PoCs are **withheld by default** (RISK-05);
the full detail stays in the CLI/SARIF output for the operator.

### Whole-project AI audit (`--audit`)

By default the LLM review sends the target as one prompt (good for a diff or a
small target). `--audit` instead reviews the project **file by file**, so a whole
codebase gets AI coverage — not just the changed lines:

```bash
cosmo review ./app --audit --model claude-cli
```

A **hard call budget** protects you from firing thousands of LLM calls by
accident: `llm_audit.max_files` (default **50**) caps how many files one audit
sends to the model. It's an operator-tier setting — a scanned repo may only
*lower* it. Files past the budget are **reported as un-audited**, never silently
skipped, so you always know your coverage. Raise it in the operator config to
cover a bigger project:

```yaml
# operator-config.yaml
llm_audit:
  max_files: 200
```

A whole-project audit fires many back-to-back `claude` sessions, and a single one
can transiently fail (exit 1, empty error). cosmo **retries with exponential
backoff** per file, and a file that still fails after its retries is isolated —
recorded under `skipped:`, never aborting the rest of the run. Add `--verbose`
(or `-v`) to watch each file being reviewed live instead of waiting for the end.

---

## 3. Waivers (silence a known/false finding)

Each finding prints a stable content-based fingerprint. Waive by fingerprint:

```bash
cosmo review .                                   # copy a fingerprint from output
cosmo waive . <fingerprint> --reason "test fixture, not reachable"
cosmo baseline .                                 # list what's waived
cosmo baseline . --unwaive <fingerprint>         # bring one back
```

The fingerprint is derived from the finding's content/AST, not its line number
(RISK-07), so a waiver survives the file shifting around but does **not** suppress
a genuinely new instance of the same bug.

---

## 4. Git hook (review on every commit)

```bash
cosmo install-hook              # non-blocking pre-commit hook
cosmo install-hook --blocking   # abort the commit on an actionable finding
cosmo install-hook --type pre-push
cosmo hook                      # run it manually over the staged diff
cosmo hook --blocking           # ...and fail on findings
```

The hook reviews the **staged** diff (`git diff --cached`) at a `critical`
threshold, leaning on the cache to stay fast. A non-blocking hook never fails a
commit — it just prints a summary.

---

## 5. GitHub Action (review a PR in CI)

```bash
cosmo action "owner/repo#123" --post --sarif cosmo.sarif
cosmo action "owner/repo#123" --no-block        # report without failing the job
```

Reviews the PR diff at `medium+`, writes SARIF for the Security tab, and — with
`--post` — posts the **gated** PR comment (sensitive detail withheld). A
ready-to-copy workflow is in [`../examples/github/`](../examples/github/).

---

## 6. Trends & compliance rollup

After recording scans with `--record`:

```bash
cosmo review . --record         # record this scan
cosmo trends .                  # lifecycle, noisiest rules, OWASP Top-10 rollup
cosmo trends . --disclosure     # the coordinated-disclosure queue
```

---

## 7. Interactive session (slash-commands)

Same engine as batch mode, but live — answers follow-ups from in-session state
without re-scanning.

```bash
cosmo interactive .             # scans on start; /help lists commands
cosmo interactive . --no-scan   # open without an initial scan
```

In-session commands (each delegates to the *same* guarded code path as batch mode
— a chat command can never widen a guardrail):

```
/status            findings so far, current settings
/threshold high    move the session severity floor (preference only)
/model claude-cli  switch reviewer (claude-cli = your subscription) — §8 gated
/audit             AI-audit every file in the background (whole project)
/audit wait        ...and block until it finishes instead of returning at once
/skills            show injected skills
/waive <fp>        waive a finding      /baseline   list waived
/scope ...         declare an authorized external-target scope (§9)
/disclose <id>     draft + QUEUE a disclosure (sends nothing; §13)
/confirm           confirm a finding in the sandbox
/duration 30m      set a fuzzing time cap (clamped by config)
/report [pr]       render output (pr = through the fail-closed gate)
/help              full list
```

`/audit` runs on a **background thread**, so the prompt stays responsive while a
slow multi-file audit works. Findings merge into session state as each file
finishes — run `/status` any time to see progress (`audit: running (3/12 files)`)
and the findings landed so far, or `/report` once it's done. Use `/audit wait`
when you'd rather block until it completes. It needs an LLM reviewer, so switch
to one first if the session has none: `/model claude-cli`.

---

## 8. Agent mode (natural language, harness-agnostic)

Like the interactive session, but you type plain English and a **planner** maps
it to guarded commands. It runs out of the box either way:

```bash
cosmo agent .                   # natural-language session
cosmo agent . --operator-config op.yaml
```

- If a live model provider is **available and allowed** by the §8 gate
  (Claude / Codex / DeepSeek / local Llama), that model plans the commands.
- Otherwise cosmo falls back to a **no-model rule-based planner** — no API key
  required.

Either way, the planner can only *propose*; the driver executes each call only if
it's in the guarded command catalog, so the LLM never gains a capability the CLI
doesn't already have.

---

## 9. Zero-day fuzzing (manual-only)

A separate, explicitly manual capability that fuzzes cosmo's **own sandboxed
build** — never an external target.

```bash
cosmo fuzz . --duration 30m --operator-config op.yaml
cosmo fuzz . --language c --duration 2h --confirm    # long run needs --confirm
```

`fuzzing.enabled` is **off by default** and is a safety-tier setting a scanned
repo cannot flip on. `--duration` never defaults silently; a run above
`fuzzing.confirm_above` requires `--confirm`.

---

## 10. Config & trust tiers

`cosmo.yaml` in the scanned repo is **untrusted**. It can override *preference*
keys (threshold, ignore paths, provider choice) but can only **tighten** *safety*
keys (`sandbox.*`, `fuzzing.*`, `external_targets.*`, `providers_policy.*`,
`extensions.*`) — loosening values are clamped and warned at load.

The trusted ceiling is the **operator config**, supplied two ways:

```bash
cosmo review . --operator-config /etc/cosmo/operator.yaml
export COSMO_OPERATOR_CONFIG=/etc/cosmo/operator.yaml
```

See [`../cosmo.example.yaml`](../cosmo.example.yaml) for the full key list.

---

## 11. Custom extensions

Add a detector, skill, and/or `/x-<name>` command without forking. Point the
**operator** config at it and arm it by name (discovery ≠ activation):

```yaml
# operator config only — NOT the scanned repo's cosmo.yaml
extensions:
  paths:   ["/abs/path/to/my-ext"]
  enabled: ["my-ext"]
```

```bash
cosmo extensions --operator-config operator.yaml   # list active / discovered
```

Full authoring guide: [`EXTENSIONS.md`](EXTENSIONS.md).

---

## 12. As a Claude Code plugin

cosmo ships a plugin surface generated from the one guarded command registry.

```bash
cosmo plugin sync    # (re)generate .claude-plugin/plugin.json + commands/*.md
cosmo plugin check   # report drift; non-zero exit if out of date (CI gate)
```

Inside Claude Code, the `/cosmo-review` umbrella command and the `/cosmo-*` family
shell out to the same `cosmo` binary — so the plugin can never grant itself a
capability the CLI doesn't already enforce. It depends on Claude Code; it does not
fork it.

---

## 13. Run the tests

```bash
pip install -e '.[dev]'
PYTHONPATH=src python -m pytest -q          # full hermetic suite
PYTHONPATH=src python -m cosmo plugin check --root .   # plugin-drift gate
```

---

## Quick reference

| Command | Does |
|---|---|
| `cosmo review <target>` | one-shot review (local path or PR) |
| `cosmo review <t> --model claude-cli` | + AI review on your Claude subscription |
| `cosmo waive / baseline` | manage waived findings |
| `cosmo hook` / `install-hook` | git pre-commit/pre-push review |
| `cosmo action <pr>` | CI PR review + gated comment + SARIF |
| `cosmo trends <target>` | lifecycle / OWASP rollup / disclosure queue |
| `cosmo interactive <target>` | live session, slash-commands |
| `cosmo agent <target>` | live session, natural language |
| `cosmo fuzz <target>` | manual-only sandbox fuzzing |
| `cosmo extensions` | list custom extensions |
| `cosmo plugin sync/check` | manage the Claude Code plugin surface |
