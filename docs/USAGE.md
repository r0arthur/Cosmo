# Running cosmo

A practical guide to every way you can run cosmo — from a one-shot review to a
live session, a git hook, CI, fuzzing, and the Claude Code plugin. For *what each
piece does and why it's safe*, see [`architecture.html`](architecture.html); for
config, [`../cosmo.example.yaml`](../cosmo.example.yaml).

---

## Quickstart (60 seconds)

```bash
# clone/download cosmo, then from its directory:
make install          # venv + semgrep + a `cosmo` on your PATH — one command

cosmo review .                          # your local uncommitted changes
cosmo review owner/repo#123             # a GitHub PR, online (needs the gh CLI)
```

`make install` is just a wrapper for [`scripts/install.sh`](../scripts/install.sh),
which you can also run directly (see [Install](#1-install) for options). Prefer a
system package? `make deb` builds a `.deb` — see [Install as a .deb](#install-as-a-deb).

That's it. No API key required for the static scan. To turn on the AI review, see
**[Turn on the AI review](#turn-on-the-ai-review)** below.

---

## 1. Install

Pick whichever fits — all three give you a `cosmo` on your PATH.

**A. One command (recommended).** From cosmo's directory:

```bash
make install           # or: ./scripts/install.sh
```

That creates an isolated venv, installs cosmo + `semgrep` into it, and symlinks
`cosmo` into `~/.local/bin`. Re-run it to upgrade; `make uninstall` removes it.
Knobs: `PREFIX=/opt ./scripts/install.sh`, or `NO_SEMGREP=1` to skip the scanner.

**B. As a `.deb`.** See [Install as a .deb](#install-as-a-deb) below.

**C. By hand** (if you'd rather manage the venv yourself):

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

## Install as a `.deb`

Prefer a system package (installs for all users, uninstalls with `apt`/`dpkg`)?
Build one from the repo — no `fpm` or Debian packaging skills needed:

```bash
make deb                       # or: ./packaging/build-deb.sh
sudo dpkg -i dist/cosmo_*.deb  # installs /usr/bin/cosmo
cosmo --help
```

The package is **self-contained**: it vendors cosmo and its Python deps under
`/opt/cosmo/lib` and installs a `/usr/bin/cosmo` launcher that runs them with the
system `python3` — so the only requirement on the target is `python3 (>= 3.10)`,
no `pip` step. It's `Architecture: all` (pure Python), so one build installs
anywhere. `semgrep` (static stage) and the `claude` CLI (AI review) stay optional
companions you add separately; cosmo degrades gracefully without them.

Remove it with `sudo dpkg -r cosmo`. To share the `.deb`, just hand someone the
file from `dist/` — `sudo dpkg -i cosmo_<version>_all.deb` is all they run.

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
cosmo review . --live                # live UI: objective, stages, what's running now
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

### Watch it run (`--live`)

`--live` replaces the scrolling log with a live view of the pipeline: the
objective, the eleven workflow stages as they go pending → running → done (or
**skipped**), the operation in flight, and a timestamped activity feed of the
real work — the `semgrep` argv, each model call crossing the egress broker, each
file a whole-project audit finishes.

```bash
cosmo review . --live
cosmo review ./app --audit --model claude-cli --live   # watch the audit fan out
```

It ends on a verdict: findings by severity, and a **coverage** panel naming every
stage that did *not* run. That panel is the point — a review that skipped semgrep
is not the same as a clean one, and the UI never lets that difference hide.

Two things it deliberately does not do: it draws on **stderr**, so
`--format sarif|pr` still pipes cleanly and the exit code keeps its CI meaning;
and it adds **no dependency** — the drawing is plain ANSI, so the `.deb` still
needs nothing but `python3`. Redirect stderr, or pass `--no-color`, and it
degrades to one durable line per event.

## Sweep a repo's history (`cosmo history`)

`cosmo review` looks at one diff. `cosmo history` looks at *many* — every commit
in a range becomes its own review unit. That is how you find a flaw introduced
years ago and never fixed, or one quietly patched without an advisory.

```bash
cosmo history . --since '6 months ago' --model claude-cli
cosmo history . --range v1.2.0..HEAD --live
cosmo history . --author alice --path src/auth --max-commits 50
cosmo history owner/repo --since 2024-01-01 --live-only   # no clone needed
```

**No clone required.** A local path is swept with `git`; an `owner/repo`
reference is read straight off the GitHub API through the `gh` CLI — the same
access pattern the PR reviewer already uses. A path that exists on disk always
wins, so a directory that happens to look like `owner/repo` is never silently
swapped for a repository on the internet. (The API takes ISO dates for
`--since`/`--until`, not git's relative forms.)

**Every finding says which commit introduced it** — sha, author, date, subject —
and whether the code is **still in HEAD**:

```
introduced in 4a1c9de by Alice Chen on 2024-03-11 — add order lookup endpoint
still in HEAD: present
```

That last line is the one that matters. A finding in an old commit is only worth
acting on if the code is still there, so each is checked against HEAD and marked
`present`, `absent`, or `unknown`. **`absent` never auto-waives anything** — the
line being gone may be a fix, or may be a rename or a refactor, and cosmo does
not claim to know which (the same discipline as RISK-04). Use `--live-only` to
keep just what is still reachable.

A **hard commit budget** applies: `history.max_commits` (default **200**) caps
how many commits one sweep reviews. It is an operator ceiling a repo may only
lower — and `--max-commits` may only lower it further, never raise it, so a flag
cannot buy a bigger model bill. The list is truncated *before* any review is
dispatched, so concurrency (shared with `llm_audit.concurrency`) changes how fast
the capped set is worked through, never how many calls are made. Commits past the
budget are reported as un-reviewed.

Merge commits are skipped by default (their diffs restate work already reviewed
on the branch); `--include-merges` keeps them. A sweep reviews commit diffs, so
the tree-level static tools never run — it says so under `skipped:` rather than
letting a clean sweep imply a clean tree.

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
  concurrency: 8      # per-file reviews in flight at once (default 4)
```

Files are reviewed **several at a time** — `llm_audit.concurrency` (default
**4**) sets how many. It's the same trust tier as `max_files`: a scanned repo may
only lower it, since burst rate is what trips a provider's rate limit. It changes
only how fast the capped set is worked through — the budget is applied *before*
any review is dispatched, so concurrency can never widen it.

Each file is reviewed independently, so results don't depend on which review
finishes first: findings always come back in file order, and the same project
audits to the same report.

A whole-project audit fires many `claude` sessions, and a single one can
transiently fail (exit 1, empty error). cosmo **retries with exponential
backoff** per file, and a file that still fails after its retries is isolated —
recorded under `skipped:`, never aborting the rest of the run. Add `--verbose`
(or `-v`) to watch files being reviewed live instead of waiting for the end;
progress is a completion count (`[3/20]`), so lines arrive as reviews land, not
in file order.

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
slow multi-file audit works — and that thread reviews several files at once
(`llm_audit.concurrency`). Findings merge into session state as each file
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
keys (threshold, ignore paths, provider choice, skills) but can only **tighten**
*safety* keys — `sandbox.*`, `fuzzing.*`, `external_targets.*`, `disclosure.*`,
`triggers.*`, `providers_policy.*`, `extensions.*`, `llm_audit.*`, `history.*` —
and loosening values are clamped and warned at load.

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
| `cosmo review <t> --live` | same review, live workflow UI on stderr |
| `cosmo history <target>` | sweep commit history (local path or `owner/repo`) |
| `cosmo waive / baseline` | manage waived findings |
| `cosmo hook` / `install-hook` | git pre-commit/pre-push review |
| `cosmo action <pr>` | CI PR review + gated comment + SARIF |
| `cosmo trends <target>` | lifecycle / OWASP rollup / disclosure queue |
| `cosmo interactive <target>` | live session, slash-commands |
| `cosmo agent <target>` | live session, natural language |
| `cosmo fuzz <target>` | manual-only sandbox fuzzing |
| `cosmo extensions` | list custom extensions |
| `cosmo plugin sync/check` | manage the Claude Code plugin surface |
