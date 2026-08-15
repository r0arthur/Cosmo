# Running cosmo

A practical guide to every way you can run cosmo — from a one-shot review to a
live session, a git hook, CI, fuzzing, and the Claude Code plugin. For *what each
piece does and why it's safe*, see [`architecture.html`](architecture.html); for
config, [`../cosmo.example.yaml`](../cosmo.example.yaml).

---

## 1. Install

```bash
pip install -e .            # core (PyYAML only)
pip install -e '.[claude]'  # + Anthropic SDK, for the live LLM review stage
pip install -e '.[dev]'     # + pytest, for running the test suite
```

Optional runtime pieces, each degrades gracefully if absent:

| Piece | Needed for | If missing |
|---|---|---|
| `ANTHROPIC_API_KEY` (or another provider key) | the LLM review stage | stage is **skipped**, not failed |
| `semgrep`, `gitleaks` | the static pre-filter | that tool is listed under `skipped:` |
| `gh` CLI (authenticated) | reviewing a GitHub PR, reading issues | local-path review still works |

Verify the install:

```bash
cosmo --help                # or: python -m cosmo --help
```

> Every command below is also runnable as `python -m cosmo <cmd>` if the `cosmo`
> entry point isn't on your `PATH`.

---

## 2. Review something (the core command)

`cosmo review` runs the pipeline once and prints the result.

```bash
cosmo review .                       # review the local working-tree diff
cosmo review owner/repo#123          # review a GitHub PR (needs gh)
cosmo review https://github.com/owner/repo/pull/123
```

Useful flags:

```bash
cosmo review . --threshold high      # only surface high+ (overrides config)
cosmo review . --format sarif        # SARIF for a CI Security tab
cosmo review . --format pr           # preview the GATED public comment
cosmo review . --no-cache            # force a full re-scan (ignore the cache)
cosmo review . --no-color            # plain output for logs
cosmo review . --record              # also store findings for trend tracking
cosmo review . --operator-config op.yaml   # apply the operator/org ceiling
```

**Exit code:** `1` if any non-waived finding survived the threshold, else `0` —
so `cosmo review` drops straight into a CI gate.

`--format pr` is worth knowing: it shows exactly what would be posted publicly.
Confirmed/sensitive findings and their PoCs are **withheld by default** (RISK-05);
the full detail stays in the CLI/SARIF output for the operator.

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
/model deepseek    switch reviewer — subject to the §8 data-governance gate
/skills            show injected skills
/waive <fp>        waive a finding      /baseline   list waived
/scope ...         declare an authorized external-target scope (§9)
/disclose <id>     draft + QUEUE a disclosure (sends nothing; §13)
/confirm           confirm a finding in the sandbox
/duration 30m      set a fuzzing time cap (clamped by config)
/report [pr]       render output (pr = through the fail-closed gate)
/help              full list
```

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
| `cosmo waive / baseline` | manage waived findings |
| `cosmo hook` / `install-hook` | git pre-commit/pre-push review |
| `cosmo action <pr>` | CI PR review + gated comment + SARIF |
| `cosmo trends <target>` | lifecycle / OWASP rollup / disclosure queue |
| `cosmo interactive <target>` | live session, slash-commands |
| `cosmo agent <target>` | live session, natural language |
| `cosmo fuzz <target>` | manual-only sandbox fuzzing |
| `cosmo extensions` | list custom extensions |
| `cosmo plugin sync/check` | manage the Claude Code plugin surface |
