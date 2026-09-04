# FAQ & troubleshooting

Real messages cosmo emits, what causes them, and what to do.

Install problems: **[installation.md](installation.md#common-install-failures)** ·
Config: **[configuration.md](configuration.md)** ·
Commands: **[usage.md](usage.md)**

---

## Reading the output first

Before treating anything as an error, read the `skipped:` lines. cosmo reports
what it did *not* look at, and most confusion comes from mistaking an incomplete
run for a clean one.

```
Summary: no findings at or above the configured threshold
  skipped: static:semgrep (not installed)
  skipped: model:claude (cosmo's default) unavailable — needs ANTHROPIC_API_KEY
           and the `anthropic` SDK. other providers: claude-cli needs the
           `claude` CLI on PATH; codex needs OPENAI_API_KEY; deepseek needs
           DEEPSEEK_API_KEY
```

That is **not** "your code is fine". That is "almost nothing ran".

---

## FAQ

### Why does it say "no findings" when I know there's a bug?

Most likely nothing capable of finding it ran. Check `skipped:`. With no semgrep
and no model configured, cosmo has almost no detection surface. See
[getting-started — Making it actually review something](getting-started.md#making-it-actually-review-something).

Second possibility: your finding is below the severity floor. Try
`--threshold info`.

Third: it was waived. Check `cosmo baseline .`.

### Do I need an API key?

No, for the static scan. For the AI review you need either the `claude` CLI
logged in (uses your subscription, no separate billing) or an `ANTHROPIC_API_KEY`
with the `anthropic` SDK installed. See
[installation — Turning on the AI review](installation.md#turning-on-the-ai-review).

### Will it send my code to a third party?

Only if a hosted provider is selected. Set
`providers_policy: {data_sensitivity: sensitive}` and only **local** providers
and operator-approved vendors are eligible — a sensitive repo never has its
source fanned out. The `claude-cli` provider still goes to Anthropic; a local
`llama` endpoint does not leave your network.

### Can I scan a remote repo without cloning it?

For **history**, yes: `cosmo history owner/repo`. For **PRs**, yes:
`cosmo review owner/repo#123`. For a whole remote repo, no — clone it, delete
`.git`, and review the folder.

### Why is `--audit` so slow / expensive?

It is one model call per file. That is what `llm_audit.max_files` (default 50)
exists to bound. Raise it deliberately in the operator config, and prefer
pointing it at a subdirectory rather than a whole repo.

### What's the difference between `review` and `history`?

`review` looks at the present — a diff, a PR, or the current tree. `history`
looks at the past, commit by commit, and tells you whether each finding's code is
**still in HEAD**.

### Does `absent` mean the vulnerability was fixed?

**No.** It means the flagged line is no longer in HEAD. That may be a fix, or a
rename, or a refactor. cosmo annotates and never auto-waives on that basis. Judge
it yourself.

### Is there a `--version` flag?

No — it exits `2`. Use `cosmo --help`, or `dpkg -s cosmo | grep Version` for a
`.deb` install.

---

## Errors, by message

### `error: target path does not exist: '...'`

The local path is wrong, or a shell variable expanded to nothing. For a GitHub PR
use `owner/repo#123` or a pull-request URL — a bare repo URL is not a PR.

**Exit code 2.** Checked before any scan begins, so it never scans the wrong tree.

### `GitHub target requested but 'gh' CLI is not installed`

PR review and remote history sweeps read through `gh`.

```bash
gh auth login && gh auth status
```

### `model:claude (cosmo's default) unavailable — needs ...`

Appears under `skipped:`. The provider cosmo selected has no credentials on this
machine. The line names what *that* provider needs, then either the alternatives
already usable here (`available now: --model codex`) or what each of the others
would need. Pick any of them with `--model <name>`; the cheapest route is usually
installing the `claude` CLI, logging in, and passing `--model claude-cli`.

For `cosmo history` this is fatal (exit `2`) rather than a skip — a history sweep
*is* an LLM review, so there is nothing left to run:

```
error: model:claude (cosmo's default) unavailable — needs ANTHROPIC_API_KEY
and the `anthropic` SDK. other providers: claude-cli needs the `claude` CLI
on PATH; codex needs OPENAI_API_KEY; deepseek needs DEEPSEEK_API_KEY
A history sweep is an LLM review, so there is nothing to run without one.
```

### `static:semgrep (not installed)` / `static:gitleaks (not installed)`

The scanner isn't on `PATH`. Note that installing it into a venv that isn't on
`PATH` produces the same message — cosmo resolves these by `PATH`, not by import.

```bash
pip install semgrep
export PATH="$HOME/.local/bin:$PATH"
```

### Why did `cosmo interactive` start scanning on its own?

It no longer does. Opening a session waits for you; `/scan` runs the static
scanners and `/scan llm` adds the model review. `--scan` / `--scan llm` restore
scan-on-open if you want it.

It used to scan automatically, and that scan ran the full pipeline — so with a
provider configured, opening a session sent your code to a vendor before you had
asked for anything.

### I pressed Ctrl-Z and cosmo did not exit

Ctrl-Z **suspends**; it does not stop. The run is frozen in the background —
`jobs` lists it, `fg` resumes it, `kill %1` ends it. To stop a run, use
**Ctrl-C**: cosmo exits `130`, writes no report, posts nothing, and stops every
scanner it started (including semgrep's `semgrep-core`, which otherwise outlives
the run). Give it a couple of seconds — scanners get a brief grace period before
they are killed.

If Ctrl-C used to leave a `concurrent.futures` traceback, that is fixed: it was
cosmo failing to say "you stopped me" rather than anything actually breaking.

### How do I know which scanners I have, and whether they are current?

```bash
cosmo tools --check-updates
```

Offline without the flag. Exits `1` if a scanner is missing or outdated, so it
works as a CI gate. Two tools cannot report their own version — Debian's
`gitleaks` prints `version is set by build process`, and the find-sec-bugs
launcher has no version flag — and those show as `version unknown` rather than
being assumed fine.

### A scanner shows `not installed` — how do I get it?

`./scripts/install.sh` fetches all seven automatically on a fresh install (see
[installation.md](installation.md)), so this is usually about a machine that
installer never ran on, or one where a fetch failed the first time (offline,
rate-limited, or no release asset for that OS/architecture). Fetch it directly:

```bash
cosmo tools --install              # every one of the five with no pip package
cosmo tools --install gitleaks     # just one
```

`semgrep`/`bandit` aren't in that list — they come from `pip install
semgrep`/`pip install bandit` instead (what `scripts/install.sh` already does).
`cosmo tools --install semgrep` is refused and says so, rather than silently
doing nothing.

### `static:dep-audit (no dependency scanner ran ...)`

Dependency auditing is trivy's job, and trivy is not installed or not in
`static.tools`. Install it and the line goes away, replaced by real CVE
findings. It is worth being explicit that "no CVEs reported" and "nothing looked
at the dependencies" are different results — that distinction is the reason this
line exists.

### `static:find-sec-bugs (Java source found but no compiled classes ...)`

find-sec-bugs analyses **bytecode**, not source, so a repo has to be built
before it can look at anything. Run your build first (`mvn -q compile`, `gradle
classes`) so `target/classes` or `build/classes` exists, then re-run. A repo
with no Java at all produces no such line — nothing was missed.

### `claude CLI failed after 3 attempts: ...`

The `claude` CLI failed transiently three times (it retries with exponential
backoff). Usually rate/resource contention, especially with a concurrent
`--audit`. Lower `llm_audit.concurrency`, or check `claude` works standalone:

```bash
echo "say hi" | claude -p --output-format text
```

### `cache: could not write .cosmo cache (read-only/permission)`

A `note:`, not a failure. The review completed; you just lose the incremental
speedup next run. Make the target writable, or ignore it.

### `'<key>' from repo ignored (operator-only: it designates trust, not preference)`

The scanned repository tried to set `skills.org_dir`, which would let it promote
its own skills to authoritative. Ignored by design. See
[configuration.md](configuration.md#one-reserved-key-inside-a-preference-section).

### `safety-tier '<key>': repo value X would loosen the operator ceiling Y — clamped to Y`

Working as intended — the repo tried to weaken a safety setting. If *you* want
the looser value, set it in the **operator** config, not the repo's.

### `safety-tier '<section>' from repo ignored (operator-only)`

`external_targets`, `disclosure`, `triggers`, and `extensions` are entirely
operator-controlled. A repo block is ignored wholesale.

### `ext:<name> (load error: ...)` / `ext-detector:<id> (error: ...)`

A custom extension failed to import or threw. It is isolated and reported rather
than crashing the review. See [extensions.md](extensions.md).

### `sandbox (no container runtime — findings left unconfirmed)`

Sandbox confirmation needs a rootless container runtime (podman/docker). Findings
stay `unconfirmed` — which never auto-waives them.

### `fuzzing is disabled in config (safety tier); enable fuzzing.enabled to run`

Off by default, and a scanned repo cannot turn it on. Enable it in the **operator
config**. Exit code `2`.

### `no --duration set. A fuzz campaign never defaults silently`

Deliberate: `cosmo fuzz` will not guess a runtime.

```bash
cosmo fuzz . --duration 30m
```

A duration above `fuzzing.confirm_above` additionally needs `--confirm`.

### `external-target mode requires an active /scope declaration`

Recon is refused until a scope is declared — program name, non-empty in-scope
list, and an explicit rate limit read from the program's terms.

### `host is out of declared scope` / `target resolves to a forbidden internal/metadata address`

The egress broker refused the request. Out-of-scope hosts are hard-excluded, and
the SSRF net blocks cloud metadata addresses even under a wildcard scope.

### `plugin surface is out of date` (CI failure)

You added or renamed a slash-command without regenerating the derived surface:

```bash
cosmo plugin sync
git add commands/ .claude-plugin/ && git commit
```

---

## Behaviour that looks like a bug but isn't

| Observation | Explanation |
|---|---|
| Findings appear in a different order run to run | They shouldn't. Audit and history results are returned in input order regardless of completion order — [file an issue](https://github.com/r0arthur/Cosmo/issues) if you see otherwise |
| `--live` shows nothing when redirected | It detects a non-TTY and falls back to one durable line per event |
| A PR comment shows fewer findings than the CLI | The fail-closed gate withheld sensitive ones. Working as designed — see [usage.md](usage.md#output--format-pr-the-fail-closed-gate) |
| A warm run reports fewer stages than a cold one | It shouldn't — skip records are cached alongside findings. Please report it |
| `cosmo history` reports `static` as skipped | Correct: a sweep reviews commit diffs, not the work tree |
| The same file appears twice in a history sweep | Reachability is per commit — one entry may be `absent`, another `present` |

---

## Getting help

- **Usage question** → [usage.md](usage.md)
- **Bug or feature request** → [open an issue](https://github.com/r0arthur/Cosmo/issues)
- **A way to make cosmo bypass its own guardrails** → **do not open a public
  issue.** Report it privately to the maintainer — see
  [CONTRIBUTING.md](../CONTRIBUTING.md#reporting-security-issues-in-cosmo-itself)
