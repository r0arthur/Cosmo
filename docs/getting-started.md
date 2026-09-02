# Getting started

Assumes cosmo is installed — if not, start at
**[installation.md](installation.md)**.

Next: **[Usage reference](usage.md)** · **[Configuration](configuration.md)** ·
**[Examples](examples.md)**

---

## Your first run

From inside any git repository with uncommitted changes:

```bash
cosmo review .
```

cosmo resolves your working-tree diff, runs whatever review stages are available,
and prints a report. On a fresh install with no optional tools, the output looks
like this:

```
cosmo — .
============================================================
No findings at or above the configured threshold.
  skipped: static:semgrep (not installed)
  skipped: static:gitleaks (not installed)
  skipped: static:dep-audit (stub — not implemented in MVP)
  skipped: model:claude (unavailable — no SDK or ANTHROPIC_API_KEY)
  note: provider 'claude' unavailable (no SDK/key) — falling back
```

**That is a working run, not a failure.** Read the `skipped:` lines carefully:
they are cosmo telling you exactly what it did *not* look at. Four skipped stages
means almost nothing was actually checked. A "no findings" result is only as
strong as the stages that ran.

This is the tool's central habit — it never lets an unchecked result look like a
clean one.

---

## Making it actually review something

Add one stage at a time and watch the `skipped:` list shrink.

**1. Static analysis** — install the scanner:

```bash
pip install semgrep        # into the same environment as cosmo
cosmo review .
```

**2. The AI review** — if you have the `claude` CLI installed and logged in:

```bash
cosmo review . --model claude-cli
```

With both, a finding looks like this:

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
```

---

## The smallest complete example

Create a file with an obvious flaw and review it:

```bash
mkdir /tmp/demo && cd /tmp/demo
cat > app.py <<'EOF'
import os

def handle(user_input):
    os.system("echo " + user_input)
EOF

cosmo review . --model claude-cli --threshold low
```

`/tmp/demo` is not a git repository, so cosmo falls back to **whole-tree mode**:
every file is treated as newly added. That is also how you review a project you
have cloned but whose history you do not care about.

---

## Watching it work

Add `--live` to replace the scrolling log with a live view of the pipeline:

```bash
cosmo review . --live
```

```
OBJECTIVE
──────────────────────────────────────────────────────────────
  Security review of .
  Target  .    Mode  diff review    Floor  medium
  Status  ● IN PROGRESS    Elapsed  00:01

WORKFLOW   5/11 stages
──────────────────────────────────────────────────────────────
  ✓ Resolve target into a reviewable diff
  ✓ Load incremental cache
  ✓ Static pre-filter (semgrep, gitleaks)
  ✓ Resolve model provider + egress broker
  ✓ Build review context (static + skills)
  ● AI security review
  ○ Custom extension detectors
  ○ Deduplicate findings
  ○ Apply waivers and baseline
  ○ Prioritize from issue context
  ○ Apply severity floor
```

It ends on a verdict with a **coverage** panel naming every stage that did not
run. The UI draws to stderr, so `--format sarif` still pipes cleanly.

---

## The four things you can point cosmo at

| Target | Command | Needs a clone? |
|---|---|---|
| Your working-tree changes | `cosmo review .` | already local |
| A GitHub pull request | `cosmo review owner/repo#123` | no — reads via `gh` |
| A whole project | `cosmo review ./some-folder` | yes |
| A repo's commit history | `cosmo history .` or `cosmo history owner/repo` | no, for the remote form |

There is **no** "scan a remote repo from its URL" mode for `review` — a bare repo
URL is not a PR. Clone it, delete `.git` to force whole-tree mode, then point
cosmo at the folder. `cosmo history`, by contrast, *can* read a remote repository
without cloning.

---

## Exit codes

`cosmo review` is built to drop straight into a CI gate:

| Code | Meaning |
|---|---|
| `0` | No non-waived finding survived the threshold |
| `1` | At least one actionable finding |
| `2` | Could not run — bad target, or no reviewer available |

```bash
cosmo review . || echo "findings present"
```

---

## Where to go next

- **[usage.md](usage.md)** — every command and flag, with examples
- **[configuration.md](configuration.md)** — `cosmo.yaml`, env vars, trust tiers
- **[examples.md](examples.md)** — end-to-end workflows
- **[architecture.md](architecture.md)** — how the pipeline is built
- **[faq-troubleshooting.md](faq-troubleshooting.md)** — when something goes wrong
