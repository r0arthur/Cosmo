# Examples

End-to-end workflows with real commands and the outcomes to expect.

Assumes cosmo is installed — see **[installation.md](installation.md)**. Flag
details live in **[usage.md](usage.md)**.

---

## 1. Review a pull request before merging

The everyday case. No clone required.

```bash
cosmo review owner/repo#123 --model claude-cli
```

```
cosmo — owner/repo#123
============================================================
   HIGH    Unvalidated redirect in login flow
          src/auth/views.py:44  ·  model:claude-cli  ·  CWE-601  ·  conf=80%
          ↳ `next` parameter is echoed into a redirect without an allow-list.
          fix: Validate `next` against a list of permitted paths.

Summary: 1 high
```

Preview what a public comment would actually reveal before posting one:

```bash
cosmo review owner/repo#123 --format pr
```

Anything confirmed or security-sensitive is withheld here by design — the full
detail stays in the CLI and SARIF output.

---

## 2. Triage a whole project you just cloned

```bash
git clone https://github.com/acme/legacy-shop
cd legacy-shop
rm -rf .git                 # forces whole-tree mode: every file treated as new
cosmo review . --threshold high
```

Static-only, which is what you want for a first pass over a large codebase. Then
narrow to a module and bring in the model:

```bash
cosmo review ./src/payments --audit --model claude-cli --live
```

> Do not point `--audit` with an LLM at an entire large repo. The budget
> (`llm_audit.max_files`, default 50) will stop you, and it reports what it
> didn't reach — but a targeted subdirectory gives better results for the spend.

---

## 3. Find old vulnerabilities that were never fixed

The highest-value sweep: review the repository's past, then keep only findings
whose code is still live.

```bash
cosmo history . --since '2 years ago' --model claude-cli --live-only
```

```
history-4a1c9de-1 | src/auth/token.py:88
  introduced in 4a1c9de by Alice Chen on 2024-03-11 — add order lookup endpoint
  still in HEAD: present

commits reviewed: 187 of 340+ matched   source: local
still in HEAD: 12 present, 31 absent, 4 unknown
```

`absent` findings are annotated, not dropped — the line being gone may be a fix
or may be a refactor, and cosmo does not claim to know which. Drop `--live-only`
to see them.

Narrow to the code you care about:

```bash
cosmo history . --path src/auth --path src/session --max-commits 50 --model claude-cli
```

Or sweep a repository you have not cloned at all:

```bash
cosmo history acme/legacy-shop --since 2024-01-01 --model claude-cli --live-only
```

---

## 4. Bisect a regression to the commit that introduced it

```bash
cosmo history . --range v1.4.0..v1.5.0 --model claude-cli --threshold high
```

Each finding names its commit, so the output *is* the bisect result. Follow up
on a specific one:

```bash
git show 4a1c9de -- src/auth/token.py
```

---

## 5. Gate your own commits

```bash
cosmo install-hook --blocking
```

From then on, `git commit` runs a fast review over the staged diff and aborts on
a critical finding. Non-blocking is the default if you'd rather just be told:

```bash
cosmo install-hook
```

Run it manually any time:

```bash
git add -p
cosmo hook
```

---

## 6. Wire it into CI

Copy [`examples/github/cosmo-review.yml`](../examples/github/cosmo-review.yml)
into `.github/workflows/`, then add `ANTHROPIC_API_KEY` as a repository secret.

Every PR gets a review, a gated comment, and SARIF in the Security tab:

```yaml
- run: >
    cosmo action "${{ github.repository }}#${{ github.event.number }}"
    --post --sarif cosmo.sarif
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    GH_TOKEN: ${{ github.token }}
```

For any other CI, the exit code is the whole integration:

```bash
cosmo review . --threshold high    # exit 1 if anything actionable survived
```

---

## 7. Handle a false positive

Every finding prints a stable fingerprint. Waive by fingerprint, not by line —
the waiver survives the code moving:

```bash
cosmo review .
# ... note the fingerprint on the finding you want to silence

cosmo waive . a1b2c3d4e5f60789 --reason "input is validated in the middleware"
cosmo review .                       # gone from the report
```

Review and reverse waivers:

```bash
cosmo baseline .
cosmo baseline . --unwaive a1b2c3d4e5f60789
```

`.cosmo/baseline.json` is meant to be committed — it is your team's shared record
of what has been triaged.

---

## 8. Teach it your codebase's patterns

Add a skill so the model looks for what matters in *your* stack:

```bash
mkdir -p .cosmo/skills
cat > .cosmo/skills/django-taint.md <<'EOF'
---
name: django-taint
description: Flag request data reaching a raw query or shell call
applies_to:
  - "**/*.py"
---
Trace values from `request.GET`, `request.POST`, and URL kwargs into
`.raw()`, `.extra()`, `cursor.execute`, and `subprocess` with `shell=True`.
Django ORM filters and parameterized `.raw()` with params are safe.
Report the source expression and the sink by name.
EOF

cosmo review . --model claude-cli
```

Only skills whose `applies_to` globs match the changed files are injected.
Because this one lives in the repo, it loads as **untrusted reference** — useful
guidance, but it cannot suppress a finding. See
[usage.md § Review skills](usage.md#review-skills).

---

## 9. Track whether you're getting better

```bash
cosmo review . --record          # after each scan
cosmo trends .
```

Reports each finding's lifecycle — introduced, reopened, fixed — plus the
noisiest rule categories and an OWASP Top 10 rollup. The noisy-rule signal is
what tells you a skill needs sharpening.

---

## 10. A full engagement, start to finish

```bash
# 1. Get the code
git clone https://github.com/acme/target && cd target

# 2. Broad static pass over everything
cosmo review . --threshold medium --record

# 3. Deep AI pass on the security-critical surface
cosmo review ./src/auth --audit --model claude-cli --live --record

# 4. Look for anything old that was never fixed
cosmo history . --since '3 years ago' --path src/auth \
                --model claude-cli --live-only --record

# 5. Triage: waive what isn't real
cosmo waive . <fingerprint> --reason "..."

# 6. Machine-readable output for the report
cosmo review . --format sarif > findings.sarif

# 7. See the shape of what you found
cosmo trends .
```

For a confirmed, high-severity, unpatched finding, draft a coordinated
disclosure — which **queues** it and sends nothing:

```bash
cosmo interactive .
> /disclose <finding-id>
> /status
```

Delivery requires explicit human approval and an operator-configured endpoint. A
`SECURITY.md` in the target pointing at an arbitrary host is refused, because it
is untrusted repo input.
