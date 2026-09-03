# Installing cosmo

Every install method that actually exists in this repository, with prerequisites,
verification, upgrade, and uninstall for each.

Next: **[Getting started](getting-started.md)** · **[Usage](usage.md)** ·
**[Troubleshooting](faq-troubleshooting.md)**

---

## Requirements at a glance

| | Requirement | Notes |
|---|---|---|
| **Python** | `>= 3.10` | From `pyproject.toml` (`requires-python`). CI tests 3.10, 3.11, 3.12, 3.13. |
| **Runtime dependency** | `PyYAML >= 6.0` | The only mandatory dependency. |
| **OS** | Linux, macOS | The installer is `bash`; the `.deb` targets Debian/Ubuntu. See [Platform notes](#platform-notes). |
| **git** | recommended | Needed to review a working tree, staged diff, or commit history. |

Everything below this line is **optional**. cosmo degrades rather than failing —
a missing tool is reported under `skipped:` in the report:

| Optional | Enables | Without it |
|---|---|---|
| `semgrep` | multi-language taint/pattern rules | `static:semgrep (not installed …)` |
| `opengrep` | the semgrep fork's rules, plus the matched source line semgrep's OSS engine withholds | `static:opengrep (not installed …)` |
| `gitleaks` | secrets — working tree *and* git history | `static:gitleaks (not installed …)` |
| `trufflehog` | secrets, with an optional live check against the credential's provider | `static:trufflehog (not installed …)` |
| `bandit` | Python AST security checks | `static:bandit (not installed …)` |
| `trivy` | dependency CVEs and IaC misconfiguration | `static:dep-audit (no dependency scanner ran)` |
| `findsecbugs` | Java taint analysis — **needs compiled bytecode** | `static:find-sec-bugs (not installed …)` |
| `claude` CLI, logged in | AI review on your subscription | LLM stage skipped |
| `anthropic` SDK + `ANTHROPIC_API_KEY` | AI review via API | LLM stage skipped |
| `gh` CLI, authenticated | GitHub PR review, remote history sweeps | local review still works |

The scanners are separate projects by other authors; cosmo runs whichever it
finds on your `PATH` and never bundles them. See [CREDITS.md](../CREDITS.md).

**Method A (below) installs all seven automatically.** `semgrep` and `bandit`
come from `pip`; the other five have no pip package, so cosmo fetches their
GitHub release binaries itself — verified against the release's published
checksum where one exists (`gitleaks`, `trivy`, `trufflehog`), downloaded over
HTTPS only where it does not (`opengrep`, `find-sec-bugs`; both note this
rather than reporting an unverified download as equivalent to a verified one).
Nothing is bundled *into* cosmo — this is the same category of action as
`pip install semgrep` already was, just reaching a release page instead of
PyPI, and happening for you instead of by hand.

Anywhere else — a `.deb` install, a manual `pip install -e`, a machine the
installer never ran on — the same fetcher is available directly:

```bash
cosmo tools --install              # fetch every one of the five that is missing
cosmo tools --install gitleaks     # or just one
```

To see which of the seven this machine actually has, and whether they are
current:

```bash
cosmo tools                    # offline
cosmo tools --check-updates    # compare against the newest release
```

> **cosmo never silently skips a stage.** Anything that did not run is named in
> the report's `skipped:` list, so a clean result is never confused with an
> unchecked one.

---

## Method A — one command (recommended)

From a clone of this repository:

```bash
make install
```

That is a thin wrapper for the installer, which you can also call directly:

```bash
./scripts/install.sh
```

**What it does**, in order:

1. Creates an isolated virtualenv at `~/.local/share/cosmo/venv`
2. `pip install -e` this repository into it
3. Installs `semgrep` and `bandit` into the same venv (skippable — see below)
4. Symlinks `~/.local/bin/cosmo` → the venv's `cosmo`
5. Symlinks `~/.local/bin/semgrep` and `~/.local/bin/bandit` too, if they installed — otherwise cosmo
   would not find it on `PATH` and the static stage would show as skipped
6. Fetches `gitleaks`, `trivy`, `opengrep`, `trufflehog`, and `find-sec-bugs`
   from their GitHub releases via `cosmo tools --install` — each into
   `~/.local/share/cosmo/tools/<name>/`, symlinked into `~/.local/bin/` the
   same way as the pip-installed pair (skippable individually or all at once —
   see below)

A tool this machine's OS/architecture has no release asset for (or that fails
to fetch — offline, rate-limited) is skipped, not fatal: the rest of the
install continues, and that scanner shows as `not installed` in `cosmo tools`
same as if you had never asked for it.

**Knobs** (environment variables):

| Variable | Default | Effect |
|---|---|---|
| `PREFIX` | `$HOME/.local` | Install root; binaries go to `$PREFIX/bin`, fetched tools to `$PREFIX/share/cosmo/tools` |
| `VENV` | `$PREFIX/share/cosmo/venv` | Where the virtualenv lives |
| `NO_SEMGREP` | unset | Skip installing semgrep (pip) |
| `NO_BANDIT` | unset | Skip installing bandit (pip) |
| `NO_GITLEAKS` | unset | Skip fetching gitleaks (GitHub release) |
| `NO_TRIVY` | unset | Skip fetching trivy (GitHub release) |
| `NO_OPENGREP` | unset | Skip fetching opengrep (GitHub release) |
| `NO_TRUFFLEHOG` | unset | Skip fetching trufflehog (GitHub release) |
| `NO_FINDSECBUGS` | unset | Skip fetching find-sec-bugs (GitHub release) |
| `NO_SCANNERS` | unset | Skip all five GitHub-release fetches at once |

```bash
PREFIX=/opt ./scripts/install.sh          # system-wide-ish location
NO_SEMGREP=1 ./scripts/install.sh         # skip semgrep specifically
NO_SCANNERS=1 ./scripts/install.sh        # cosmo alone, fetch nothing
```

**Re-running upgrades in place** — it is safe to run repeatedly. Re-running
`cosmo tools --install` (or the whole installer) re-fetches each tool's latest
release and replaces what is there.

**Uninstall:**

```bash
make uninstall          # or: ./scripts/install.sh --uninstall
```

This removes `~/.local/bin/cosmo`, the venv, and `~/.local/share/cosmo/tools`.
Every scanner symlink — the pip-installed pair and the five fetched ones — is
removed **only if it points into a location cosmo itself manages**, so a copy
you installed yourself, anywhere else on `PATH`, is never touched.

---

## Method B — Debian package (`.deb`)

Build a self-contained package from the repo. No `fpm` or Debian packaging
knowledge required:

```bash
make deb                        # or: ./packaging/build-deb.sh
sudo dpkg -i dist/cosmo_*.deb   # installs /usr/bin/cosmo
```

Choose a different output directory with `OUT=/tmp ./packaging/build-deb.sh`.

**What the package contains:**

- `/opt/cosmo/lib/` — cosmo plus its Python dependencies, vendored flat
- `/usr/bin/cosmo` — a shell launcher running
  `env PYTHONPATH=/opt/cosmo/lib /usr/bin/python3 -s -m cosmo "$@"`

Because the launcher calls the **system** `python3` against a vendored library
directory, the only requirement on the target machine is `python3 (>= 3.10)` —
no `pip` step, no venv. `Architecture: all` (pure Python), so one build installs
anywhere. The control file declares `Depends: python3 (>= 3.10)`,
`Recommends: git`, and `Suggests: gitleaks, bandit` — the two static scanners
that exist as Debian packages. The other five (`semgrep`, `opengrep`,
`trufflehog`, `trivy`, `find-sec-bugs`) are upstream binaries with no Debian
package, so they aren't in `Suggests` either — apt has nothing to point at.

None of the seven scanners, nor the `claude` CLI, is a hard dependency: this
package installs and runs with zero of them present, and each missing one is
named under `skipped:` on every scan rather than silently narrowing it. See the
[optional-tools table](#requirements-at-a-glance) above and
[`cosmo tools`](usage.md#cosmo-tools) to check what's on a given machine.

After installing the package, `cosmo tools --install` fetches the five that
have no Debian package (see [above](#requirements-at-a-glance)) the same way
Method A's installer does — it is not part of the `.deb` payload itself
(nothing is bundled; see [CREDITS.md](../CREDITS.md) on why), but it is the
same fetcher, reachable from any install method.

**Building requires** `dpkg-deb` and `fakeroot` (present on Debian/Ubuntu; CI
installs `fakeroot` explicitly).

**Upgrade:** rebuild and `sudo dpkg -i` the new file — `dpkg` replaces in place.

**Uninstall:**

```bash
sudo dpkg -r cosmo
```

**Sharing it:** hand someone the file from `dist/`. All they run is
`sudo dpkg -i cosmo_<version>_all.deb`.

---

## Method C — by hand

If you would rather manage the virtualenv yourself:

```bash
python3 -m venv ~/cosmo-venv
~/cosmo-venv/bin/pip install -e /path/to/cosmo semgrep bandit
ln -s ~/cosmo-venv/bin/cosmo ~/.local/bin/cosmo
```

Add `'.[claude]'` instead of plain `.` if you want the Anthropic SDK for the
API-key provider:

```bash
~/cosmo-venv/bin/pip install -e '/path/to/cosmo[claude]'
```

Uninstall by deleting the venv and the symlink.

---

## Method D — from source, for development

See **[CONTRIBUTING.md](../CONTRIBUTING.md)** for the full contributor setup.
The short version:

```bash
git clone git@github.com:r0arthur/Cosmo.git
cd Cosmo
python3 -m venv .venv && . .venv/bin/activate
pip install -e '.[dev]'
pytest -q
```

`.[dev]` adds `pytest >= 7`. The suite is hermetic — no network, no model, no
external binaries required.

---

## Verifying the install

```bash
cosmo --help
```

Expected — the subcommand list:

```
usage: cosmo [-h]
             {review,waive,baseline,hook,install-hook,action,fuzz,interactive,agent,history,trends,extensions,plugin}
             ...

cosmo security review + zero-day discovery (full build, steps 1–20)
```

Then a real end-to-end check against the current directory:

```bash
cosmo review .
```

> **There is no `cosmo --version`.** The flag does not exist and exits `2`. Use
> `cosmo --help`, or for a `.deb` install, `dpkg -s cosmo | grep Version`. This
> is a known gap — see [open questions](#known-gaps).

---

## PATH matters

cosmo locates `semgrep`, `claude`, and `gh` on your `PATH`. Run it from a shell
that has dropped `~/.local/bin` and those stages silently report as `skipped:`
rather than erroring.

```bash
export PATH="$HOME/.local/bin:$PATH"
```

The installer prints a warning if `$PREFIX/bin` is not already on your `PATH`.

---

## What gets created, and where

| Path | When | What |
|---|---|---|
| `~/.local/share/cosmo/venv` | Method A | The virtualenv (override with `VENV`) |
| `~/.local/bin/cosmo` | Method A | Launcher symlink (override with `PREFIX`) |
| `~/.local/bin/semgrep` | Method A | Only if semgrep installed into the venv |
| `~/.local/bin/bandit` | Method A | Only if bandit installed into the venv |
| `/opt/cosmo/lib`, `/usr/bin/cosmo` | Method B | Vendored library + launcher |
| `<target>/.cosmo/cache.json` | first `cosmo review` | Incremental scan cache |
| `<target>/.cosmo/baseline.json` | first `cosmo waive` | Waived-finding fingerprints |
| `<target>/.cosmo/trends.db` | `cosmo review --record` | SQLite trend/disclosure store |
| `<target>/.git/hooks/pre-commit` | `cosmo install-hook` | Git hook |

Everything cosmo writes into a scanned project lives under `.cosmo/`. The
repository's own `.gitignore` already excludes it; add `.cosmo/` to yours if you
are scanning a project that does not.

---

## Turning on the AI review

The static scan needs no account. For the LLM stage, pick **one**:

**Option 1 — your Claude Code subscription (no API key).** If the `claude` CLI
is installed and logged in:

```bash
cosmo review . --model claude-cli
```

cosmo shells out to `claude`; there is no separate API billing.

**Option 2 — an Anthropic API key** (billed separately from any subscription):

```bash
pip install anthropic          # into whichever env holds cosmo
export ANTHROPIC_API_KEY=sk-ant-...
cosmo review .                 # the built-in `claude` provider is the default
```

Other providers are configured rather than installed — see
**[configuration.md](configuration.md#providers)** for `codex` (`OPENAI_API_KEY`),
`deepseek` (`DEEPSEEK_API_KEY`), and local `llama`.

Either way, a repo marked `data_sensitivity: sensitive` will not have its source
sent to a third party unless the operator explicitly allows that vendor.

---

## Installing for CI

CI does not use the installer. Install the package directly and let the runner's
Python provide the environment:

```yaml
- uses: actions/setup-python@v5
  with:
    python-version: "3.12"
- run: pip install -e .
- run: cosmo action "${{ github.repository }}#${{ github.event.number }}" --post --sarif cosmo.sarif
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
    GH_TOKEN: ${{ github.token }}
```

A complete, ready-to-copy workflow lives at
[`examples/github/cosmo-review.yml`](../examples/github/cosmo-review.yml).
See **[usage.md](usage.md#cosmo-action)** for what `cosmo action` does.

---

## Platform notes

**Linux** — the reference platform. CI runs `ubuntu-latest`.

**macOS** — Methods A, C, and D work (`bash`, `python3`, symlinks). Method B
(`.deb`) does not apply. `~/.local/bin` is often not on `PATH` by default on
macOS; add it.

**Windows** — not supported directly. `scripts/install.sh` and
`packaging/build-deb.sh` are bash, and the sandbox uses a rootless Linux
container runtime. Use **WSL2** and follow the Linux instructions.

CI only exercises Linux, so macOS support is inferred from the code rather than
tested. See [known gaps](#known-gaps).

---

## Offline and restricted networks

cosmo's **static** path needs no network at all. The pieces that do:

- **Model providers.** `claude`, `codex`, and `deepseek` are hosted. For a fully
  offline review, configure the **local `llama` provider** against an endpoint
  you host (Ollama, vLLM):

  ```yaml
  providers:
    llama: { local: true, endpoint: "http://localhost:11434/v1" }
  ```

  Local providers are also the only ones eligible when
  `providers_policy.data_sensitivity` is `sensitive`.

- **The egress broker** restricts model calls to an allow-list of provider hosts
  plus loopback. A self-hosted endpoint on a non-loopback address must be added
  by the operator via `providers_policy.allowed_provider_hosts`.

- **Installation itself** still needs a package index unless you build the `.deb`
  on a connected machine and copy the file across — which is the recommended
  air-gapped path, since the package vendors its dependencies.

**Port 22 blocked?** If your network blocks SSH, GitHub also serves SSH on 443:

```bash
git remote set-url origin ssh://git@ssh.github.com:443/<owner>/<repo>.git
```

---

## Common install failures

| Symptom | Cause | Fix |
|---|---|---|
| `cosmo: command not found` after Method A | `$PREFIX/bin` not on `PATH` | `export PATH="$HOME/.local/bin:$PATH"` |
| Stages show `static:<tool> (not installed …)` | That scanner is absent, or in a venv/tools dir not on `PATH` | `cosmo tools --install` (the 5 without a pip package) or `cosmo tools --install <tool>`; for semgrep/bandit, re-run `./scripts/install.sh` without `NO_SEMGREP`/`NO_BANDIT` |
| `cosmo tools --install` fetches nothing for a tool | Its project has no release asset for this OS/architecture | Reported as `unsupported OS: ...` or `no ... release asset matches this platform` — install that one manually from its release page |
| `static:find-sec-bugs (Java source found but no compiled classes …)` | find-sec-bugs analyses bytecode, not source | Build first (`mvn -q compile`), so `target/classes` exists |
| `model:claude (cosmo's default) unavailable — needs ...` | The selected provider has no credentials here; the line lists what the others need | [Turn on the AI review](#turning-on-the-ai-review), or `--model <name>` |
| `error: target path does not exist: '...'` | Bad path, or an unset shell variable that expanded to nothing | Check the path; for a PR use `owner/repo#123` |
| `GitHub target requested but 'gh' CLI is not installed` | PR/remote-history target without `gh` | Install `gh` and `gh auth login` |
| `make deb` fails on `fakeroot` | Build dependency missing | `sudo apt-get install -y fakeroot` |
| `cache: could not write .cosmo cache` | Target directory is read-only | Harmless — the review is unaffected, only the incremental speedup is lost |
| `dpkg: dependency problems` on install | System `python3` older than 3.10 | Upgrade Python, or use Method A with a newer interpreter |

More, including config and usage errors, in
**[faq-troubleshooting.md](faq-troubleshooting.md)**.

---

## Known gaps

Flagged honestly rather than papered over:

- **No published package.** cosmo is not on PyPI; there is no
  `pip install cosmo`, `brew install`, `npm`, or `cargo` path. Every method
  above starts from a clone. `pyproject.toml` is publishable, but no release
  workflow pushes to an index.
- **No prebuilt binaries or Docker image.** No `Dockerfile` exists in the repo.
  `release.yml` attaches a built `.deb` to a GitHub Release on a `v*` tag; that
  is the only distributed artifact.
- **No `--version` flag.** `cosmo --version` exits `2`.
- **macOS and WSL are untested.** CI is Linux-only.
