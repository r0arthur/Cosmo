# Writing cosmo extensions (custom plugins & skills)

cosmo is extensible without forking. A **custom extension** is a small Python
module that adds any combination of:

| Contribution | What it adds | Surfaced as |
|---|---|---|
| **skill** | extra review guidance for the LLM stage | injected when a matching file changes |
| **detector** | an extra finding source | findings joined to the normal pipeline (dedupe → waiver → gate) |
| **command** | an interactive slash-command | `/x-<name>` in a live session |

Everything an extension contributes flows through the **same guardrails** as
first-party code. Read the safety model below before you ship one — it explains
what an extension can and cannot do, and why.

---

## The safety model (read this first)

Extensions run **in-process**, so activating one is a full-trust decision. cosmo
makes that decision safe by construction:

1. **Discovery ≠ activation.** cosmo *discovers* candidate extensions from
   configured paths and installed entry points, but it only *imports and runs*
   the ones whose name appears in `extensions.enabled`. A disabled extension's
   module is never imported — its top-level code never executes.

2. **Only the operator can enable an extension.** `extensions` is a **safety-tier**
   config section. The operator/org config (the trusted tier) can enable
   extensions; a **scanned repo's `cosmo.yaml` cannot** — any `extensions:` block
   in a repo under review is ignored and a warning is emitted. So a hostile repo
   can ship extension code, but it stays inert.

3. **No impersonating a guarded command.** A custom command is always exposed as
   `/x-<name>`. It can never take the name of a builtin (`/report`, `/scope`,
   `/disclose`, …), so it cannot masquerade as the gated command a user expects.

4. **Custom findings have no shortcut.** Detector output is normalized into the
   shared `Finding` shape and re-stamped `source="ext:<name>"`. It then goes
   through dedupe, waiver suppression, and the fail-closed public-comment gate
   like any other finding — an extension cannot push a finding straight to a
   public surface, and returning a non-`Finding` object is rejected.

5. **Custom-skill trust follows activation.** An enabled extension's skills are
   treated as authoritative guidance — *unless* the operator lists the extension
   under `extensions.reference_only`, in which case its skills load as UNTRUSTED
   reference (the same RISK-03 framing as repo-provided skills).

---

## Quickstart: a local extension

Create a directory with a `cosmo_extension.py`. The extension's **name is the
directory basename**.

```
my-ext/
└── cosmo_extension.py
```

```python
# my-ext/cosmo_extension.py
from cosmo.extensions import Extension
from cosmo.findings import Finding
from cosmo.severity import Severity
from cosmo.skills.loader import Skill

def detect(target, config):
    # ... scan `target`, return a list[Finding] ...
    return [Finding(id="my:1", title="something", severity=Severity.MEDIUM,
                    source="ext:my-ext", file="app.py", line=10, category="CWE-123")]

def cmd_hello(session, args):
    return f"hello from my-ext ({len(args)} args)"

COSMO_EXTENSION = Extension(
    name="my-ext",
    version="1.0",
    description="what this extension does",
    skills=[Skill(name="my-guidance", description="…", applies_to=["**/*.py"],
                  instructions="Look harder at …", origin="ext:my-ext")],
    detectors={"main": detect},
    commands={"hello": cmd_hello},   # → /x-hello
)
```

The module must expose either a module-level `COSMO_EXTENSION` (an `Extension`)
or a `register()` function that returns one.

Point the **operator** config at it and enable it by name:

```yaml
# operator-config.yaml  (the trusted tier — NOT the scanned repo's cosmo.yaml)
extensions:
  paths:
    - /abs/path/to/my-ext
  enabled:
    - my-ext                 # this line is what actually arms it
  # reference_only:          # optional: load its skills as untrusted reference
  #   - my-ext
```

Verify what cosmo sees:

```bash
cosmo extensions --operator-config operator-config.yaml     # lists active/disabled
```

A worked example lives in [`examples/extensions/hardcoded-ip/`](../examples/extensions/hardcoded-ip/cosmo_extension.py).

---

## Distributing as an installed package (entry point)

Ship an extension as a pip-installable package by registering a `cosmo.extensions`
entry point. The value may be an `Extension`, or a zero-arg callable returning one.

```toml
# pyproject.toml of your extension package
[project.entry-points."cosmo.extensions"]
my-ext = "my_pkg.cosmo_ext:COSMO_EXTENSION"
```

Installed entry points are discovered automatically, but — like local paths —
still only run when the operator lists the name under `extensions.enabled`.

---

## The `Extension` contract

```python
@dataclass
class Extension:
    name: str
    version: str = "0"
    description: str = ""
    skills: list[Skill] = []                 # cosmo.skills.loader.Skill
    detectors: dict[str, Detector] = {}      # name -> (target: str, config) -> list[Finding]
    commands: dict[str, CommandHandler] = {} # name -> (session, args) -> str
```

- **Detector** `(target, config) -> list[Finding]`. `target` is a local path (or
  a resolved checkout). Raise or return `[]` freely — a detector that raises is
  isolated and recorded under `skipped:`, never crashing the review.
- **CommandHandler** `(session, args) -> str`, the same signature as builtin
  interactive commands. `session` gives you `.target`, `.config`, `.findings`.
- **Skill**: the same convention as a repo skill — see
  [usage.md — Review skills](usage.md#review-skills); `applies_to`
  is a list of globs matched against changed files.

## Testing your extension

```python
from cosmo.config import Config
from cosmo.extensions import load_enabled, normalize_extension_findings

cfg = Config(data={"extensions": {"paths": ["/abs/path/to/my-ext"],
                                  "enabled": ["my-ext"]}})
loaded = load_enabled(cfg)
assert [e.name for e in loaded.active] == ["my-ext"]
```

See [`tests/test_extensions.py`](../tests/test_extensions.py) for the full set of
guarantees the extension system holds, each as a runnable test.
