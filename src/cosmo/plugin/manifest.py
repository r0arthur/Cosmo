"""Plugin manifest + slash-command surface (architecture §17, build step 20).

Cosmo ships as a Claude Code plugin/skill; it does **not** fork Claude Code. It
reuses Claude Code's auth/session/tool-use by shelling to the same `cosmo`
binary that batch mode, the git hook, and the GitHub Action use — so every
guardrail (config trust tiers §15, the fuzz duration cap §7, the data-governance
gate §8, the fail-closed public-comment gate §11, the egress broker §9a) is
enforced in exactly one place and the plugin cannot relax any of it.

The load-bearing property of this module: the plugin's slash-command surface is
**derived from the guarded interactive registry** (`interactive.commands`), not
hand-maintained. A command can only appear in the plugin if it already exists in
the enforced dispatcher, and every generated command file restricts
`allowed-tools` to the `cosmo` binary — a slash command can never grant itself
an arbitrary shell, a raw network socket, or a GitHub-posting tool. The surface
therefore cannot drift away from, or widen past, what the enforced layer allows.
"""
from __future__ import annotations

from dataclasses import dataclass

from .. import __version__
from ..interactive.commands import _COMMANDS

# The only tools a cosmo slash command may invoke. Enforcement lives in the
# `cosmo` binary; the plugin is a thin caller, so the surface is deliberately
# narrow and identical for every command. Notably absent: a bare `Bash(*)`, any
# `curl`/network tool, and any `gh ... comment`/post tool — public posting stays
# behind the §11 gate inside cosmo, never a plugin-granted capability.
ALLOWED_TOOLS = "Bash(cosmo:*), Bash(python -m cosmo:*)"

# Commands that read/refine session state only vs. commands the plugin exposes
# as their own top-level slash command. `/help` and `/status` are folded into
# the umbrella `/cosmo-review` command's flow rather than shipped standalone.
_STANDALONE = {
    "review",     # synthetic umbrella command (not in _COMMANDS) — see below
    "scope", "disclose", "report", "confirm", "waive", "baseline",
    "threshold", "model", "duration", "skills",
    # "which scanners does this machine have" is a question worth answering
    # before trusting a result, so it gets its own command rather than being
    # buried in the review flow.
    "tools",
    # `/scan` was missing from this set entirely — it existed in `_COMMANDS`
    # and worked from the CLI's interactive session, but had no Claude Code
    # slash-command surface at all. `/findings` is its natural companion: read
    # the result of a scan someone just ran.
    "scan", "findings",
}


@dataclass(frozen=True)
class CommandSpec:
    """One plugin slash command, named `/cosmo-<name>`."""
    name: str                 # e.g. "scope"
    slug: str                 # e.g. "cosmo-scope" — the file/command name
    description: str
    body: str
    allowed_tools: str = ALLOWED_TOOLS


def _first_line(doc: str | None) -> str:
    """The command's own summary line, without its leading separator.

    Interactive docstrings are written for `/help`, where the convention is
    `[args] — what it does` and a command taking no arguments starts at the
    dash. The description below adds its own dash, so leaving that one in place
    renders "cosmo /tools — — static scanners".
    """
    if not doc:
        return ""
    for ln in doc.splitlines():
        ln = ln.strip()
        if ln:
            return ln.lstrip("—- ").strip() if ln.startswith(("—", "-")) else ln
    return ""


def interactive_command_names() -> list[str]:
    """The exact set of guarded slash-commands, from the one enforced registry."""
    return list(_COMMANDS.keys())


def command_specs() -> list[CommandSpec]:
    """Derive the plugin surface from the guarded registry.

    Every spec here maps 1:1 onto a command in `interactive.commands._COMMANDS`
    (plus the synthetic `/cosmo-review` umbrella, which just runs `cosmo review`
    non-interactively). Nothing is invented: if a command is not in the enforced
    dispatcher it cannot be exposed, and none of these can run a tool outside
    `ALLOWED_TOOLS`.
    """
    specs: list[CommandSpec] = [_review_umbrella()]
    for name, handler in _COMMANDS.items():
        if name not in _STANDALONE:
            continue                      # help/status ride inside /cosmo-review
        desc = _first_line(handler.__doc__) or f"cosmo /{name}"
        specs.append(CommandSpec(
            name=name,
            slug=f"cosmo-{name}",
            description=f"cosmo /{name} — {desc}",
            body=_delegating_body(name, desc),
        ))
    return specs


def _delegating_body(name: str, desc: str) -> str:
    return (
        f"Run the cosmo `/{name}` command in a live session over the current "
        f"target and report the result.\n\n"
        f"Steps:\n"
        f"1. Open a session on the target (current working tree, or a PR the "
        f"user named) — opening one never scans on its own, `/scan` is a "
        f"separate, explicit step:\n"
        f"   ```\n   cosmo interactive <target>\n   ```\n"
        f"   then issue `/{name} <args>` — or run it non-interactively if the "
        f"user gave concrete arguments.\n"
        f"2. Report exactly what cosmo returns. Do not reinterpret a refusal: if "
        f"cosmo says a scope was refused, a disclosure needs human approval, or a "
        f"finding was withheld from a public surface, relay that verbatim.\n\n"
        f"Guardrails are authoritative and enforced inside cosmo — this command "
        f"cannot relax the config trust tiers, the fuzz duration cap, the "
        f"data-governance gate, the disclosure gate, or the egress broker. It "
        f"cannot post anything to a public surface; the public-comment gate "
        f"decides that inside cosmo, not here."
    )


def _review_umbrella() -> CommandSpec:
    body = (
        "Run a cosmo security review over the current diff or a GitHub PR and "
        "report findings.\n\n"
        "Steps:\n"
        "1. Determine the target: a PR the user named (`owner/repo#123` or URL), "
        "else the current working-tree diff vs HEAD.\n"
        "2. Run the review:\n"
        "   ```\n   cosmo review <target> --format cli\n   ```\n"
        "   (`--format sarif` for CI; `--format pr` to preview the *gated* public "
        "comment.)\n"
        "3. Summarize findings. Surface any `skipped:` stages (a scanner not "
        "installed, provider unavailable) so a partial run is not mistaken for a "
        "clean bill of health.\n"
        "4. Do NOT post anything to GitHub. Public posting is governed by the "
        "fail-closed disclosure gate (§11); `--format pr` already shows what "
        "would and would not be posted, with confirmed/high-sensitivity findings "
        "withheld by design.\n\n"
        "cosmo's own guardrails are authoritative — this command cannot relax the "
        "config trust tiers or the disclosure gate. Sandbox confirmation (§6), "
        "fuzzing (§7), disclosure (§13), and external-target recon (§9) are "
        "reached through their own `/cosmo-*` commands, each still enforced "
        "inside cosmo."
    )
    return CommandSpec(
        name="review",
        slug="cosmo-review",
        description="Run a cosmo security review over the current diff or a GitHub PR",
        body=body,
    )


def plugin_manifest() -> dict:
    """The `.claude-plugin/plugin.json` contents, versioned off the package."""
    return {
        "name": "cosmo",
        "version": __version__,
        "description": (
            "Security review and zero-day discovery tool. "
            "Static pre-filter + multi-model LLM review over a diff, dynamic "
            "sandbox confirmation, manual fuzzing, trend/compliance tracking, "
            "coordinated disclosure, and authorized external-target recon — all "
            "behind a two-tier config trust model, a single egress broker, and a "
            "fail-closed public-comment gate. Reuses Claude Code auth/session/"
            "tool-use; does not fork it."
        ),
        "author": {"name": "cosmo"},
        "commands": [f"./commands/{s.slug}.md" for s in command_specs()],
    }


def command_markdown(spec: CommandSpec) -> str:
    """Render a slash-command file: frontmatter (with narrowed tools) + body."""
    return (
        "---\n"
        f"description: {spec.description}\n"
        f"allowed-tools: {spec.allowed_tools}\n"
        "---\n\n"
        f"{spec.body}\n"
    )
