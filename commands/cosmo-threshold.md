---
description: cosmo /threshold — [level] — view or set the session severity floor (a preference)
allowed-tools: Bash(cosmo:*), Bash(python -m cosmo:*)
---

Run the cosmo `/threshold` command in a live session over the current target and report the result.

Steps:
1. Open a session on the target (current working tree, or a PR the user named):
   ```
   cosmo interactive <target> --no-scan
   ```
   then issue `/threshold <args>` — or run it non-interactively if the user gave concrete arguments.
2. Report exactly what cosmo returns. Do not reinterpret a refusal: if cosmo says a scope was refused, a disclosure needs human approval, or a finding was withheld from a public surface, relay that verbatim.

Guardrails are authoritative and enforced inside cosmo — this command cannot relax the config trust tiers (§15), the fuzz duration cap (§7), the data-governance gate (§8), the disclosure gate (§13), or the egress broker (§9a). It cannot post anything to a public surface; the §11 gate decides that inside cosmo, not here.
