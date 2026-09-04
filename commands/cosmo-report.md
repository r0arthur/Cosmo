---
description: cosmo /report — [format] — export as cli|markdown|sarif|pr (pr goes through the gate)
allowed-tools: Bash(cosmo:*), Bash(python -m cosmo:*)
---

Run the cosmo `/report` command in a live session over the current target and report the result.

Steps:
1. Open a session on the target (current working tree, or a PR the user named) — opening one never scans on its own, `/scan` is a separate, explicit step:
   ```
   cosmo interactive <target>
   ```
   then issue `/report <args>` — or run it non-interactively if the user gave concrete arguments.
2. Report exactly what cosmo returns. Do not reinterpret a refusal: if cosmo says a scope was refused, a disclosure needs human approval, or a finding was withheld from a public surface, relay that verbatim.

Guardrails are authoritative and enforced inside cosmo — this command cannot relax the config trust tiers, the fuzz duration cap, the data-governance gate, the disclosure gate, or the egress broker. It cannot post anything to a public surface; the public-comment gate decides that inside cosmo, not here.
