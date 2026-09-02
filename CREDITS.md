# Credits

cosmo finds very little on its own. Most of what a scan reports was found by
somebody else's tool; cosmo's job is to run them together, normalize what comes
back into one shape, keep track of what didn't run, and hand the result to a
model for a second look. The projects below do the actual detection, and they
deserve the credit for it.

Every license id here was read from the project's own repository, not from
memory. If you spot one that has changed, please open an issue.

---

## Static scanners

cosmo executes these as ordinary subprocesses on your machine. It does not
bundle, vendor, link against, or redistribute any of them — you install them
yourself, and cosmo finds them on your `PATH`. The one hard rule cosmo keeps is
that a tool which is absent is *reported* as absent rather than quietly leaving
a hole in the scan.

| Tool | Project | Maintainers | License |
|---|---|---|---|
| `semgrep` | [Semgrep](https://semgrep.dev) | Semgrep, Inc. and contributors | LGPL-2.1 |
| `opengrep` | [Opengrep](https://github.com/opengrep/opengrep) | the Opengrep project | LGPL-2.1 |
| `gitleaks` | [Gitleaks](https://gitleaks.io) | Zachary Rice and contributors | MIT |
| `trufflehog` | [TruffleHog](https://trufflesecurity.com) | Truffle Security Co. and contributors | AGPL-3.0 |
| `bandit` | [Bandit](https://bandit.readthedocs.io) | PyCQA | Apache-2.0 |
| `trivy` | [Trivy](https://trivy.dev) | Aqua Security and contributors | Apache-2.0 |
| `find-sec-bugs` | [Find Security Bugs](https://find-sec-bugs.github.io/) | Philippe Arteau and contributors | LGPL-3.0 |

This table is generated from the tool registry in
[`src/cosmo/static/prefilter.py`](src/cosmo/static/prefilter.py), and a test
checks the two agree — so a scanner cannot be added to cosmo without its authors
being named here.

### Also underneath

* **[SpotBugs](https://spotbugs.github.io/)** (LGPL-2.1) — Find Security Bugs is
  a SpotBugs plugin; SpotBugs is the analysis engine doing the work.
* **[Semgrep Rules](https://github.com/semgrep/semgrep-rules)** — the rule set
  `--config auto` pulls, under the Semgrep Rules License v1.0. Opengrep runs
  rules in the same format.
* **Trivy's vulnerability database**, which aggregates public advisory data. The
  advisories cosmo has seen it return for Python packages come from the
  [GitHub Security Advisory database](https://github.com/advisories); trivy
  draws on other sources for other ecosystems.
* **CWE** and **OWASP** — the taxonomies cosmo normalizes every finding's
  category into. CWE™ is a trademark of MITRE.

### A note on TruffleHog and AGPL-3.0

TruffleHog is AGPL-3.0, which is worth knowing about even though it does not
reach cosmo: cosmo runs it as a separate program over a process boundary and
reads its JSON output, rather than linking it or deriving from it. cosmo itself
stays MIT. This is a description of how the code is arranged, not legal advice —
if you redistribute a bundle that *includes* these binaries, the terms are
between you and each project.

---

## Runtime and platform

| Dependency | Used for | License |
|---|---|---|
| [PyYAML](https://pyyaml.org/) | the only required dependency — config parsing | MIT |
| [Anthropic Python SDK](https://github.com/anthropics/anthropic-sdk-python) | optional, for the API-key Claude provider | MIT |
| [GitHub CLI (`gh`)](https://cli.github.com/) | optional, for PR review and remote history sweeps | MIT |
| [git](https://git-scm.com/) | diffs, history, hooks | GPL-2.0 |

## Model providers

The AI review stage calls a provider you choose and configure. cosmo is not
affiliated with any of them, and none is required — the static scan runs without
a model at all.

[Anthropic](https://www.anthropic.com/) (Claude, via API or the Claude Code
CLI) · [OpenAI](https://openai.com/) · [DeepSeek](https://www.deepseek.com/) ·
any OpenAI-compatible local endpoint, such as
[Ollama](https://ollama.com/) or [vLLM](https://docs.vllm.ai/).

---

## Standards and formats

* **[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)**
  (OASIS) — the interchange format `--format sarif` emits, and the format cosmo
  reads back from SpotBugs.
* **[OWASP Top 10](https://owasp.org/Top10/)** — the rollup in `cosmo trends`.

---

cosmo is MIT-licensed; see [LICENSE](LICENSE).
