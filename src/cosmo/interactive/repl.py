"""Interactive REPL loop (architecture §7).

Streams a session: read a line, dispatch a command (or run/refine a scan),
print, repeat. Kept I/O-injectable (`read`/`write`) so the loop is exercised in
tests without a tty. This is orchestration only — all behavior lives in
`commands.dispatch` over the shared `Session`.
"""
from __future__ import annotations

from typing import Callable

from ..config import load_config
from .commands import dispatch
from .session import Session

_BANNER = ("cosmo interactive — same engine as batch mode. /help for commands, "
           "/status for state, blank line or /quit to exit.")


def run_repl(
    target: str,
    *,
    operator_config: str | None = None,
    read: Callable[[str], str] = input,
    write: Callable[[str], None] = print,
    autoscan: bool = True,
) -> Session:
    config = load_config(target if _is_local(target) else ".", operator_config=operator_config)
    session = Session(config=config, target=target)
    session.writer = write   # so /audit can stream progress live as it runs
    write(_BANNER)
    if autoscan:
        report = session.scan()
        write(f"initial scan: {len(report.findings)} finding(s) "
              f"at threshold {session.effective_threshold()}")

    while True:
        try:
            line = read("cosmo> ")
        except (EOFError, KeyboardInterrupt):
            break
        line = (line or "").strip()
        if line in ("", "/quit", "/exit"):
            break
        write(dispatch(session, line))
    return session


def _is_local(target: str) -> bool:
    return "#" not in target and not target.startswith("http")
