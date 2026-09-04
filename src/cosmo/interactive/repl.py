"""Interactive session entry point.

On a terminal this hands off to the full-screen UI in `screen.py`. Everywhere
else — a pipe, CI, the test suite — it runs the line-based loop below, which
stays the reference implementation of a session: read a line, dispatch, print,
repeat, with `read`/`write` injectable so the loop is exercised without a tty.

Either way this is orchestration only. All behaviour lives in
`commands.dispatch` over the shared `Session`, so the two front ends cannot
diverge on what a command is allowed to do.
"""
from __future__ import annotations

from typing import Callable

from ..config import load_config
from .commands import dispatch
from .session import Session

_BANNER = ("cosmo interactive — same engine as batch mode. /scan to run the "
           "scanners, /scan llm to include the model. /help for commands, "
           "blank line or /quit to exit.")


def run_repl(
    target: str,
    *,
    operator_config: str | None = None,
    read: Callable[[str], str] = input,
    write: Callable[[str], None] = print,
    scan_on_open: str | None = None,
    plain: bool = False,
) -> Session:
    config = load_config(target if _is_local(target) else ".", operator_config=operator_config)
    session = Session(config=config, target=target)

    # On a real terminal the session is full-screen. Everywhere else — a pipe,
    # CI, the test suite — this line-based loop stays the reference
    # implementation, and `--plain` forces it on a terminal too.
    if not plain and read is input and write is print:
        from .screen import run_screen, usable
        if usable():
            return run_screen(session, scan_on_open=scan_on_open)

    session.writer = write   # so /audit can stream progress live as it runs
    write(_BANNER)
    if scan_on_open:
        report = session.scan(llm=scan_on_open == "llm")
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
