"""Shared terminal primitives: one palette, one set of text-fitting rules.

cosmo ships a .deb whose only requirement is `python3 >= 3.10`, so there is no
`rich`, no `textual`, no `curses` wrapper — every box, colour and column in this
tool is hand-rolled ANSI. That is a deliberate cost, and it is only bearable if
the drawing primitives live in one place: the live review panel and the
full-screen session both draw from here, so a colour or a clipping rule cannot
drift between them.

The one rule worth stating: **escape codes have length but no width.** Anything
that pads, centres or truncates has to measure the visible text and colour it
afterwards, never the other way round — padding an already-coloured string
misaligns every column that follows it.
"""
from __future__ import annotations

import re

# --- palette ----------------------------------------------------------------

C = {
    "reset": "\033[0m", "dim": "\033[2m", "bold": "\033[1m",
    "gray": "\033[38;5;245m", "faint": "\033[38;5;240m",
    "cyan": "\033[38;5;80m", "blue": "\033[38;5;75m",
    "green": "\033[38;5;77m", "yellow": "\033[38;5;221m",
    "orange": "\033[38;5;215m", "red": "\033[38;5;203m",
    "magenta": "\033[38;5;176m", "white": "\033[38;5;253m",
    # Selection: a filled row reads better than a cursor glyph when the list is
    # long, but only if the text on it stays legible against the fill.
    "sel_bg": "\033[48;5;236m",
}

SEVERITY_COLOR = {
    "critical": "red", "high": "orange", "medium": "yellow",
    "low": "blue", "info": "gray",
}

# --- escape-aware measurement ------------------------------------------------

_ANSI = re.compile(r"\033\[[0-9;?]*[A-Za-z]")


def strip(text: str) -> str:
    """The text as the terminal displays it, with escape codes removed."""
    return _ANSI.sub("", str(text))


def width(text: str) -> int:
    """Display columns a string occupies."""
    return len(strip(text))


def paint(text: str, color: str, *, enabled: bool = True) -> str:
    if not enabled or not text or color not in C:
        return text
    return f"{C[color]}{text}{C['reset']}"


def pad(text: str, to: int) -> str:
    """Pad to `to` display columns, counting only what is visible."""
    return text + " " * max(0, to - width(text))


def truncate(text: str, limit: int) -> str:
    """Cut to `limit` display columns without severing an escape sequence.

    `clip`/`fit` work on plain text; this one is for a string that has already
    been coloured, where a naive slice can land inside a `\033[38;5;215m` and
    spray the rest of the frame with garbage.
    """
    if limit <= 0:
        return ""
    if width(text) <= limit:
        return text
    out, shown, i = [], 0, 0
    while i < len(text) and shown < limit - 1:
        m = _ANSI.match(text, i)
        if m:                       # zero-width: copy it, do not count it
            out.append(m.group(0))
            i = m.end()
            continue
        out.append(text[i])
        shown += 1
        i += 1
    out.append("…")
    if "\033" in text:
        out.append(C["reset"])      # never leave a colour bleeding past the cut
    return "".join(out)


def cell(text: str, to: int) -> str:
    """Exactly `to` display columns: truncated if long, padded if short.

    Padding alone is not enough. A row that only pads overflows its frame the
    moment the content is wider than the terminal, and every border after it
    lands in the wrong column.
    """
    return pad(truncate(text, to), to)


# --- fitting text to a column ------------------------------------------------

_ABS_PATH = re.compile(r"(?:/[^\s/]+){3,}")


def shorten_paths(text: str, keep: int = 2) -> str:
    """Collapse absolute paths in a line to their identifying tail.

    Whole-tree mode carries absolute paths, which otherwise fill the line with
    the one part of it every row has in common.
    """
    def _sub(m: "re.Match") -> str:
        raw = m.group(0)
        if len(raw) <= 34:
            return raw
        return "…/" + "/".join(raw.strip("/").split("/")[-keep:])
    return _ABS_PATH.sub(_sub, text)


def clip_path(path: str, limit: int) -> str:
    """Clip a path from the left — the tail identifies it, the prefix rarely does."""
    path = str(path or "-")
    return path if len(path) <= limit else "…" + path[-(limit - 1):]


def clip(text: str, limit: int) -> str:
    text = " ".join(str(text).split())
    if limit < 8:
        return text[:limit]
    return text if len(text) <= limit else text[: limit - 1] + "…"


def fit(text: str, budget: int, collapse: bool = True) -> str:
    """One line, trimmed to `budget` display columns.

    `collapse` folds runs of whitespace, which is what tool-supplied prose needs
    (semgrep messages arrive as wrapped paragraphs). Lines composed here pass
    `collapse=False` so their deliberate spacing survives.
    """
    text = " ".join(str(text).split()) if collapse else str(text).strip()
    if budget < 12 or len(text) <= budget:
        return text
    return text[: budget - 1].rstrip() + "…"


def wrap(text: str, limit: int) -> list[str]:
    """Word-wrap plain text. Blank lines are preserved as paragraph breaks."""
    out: list[str] = []
    for para in str(text).splitlines():
        if not para.strip():
            out.append("")
            continue
        line = ""
        for word in para.split():
            if line and len(line) + 1 + len(word) > limit:
                out.append(line)
                line = word
            else:
                line = f"{line} {word}".strip()
        out.append(line)
    return out or [""]


def dur(seconds: float) -> str:
    seconds = int(seconds)
    return f"{seconds // 60:02d}:{seconds % 60:02d}"
