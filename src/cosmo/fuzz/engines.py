"""Fuzzing-engine integration (architecture §7).

cosmo *orchestrates* an existing coverage-guided engine per language — it does
not reimplement fuzzing. This module maps a language to the engine cosmo drives
and builds the invocation; the actual run is performed by an injected runner so
the orchestration logic stays testable without a real fuzzer on the box.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Engine:
    name: str
    languages: tuple[str, ...]
    sanitizers: tuple[str, ...] = ()


# One existing engine per language family. cosmo drives these; it never becomes one.
_ENGINES = (
    Engine("libFuzzer", ("c", "cpp"), sanitizers=("asan", "ubsan")),
    Engine("AFL++", ("c", "cpp"), sanitizers=("asan", "ubsan")),
    Engine("go-fuzz", ("go",)),
    Engine("Jazzer", ("jvm", "java", "kotlin")),
    Engine("Atheris", ("python",)),
)


class NoEngineForLanguage(Exception):
    pass


def select_engine(language: str) -> Engine:
    lang = language.lower()
    for e in _ENGINES:
        if lang in e.languages:
            return e
    raise NoEngineForLanguage(f"no integrated fuzzing engine for language: {language!r}")


def build_invocation(engine: Engine, harness_path: str, corpus_dir: str,
                     max_seconds: int) -> list[str]:
    """A representative, engine-appropriate argv. The hard duration cap is baked
    into the invocation itself so a run cannot outlive it even if the caller's
    own timer misfires — defense in depth around the §7 'hard duration cap'."""
    if max_seconds <= 0:
        raise ValueError("max_seconds must be positive; a fuzz run needs a bounded cap")
    if engine.name == "Atheris":
        return ["python", harness_path, corpus_dir, f"-max_total_time={max_seconds}"]
    if engine.name in ("libFuzzer",):
        return [harness_path, corpus_dir, f"-max_total_time={max_seconds}"]
    if engine.name == "AFL++":
        return ["afl-fuzz", "-i", corpus_dir, "-o", f"{corpus_dir}.out",
                "-V", str(max_seconds), "--", harness_path]
    if engine.name == "go-fuzz":
        return ["go", "test", "-run=^$", "-fuzz=.", f"-fuzztime={max_seconds}s",
                harness_path]
    if engine.name == "Jazzer":
        return ["jazzer", f"--autofuzz={harness_path}", f"-max_total_time={max_seconds}"]
    raise NoEngineForLanguage(engine.name)  # pragma: no cover
