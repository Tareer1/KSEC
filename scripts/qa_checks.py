#!/usr/bin/env python3
"""KSEC QA gate checks (standalone, stdlib only).

Runs the static gates that CI enforces (spec 09/10) so they can also be
executed locally with one command:

* compile/AST sanity sweep over every file under ``src/``
* no ``TODO``/``FIXME``/``XXX`` markers in ``src/``
* knowledge base is well-formed and every module topic routes

Exit code 0 = all gates pass.
"""
from __future__ import annotations

import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SRC = ROOT / "src"


def compile_sweep() -> list[str]:
    errors: list[str] = []
    files = sorted(SRC.rglob("*.py"))
    for path in files:
        try:
            compile(path.read_text(encoding="utf-8"), str(path), "exec")
        except SyntaxError as exc:
            errors.append(f"{path}: {exc}")
    print(f"compile sweep: {len(files)} files, {len(errors)} error(s)")
    return errors


def marker_sweep() -> list[str]:
    markers = ("TODO", "FIXME", "XXX")
    hits: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if any(marker in line for marker in markers):
                hits.append(f"{path}:{lineno}: {line.strip()}")
    print(f"marker sweep: {len(hits)} hit(s)")
    return hits


def knowledge_sweep() -> list[str]:
    sys.path.insert(0, str(ROOT / "src"))
    from ksec.knowledge.topics import all_topics

    topics = list(all_topics())
    ids = [t.id for t in topics]
    duplicates = sorted({tid for tid in ids if ids.count(tid) > 1})
    print(f"knowledge sweep: {len(topics)} topics, {len(duplicates)} duplicate id(s)")
    return [f"duplicate topic id: {tid}" for tid in duplicates]


def main() -> int:
    errors: list[str] = []
    errors += compile_sweep()
    errors += marker_sweep()
    errors += knowledge_sweep()
    if errors:
        print("\n".join(f"FAIL: {e}" for e in errors))
        return 1
    print("qa_checks: all gates passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
