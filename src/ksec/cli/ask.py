"""CLI: ``ksec ask`` — the in-tool mentor (AI-free knowledge base).

Answers free-form questions — from absolute basics ("what is an ip
address", "nmap kya hai") to role playbooks ("red team kaise shuru
karun") — with curated topics plus the exact commands to run.
``ksec role red|blue|purple|blackhat|learner`` is a shortcut to the
role playbooks (blackhat = controlled authorized emulation of a real
intruder's mindset, never unrestricted activity). Every role also gets
live, state-aware "what to do now" suggestions (``ksec suggest``).
"""
from __future__ import annotations

from ksec.bootstrap import KsecContext
from ksec.cli.output import emit
from ksec.knowledge.service import KnowledgeService
from ksec.knowledge.topics import Topic
from ksec.suggestions.service import canonical_role, suggestions

KIND_LABEL = {
    "concept": "concepts",
    "tool": "tools",
    "role": "role playbooks",
    "workflow": "workflows",
    "module": "modules",
}


def _section_text(topic: Topic) -> list[str]:
    lines: list[str] = []
    for block_type, text in topic.sections:
        if block_type == "cmd":
            lines.append(f"    $ {text}")
        elif block_type == "tip":
            lines.append(f"    > {text}")
        else:
            lines.append(text)
    return lines


def _render_topic(topic: Topic, mode: str, related: tuple[Topic, ...]) -> str:
    out: list[str] = []
    out.append(f"{topic.title}  [{topic.kind}]")
    out.append("=" * min(len(topic.title) + 10, 72))
    out.append("")
    out.append(topic.summary)
    out.append("")
    out.extend(_section_text(topic))
    if mode == "expert":
        out.append("")
        out.append(f"topic id: {topic.id}  |  audience: {', '.join(topic.audience)}")
    if related:
        out.append("")
        out.append("Also useful:")
        for rel in related:
            out.append(f"  - {rel.title}  (ask: ksec ask {rel.id})")
    return "\n".join(out)


def _answer_data(topic: Topic, query: str, related: tuple[Topic, ...]) -> dict:
    return {
        "query": query,
        "matched": True,
        "topic": {
            "id": topic.id,
            "title": topic.title,
            "kind": topic.kind,
            "audience": list(topic.audience),
            "summary": topic.summary,
            "sections": [{"type": t, "text": b} for t, b in topic.sections],
        },
        "related": [{"id": r.id, "title": r.title, "kind": r.kind} for r in related],
    }


def cmd_ask(ctx: KsecContext, args) -> int:
    knowledge = KnowledgeService()
    if getattr(args, "list_topics", False):
        grouped: dict[str, list[Topic]] = {}
        for topic in knowledge.list():
            grouped.setdefault(topic.kind, []).append(topic)
        if args.json:
            emit(
                {kind: [t.id for t in topics] for kind, topics in grouped.items()},
                True,
                False,
            )
        elif args.quiet:
            for topic in knowledge.list():
                print(topic.id)
        else:
            for kind in ("concept", "tool", "role", "workflow", "module"):
                topics = grouped.get(kind)
                if not topics:
                    continue
                print(f"{KIND_LABEL[kind].upper()}")
                for topic in topics:
                    print(f"  {topic.id:<22} {topic.title}")
                print()
        return 0

    question = " ".join(getattr(args, "question", None) or []).strip()
    if not question:
        emit("ask a question, e.g.: ksec ask 'what is a port' | ksec ask 'role red' | ksec ask --list", args.json, args.quiet)
        return 1

    answer = knowledge.answer(question)
    mode = getattr(args, "mode", None) or "professional"
    if args.json:
        if not answer.matched:
            emit({"query": question, "matched": False}, True, False)
        else:
            emit(_answer_data(answer.topic, question, answer.related), True, False)
        return 0 if answer.matched else 1
    if not answer.matched:
        print(
            f"Hmm — I don't have that exact topic. Try: ksec ask --list, or rephrase "
            f"(e.g. 'what is a port', 'nmap kya hai', 'role red')."
        )
        return 1
    print(_render_topic(answer.topic, mode, answer.related))
    return 0


def _render_suggestions(role: str, data: dict) -> str:
    items = data.get("items", [])
    if not items:
        return ""
    out = ["", "NEXT — ab kya karna hai (live suggestions)", "=" * 40]
    for i, item in enumerate(items, 1):
        out.append(f"{i}. {item['step']}")
        out.append(f"    $ {item['command']}")
        out.append(f"    why: {item['reason']}")
    state = data.get("state", {})
    if state:
        out.append("")
        out.append("your state: " + ", ".join(
            f"{k}={v}" for k, v in sorted(state.items())
        ))
    return "\n".join(out)


def cmd_role(ctx: KsecContext, args) -> int:
    knowledge = KnowledgeService()
    role_map = {
        "red": "role-red",
        "blue": "role-blue",
        "purple": "role-purple",
        "researcher": "role-purple",
        "osint": "role-purple",
        "learner": "role-learner",
        "learning": "role-learner",
        "blackhat": "role-blackhat",
        "black hat": "role-blackhat",
    }
    name = (args.name or "").strip().lower()
    topic = knowledge.get(role_map.get(name, name))
    if topic is None:
        emit(
            f"unknown role: {name} (choose red | blue | purple | blackhat | learner)",
            args.json,
            args.quiet,
        )
        return 1
    related = knowledge.related(topic.id)
    role = canonical_role(name) or "red"
    if args.json:
        data = _answer_data(topic, f"role {name}", related)
        data["suggestions"] = suggestions(ctx, role)
        emit(data, True, False)
    elif args.quiet:
        print(topic.id)
    else:
        mode = getattr(args, "mode", None) or "professional"
        print(_render_topic(topic, mode, related))
        print(_render_suggestions(role, suggestions(ctx, role)))
    return 0


def cmd_suggest(ctx: KsecContext, args) -> int:
    """Show state-aware next actions for a role (``ksec suggest red``)."""
    role = canonical_role(args.role or "") if args.role else ""
    if not role:
        emit(
            f"unknown role: {args.role} (choose red | blue | purple | blackhat | learner)",
            args.json,
            args.quiet,
        )
        return 1
    data = suggestions(ctx, role)
    if args.json:
        emit(data, True, False)
    elif args.quiet:
        for item in data["items"]:
            print(item["command"])
    else:
        print(f"{data['label']} — what to do now:")
        print(_render_suggestions(role, data).strip())
    return 0
