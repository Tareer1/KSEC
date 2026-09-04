"""Knowledge search and routing (AI-free).

Deterministic keyword routing over the curated topic set: questions are
lower-cased, split into tokens and scored against each topic's title,
summary and keyword aliases. Short/noisy tokens are ignored so questions
like "nmap kya hai", "port scan kese karein" or "red team kaise shuru
karun" land on the right topic without any external service.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ksec.knowledge.topics import ALIASES, TOPICS, Topic, topic_by_id

_WORD_RE = re.compile(r"[a-z0-9._-]+")
_STOP = {"the", "and", "for", "how", "what", "kya", "hai", "kaise", "kese", "karun", "karo",
         "hain", "hai", "with", "can", "you", "me", "does", "do", "is", "are", "why", "when",
         "use", "using", "tool", "ksec", "mein", "se", "ko", "ki", "ka", "to", "a", "an",
         "of", "in", "on", "it", "this", "that", "about"}


@dataclass(frozen=True)
class Answer:
    topic: Topic | None
    matched: bool
    query: str
    related: tuple[Topic, ...]


def _tokens(text: str) -> list[str]:
    return [t for t in _WORD_RE.findall(text.lower()) if t not in _STOP and len(t) >= 2]


def _topic_score(topic: Topic, query_lower: str, tokens: list[str]) -> int:
    score = 0
    haystack = " ".join((topic.title, topic.summary, " ".join(topic.keywords))).lower()
    for keyword in topic.keywords:
        kw = keyword.strip().lower()
        if len(kw) >= 3 and kw in query_lower:
            score += 6
    for token in tokens:
        if token in topic.title.lower():
            score += 5
        for keyword in topic.keywords:
            if token in keyword.lower():
                score += 3
                break
        if token in topic.summary.lower():
            score += 1
    for word in topic.title.lower().split():
        if len(word) >= 3 and word in query_lower:
            score += 4
    return score


def _tokenize_query(text: str) -> tuple[str, list[str]]:
    query_lower = text.lower().strip()
    return query_lower, _tokens(query_lower)


class KnowledgeService:
    """Answers free-form questions from the curated topic set."""

    def __init__(self, topics: tuple[Topic, ...] = TOPICS) -> None:
        self.topics = topics

    def get(self, topic_id: str) -> Topic | None:
        if topic_id in ALIASES:
            topic_id = ALIASES[topic_id]
        return topic_by_id(topic_id)

    def list(self, kind: str | None = None, role: str | None = None) -> list[Topic]:
        out = []
        for topic in self.topics:
            if kind and topic.kind != kind:
                continue
            if role and role not in topic.audience and "all" not in topic.audience:
                continue
            out.append(topic)
        return out

    def answer(self, query: str, limit_related: int = 3) -> Answer:
        query_lower, tokens = _tokenize_query(query)
        # Direct id / alias hit wins (e.g. "role red", "tool-nmap").
        cleaned = query_lower.replace(" ", "-").replace("_", "-").strip("-")
        direct = self.get(query_lower.strip()) or self.get(cleaned)
        if direct is not None:
            related = self.related(direct.id, limit=limit_related)
            return Answer(topic=direct, matched=True, query=query, related=related)

        ranked: list[tuple[int, Topic]] = []
        for topic in self.topics:
            score = _topic_score(topic, query_lower, tokens)
            if score > 0:
                ranked.append((score, topic))
        ranked.sort(key=lambda pair: (-pair[0], pair[1].id))
        if not ranked:
            return Answer(topic=None, matched=False, query=query, related=())
        best = ranked[0]
        related = self.related(best[1].id, limit=limit_related, exclude_scores=ranked)
        return Answer(topic=best[1], matched=True, query=query, related=related)

    def related(self, topic_id: str, limit: int = 3, exclude_scores: list[tuple[int, Topic]] | None = None) -> tuple[Topic, ...]:
        """Return topics of the same role/kind nearest to the answered one."""
        current = topic_by_id(topic_id)
        if current is None:
            return ()
        out: list[Topic] = []
        for other in self.topics:
            if other.id == current.id:
                continue
            shared_role = set(other.audience) & set(current.audience)
            same_kind = other.kind == current.kind
            if shared_role or same_kind:
                out.append(other)
        out.sort(key=lambda t: (t.kind != current.kind, t.id))
        return tuple(out[:limit])
