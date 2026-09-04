"""In-tool knowledge base and mentor (AI-free).

``ksec ask <question>`` routes free-form questions — even complete
beginners' questions in plain language — to curated topics covering
security concepts, every integrated tool, role playbooks (red / blue /
purple / learner) and KSEC modules, then suggests the exact commands to
run. No external dependency, fully offline.
"""
from ksec.knowledge.service import KnowledgeService, TOPICS

__all__ = ["KnowledgeService", "TOPICS"]
