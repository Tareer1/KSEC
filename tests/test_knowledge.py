"""Tests for the in-tool knowledge mentor (ksec ask / ksec role)."""
from __future__ import annotations

import io
import json
from contextlib import redirect_stdout
from types import SimpleNamespace

from ksec.cli.ask import cmd_ask, cmd_role
from ksec.knowledge.service import KnowledgeService
from tests import KsecTestCase


class KnowledgeServiceTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.kb = KnowledgeService()

    def test_direct_topic_id(self):
        answer = self.kb.answer("role-red")
        self.assertTrue(answer.matched)
        self.assertEqual(answer.topic.id, "role-red")

    def test_alias_resolves(self):
        self.assertEqual(self.kb.get("red").id, "role-red")
        self.assertEqual(self.kb.get("purple").id, "role-purple")

    def test_plain_concept_question(self):
        answer = self.kb.answer("what is an ip address")
        self.assertTrue(answer.matched)
        self.assertEqual(answer.topic.id, "ip-address")

    def test_roman_urdu_keyword_routing(self):
        answer = self.kb.answer("nmap kya hai")
        self.assertTrue(answer.matched)
        self.assertEqual(answer.topic.id, "tool-nmap")

    def test_role_question_routing(self):
        answer = self.kb.answer("red team kaise shuru karun")
        self.assertTrue(answer.matched)
        self.assertEqual(answer.topic.id, "role-red")

    def test_tool_question(self):
        answer = self.kb.answer("hydra kya hai")
        self.assertTrue(answer.matched)
        self.assertEqual(answer.topic.id, "tool-hydra")

    def test_unmatched_returns_false(self):
        answer = self.kb.answer("zzqqxxyy nonsense")
        self.assertFalse(answer.matched)
        self.assertIsNone(answer.topic)

    def test_list_filters_by_kind_and_role(self):
        concepts = self.kb.list(kind="concept")
        self.assertTrue(all(t.kind == "concept" for t in concepts))
        blue_team_topics = self.kb.list(role="blue")
        ids = {t.id for t in blue_team_topics}
        self.assertIn("role-blue", ids)
        # 'all'-audience topics are included for a specific role.
        self.assertIn("ip-address", ids)

    def test_four_role_playbooks_exist(self):
        for role_id in ("role-red", "role-blue", "role-purple", "role-learner"):
            self.assertIsNotNone(self.kb.get(role_id), role_id)

    def test_blackhat_role_playbook_exists(self):
        topic = self.kb.get("role-blackhat")
        self.assertIsNotNone(topic)
        self.assertEqual(topic.kind, "role")
        self.assertIn("red", topic.audience)

    def test_blackhat_aliases_resolve(self):
        self.assertEqual(self.kb.get("blackhat").id, "role-blackhat")
        self.assertEqual(self.kb.get("black hat").id, "role-blackhat")

    def test_blackhat_question_routing(self):
        answer = self.kb.answer("black hat kaise karta hai")
        self.assertTrue(answer.matched)
        self.assertEqual(answer.topic.id, "role-blackhat")

    def test_blackhat_is_controlled_emulation_not_criminal_guidance(self):
        """Spec 06#28: black-hat framing must stay authorized emulation."""
        topic = self.kb.get("role-blackhat")
        text = " ".join(
            [str(topic.title), str(topic.summary)]
            + [str(part) for part in topic.sections]
        ).lower()
        self.assertIn("controlled adversary simulation", text)
        # The playbook opens with an authorization step, never with attack steps.
        first_text = str(topic.sections[0][1]).lower()
        self.assertIn("authorize", first_text)
        self.assertNotIn("unauthorized", text)

    def test_blackhat_playbook_commands_stay_scope_gated(self):
        topic = self.kb.get("role-blackhat")
        commands = [
            part for kind, part in topic.sections if kind == "cmd"
        ]
        # Every attack step is bound to an engagement scope or the workspace.
        self.assertTrue(any("engagement create" in c for c in commands))
        self.assertTrue(any("scope add" in c for c in commands))
        self.assertTrue(any("--engagement" in c for c in commands))


class AskCliTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def _args(self, question=None, **overrides):
        defaults = dict(
            question=question,
            list_topics=False,
            json=False,
            quiet=False,
            mode="professional",
        )
        defaults.update(overrides)
        return SimpleNamespace(**defaults)

    def test_cmd_ask_text(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_ask(self.ctx, self._args(question=["what", "is", "a", "port"]))
        self.assertEqual(code, 0)
        self.assertIn("Ports", buffer.getvalue())
        self.assertIn("ksec run port_scan", buffer.getvalue())

    def test_cmd_ask_json(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_ask(self.ctx, self._args(question=["nmap", "kya", "hai"], json=True))
        self.assertEqual(code, 0)
        data = json.loads(buffer.getvalue())
        self.assertEqual(data["topic"]["id"], "tool-nmap")

    def test_cmd_ask_unmatched(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_ask(self.ctx, self._args(question=["zzqqxxyy"]))
        self.assertEqual(code, 1)

    def test_cmd_ask_list(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_ask(self.ctx, self._args(question=[], list_topics=True))
        self.assertEqual(code, 0)
        self.assertIn("role-red", buffer.getvalue())

    def test_cmd_role_blue(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_role(self.ctx, SimpleNamespace(name="blue", json=False, quiet=False, mode="professional"))
        self.assertEqual(code, 0)
        self.assertIn("BLUE TEAM playbook", buffer.getvalue())

    def test_cmd_role_blackhat_text(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_role(self.ctx, SimpleNamespace(name="blackhat", json=False, quiet=False, mode="professional"))
        self.assertEqual(code, 0)
        self.assertIn("BLACK HAT emulation playbook", buffer.getvalue())

    def test_cmd_role_blackhat_json(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_role(self.ctx, SimpleNamespace(name="blackhat", json=True, quiet=False, mode="professional"))
        self.assertEqual(code, 0)
        data = json.loads(buffer.getvalue())
        self.assertEqual(data["topic"]["id"], "role-blackhat")

    def test_cmd_role_blackhat_quiet(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_role(self.ctx, SimpleNamespace(name="blackhat", json=False, quiet=True, mode="professional"))
        self.assertEqual(code, 0)
        self.assertEqual(buffer.getvalue().strip(), "role-blackhat")

    def test_cmd_role_blackhat_alias(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_role(self.ctx, SimpleNamespace(name="black hat", json=False, quiet=False, mode="professional"))
        self.assertEqual(code, 0)
        self.assertIn("BLACK HAT emulation playbook", buffer.getvalue())

    def test_cmd_role_unknown(self):
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            code = cmd_role(self.ctx, SimpleNamespace(name="hacker", json=True, quiet=False, mode="professional"))
        self.assertEqual(code, 1)
        self.assertIn("unknown role", buffer.getvalue())


if __name__ == "__main__":
    import unittest

    unittest.main()
