from __future__ import annotations

from ksec.identity.users import UserRepository
from ksec.learning.curriculum import LEARNING_LEVELS, find_lesson, lesson_count, phases
from ksec.learning.service import LearningService
from tests import KsecTestCase


class CurriculumTest(KsecTestCase):
    def test_twelve_phases(self):
        self.assertEqual(len(phases()), 13)  # phases 0..12

    def test_lessons_exist(self):
        self.assertGreater(lesson_count(), 10)
        found = find_lesson("orientation.what-is-ksec")
        self.assertIsNotNone(found)
        self.assertEqual(found[1].title, "What is KSEC?")

    def test_five_levels(self):
        self.assertEqual(LEARNING_LEVELS[1], "Explorer")
        self.assertEqual(LEARNING_LEVELS[5], "Security Practitioner")

    def test_level_for_completion(self):
        service = LearningService
        self.assertEqual(service.level_for_completion(0, 20), 1)
        self.assertEqual(service.level_for_completion(3, 20), 2)
        self.assertEqual(service.level_for_completion(7, 20), 3)
        self.assertEqual(service.level_for_completion(12, 20), 4)
        self.assertEqual(service.level_for_completion(18, 20), 5)


class LearningServiceTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.user = UserRepository(self.ctx.db).create("student", "pw")

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_start_and_complete(self):
        self.ctx.learning.start_lesson(self.user.id, "orientation.what-is-ksec")
        status = self.ctx.learning.lesson_status(self.user.id, "orientation.what-is-ksec")
        self.assertEqual(status.status, "in_progress")
        self.ctx.learning.complete_lesson(self.user.id, "orientation.what-is-ksec")
        status = self.ctx.learning.lesson_status(self.user.id, "orientation.what-is-ksec")
        self.assertEqual(status.status, "completed")
        self.assertIsNotNone(status.completed_at)

    def test_unknown_lesson_rejected(self):
        with self.assertRaises(ValueError):
            self.ctx.learning.complete_lesson(self.user.id, "no.such.lesson")

    def test_progress_summary(self):
        self.ctx.learning.complete_lesson(self.user.id, "orientation.what-is-ksec")
        progress = self.ctx.learning.progress(self.user.id)
        self.assertEqual(progress["completed_lessons"], 1)
        self.assertGreater(progress["total_lessons"], 10)
        self.assertGreater(progress["percent"], 0.0)
        self.assertEqual(progress["level"], 1)


if __name__ == "__main__":
    import unittest

    unittest.main()