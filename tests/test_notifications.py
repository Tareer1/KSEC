from __future__ import annotations

from ksec.notifications.service import EventBus, NotificationService
from tests import KsecTestCase


class EventBusTest(KsecTestCase):
    def test_subscribe_and_publish(self):
        bus = EventBus()
        received = []
        bus.subscribe("job.completed", lambda event: received.append(event))
        bus.publish("job.completed", job_id="abc", state="COMPLETED")
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0]["payload"]["job_id"], "abc")

    def test_unsubscribed_events_ignored(self):
        bus = EventBus()
        received = []
        bus.subscribe("a", lambda event: received.append(event))
        bus.publish("b", x=1)
        self.assertEqual(received, [])


class NotificationServiceTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.service = NotificationService(self.ctx.db)

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_record_and_list(self):
        self.service.record(event_type="test", title="Hello", body="world")
        rows = self.service.list()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["title"], "Hello")
        self.assertEqual(self.service.count(), 1)


if __name__ == "__main__":
    import unittest

    unittest.main()