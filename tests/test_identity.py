from __future__ import annotations

from ksec.core.errors import IdentityError
from ksec.identity.users import (
    UserRepository,
    hash_password,
    verify_password,
)
from tests import KsecTestCase


class PasswordTest(KsecTestCase):
    def test_hash_verify_roundtrip(self):
        stored = hash_password("correct horse battery staple")
        self.assertTrue(stored.startswith("scrypt$"))
        self.assertTrue(verify_password("correct horse battery staple", stored))

    def test_wrong_password_fails(self):
        stored = hash_password("right")
        self.assertFalse(verify_password("wrong", stored))

    def test_empty_password_rejected(self):
        with self.assertRaises(IdentityError):
            hash_password("")

    def test_malformed_stored_hash(self):
        self.assertFalse(verify_password("x", "not-a-valid-hash"))
        self.assertFalse(verify_password("x", "sha256$abc"))


class UserRepositoryTest(KsecTestCase):
    def setUp(self):
        super().setUp()
        self.ctx = self.make_context()
        self.users = UserRepository(self.ctx.db)

    def tearDown(self):
        self.ctx.close()
        super().tearDown()

    def test_create_and_fetch(self):
        user = self.users.create("alice", "s3cret", display_name="Alice")
        self.assertEqual(user.username, "alice")
        fetched = self.users.get_by_username("ALICE")
        self.assertEqual(fetched.id, user.id)

    def test_duplicate_username_rejected(self):
        self.users.create("bob", "pw1")
        with self.assertRaises(IdentityError):
            self.users.create("bob", "pw2")

    def test_invalid_username_rejected(self):
        with self.assertRaises(IdentityError):
            self.users.create("bad name!", "pw")

    def test_authenticate(self):
        self.users.create("carol", "pw123")
        user = self.users.authenticate("carol", "pw123")
        self.assertEqual(user.username, "carol")
        with self.assertRaises(IdentityError):
            self.users.authenticate("carol", "wrong")

    def test_disabled_user_cannot_authenticate(self):
        user = self.users.create("dave", "pw123")
        self.users.set_status(user.id, "disabled")
        with self.assertRaises(IdentityError):
            self.users.authenticate("dave", "pw123")


if __name__ == "__main__":
    import unittest

    unittest.main()