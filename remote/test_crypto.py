"""Run with python3 -m unittest discover -s remote -p 'test_*.py'."""

import os
import runpy
import unittest
from unittest.mock import patch

with patch.dict(os.environ, {
    "ACS_DEMO_CLIENT_KEY": "test-only-key-material-32-bytes-long",
    "ACS_DEMO_CLIENT_KEY_ID": "test-key",
    "ACS_DEMO_RESOURCE_KEY": "AA",
}):
    import server


class SessionKeyTests(unittest.TestCase):
    def test_section_10_vector_and_exact_session_id(self):
        session_id = "6b1f2c9e-4d7a-4e3b-8a51-9c0d2e7f1a36"
        with patch.object(server, "CLIENT_KEY", bytes(range(32)).decode("utf-8")):
            key = server.hkdf_session_key(session_id)
            self.assertEqual(key.hex(), "80f0dc8c611279bfc2af2d5f374c5cb685888192ce1af5c3e0673d8fa748e8a4")
            for spelling in (session_id.upper(), "urn:uuid:" + session_id):
                self.assertNotEqual(server.hkdf_session_key(spelling), key)

    def test_rejects_short_utf8_secret_at_startup(self):
        for secret in ("a" * 31, "é" * 15):
            with patch.dict(os.environ, {"ACS_DEMO_CLIENT_KEY": secret}):
                with self.assertRaisesRegex(ValueError, "at least 32 UTF-8 bytes"):
                    runpy.run_path(server.__file__)
