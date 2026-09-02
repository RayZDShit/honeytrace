from __future__ import annotations

import unittest

from feature_engineering import FEATURE_COLUMNS, extract_features, feature_vector
from ingest import normalize_event
from labeling import classify
from privacy import mask_ip, masked_secret


def base_features(**updates):
    values = {name: 0.0 for name in FEATURE_COLUMNS}
    values.update(updates)
    return values


class LabelingTests(unittest.TestCase):
    def test_cryptomining_precedes_generic_post_exploitation(self):
        result = classify(base_features(login_successes=1, command_count=3, miner_keyword_count=1))
        self.assertEqual(result.label, "cryptomining")
        self.assertEqual(result.threat_level, "critical")

    def test_password_spraying(self):
        result = classify(base_features(
            login_failures=20, unique_usernames=18, unique_passwords=1,
            attempts_per_minute=12, unique_pair_ratio=0.9,
        ))
        self.assertEqual(result.label, "password_spraying")

    def test_credential_stuffing(self):
        result = classify(base_features(
            login_failures=20, unique_usernames=18, unique_passwords=18,
            unique_pair_ratio=0.95, attempts_per_minute=8,
        ))
        self.assertEqual(result.label, "credential_stuffing")


class FeatureTests(unittest.TestCase):
    def test_session_features(self):
        events = [
            {
                "id": 1, "timestamp": "2026-01-01T00:00:00+00:00",
                "event_id": "cowrie.login.failed", "native_session_id": "a",
                "username": "root", "credential_fingerprint": "x",
                "credential_length": 8, "credential_entropy": 2.5,
                "common_username": 1, "common_password": 0,
                "command": None, "client_version": None, "hassh": None,
            },
            {
                "id": 2, "timestamp": "2026-01-01T00:00:10+00:00",
                "event_id": "cowrie.login.failed", "native_session_id": "b",
                "username": "admin", "credential_fingerprint": "y",
                "credential_length": 10, "credential_entropy": 3.0,
                "common_username": 1, "common_password": 0,
                "command": None, "client_version": None, "hassh": None,
            },
        ]
        features = extract_features(events)
        self.assertEqual(features["login_failures"], 2)
        self.assertEqual(features["native_session_count"], 2)
        self.assertEqual(features["avg_login_interval"], 10)
        self.assertEqual(len(feature_vector(features)), len(FEATURE_COLUMNS))


class IngestAndPrivacyTests(unittest.TestCase):
    def test_normalized_event_never_contains_plain_password(self):
        row = normalize_event({
            "eventid": "cowrie.login.failed", "timestamp": "2026-01-01T00:00:00Z",
            "src_ip": "192.0.2.4", "session": "abc", "username": "root", "password": "secret123",
        }, "cowrie", "sensor-a")
        joined = "|".join("" if value is None else str(value) for value in row)
        self.assertNotIn("secret123", joined)
        self.assertIn("s******** (9 chars)", joined)

    def test_masks(self):
        self.assertEqual(mask_ip("192.0.2.4"), "192.0.x.x")
        self.assertEqual(masked_secret("abc"), "a*** (3 chars)")


if __name__ == "__main__":
    unittest.main()
