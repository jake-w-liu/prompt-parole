import unittest
from datetime import datetime, timezone

from prompt_parole.policy import evaluate, normalize_config, parse_window


class PolicyTests(unittest.TestCase):
    def test_cross_midnight_window_blocks_after_midnight(self):
        config = normalize_config(
            {
                "timezone": "UTC",
                "lock_windows": [{"start": "19:00", "end": "05:00", "days": ["mon"]}],
                "unlock_duration_minutes": 30,
            }
        )
        now = datetime(2026, 6, 16, 2, 0, tzinfo=timezone.utc)
        decision = evaluate(config, {}, now)
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.locked_until.hour, 5)

    def test_cross_midnight_window_does_not_block_unlisted_next_day_night(self):
        config = normalize_config(
            {
                "timezone": "UTC",
                "lock_windows": [{"start": "19:00", "end": "05:00", "days": ["mon"]}],
                "unlock_duration_minutes": 30,
            }
        )
        now = datetime(2026, 6, 16, 20, 0, tzinfo=timezone.utc)
        decision = evaluate(config, {}, now)
        self.assertTrue(decision.allowed)

    def test_temporary_unlock_allows_during_lock(self):
        config = normalize_config({"timezone": "UTC", "lock_windows": [parse_window("00:00-23:59")]})
        now = datetime(2026, 6, 20, 20, 0, tzinfo=timezone.utc)
        state = {"unlock_expires_at": "2026-06-20T20:30:00+00:00"}
        decision = evaluate(config, state, now)
        self.assertTrue(decision.allowed)
        self.assertTrue(decision.temporarily_unlocked)

    def test_parse_window_preserves_explicit_days(self):
        window = parse_window("19:00-05:00 mon,tue,wed")
        self.assertEqual(window["days"], ["mon", "tue", "wed"])

    def test_password_required_for_keeps_mandatory_actions(self):
        config = normalize_config({"password_required_for": ["disable"]})
        self.assertIn("unlock", config["password_required_for"])
        self.assertIn("passwd", config["password_required_for"])
        self.assertIn("configure", config["password_required_for"])
        self.assertIn("install", config["password_required_for"])
        self.assertIn("uninstall", config["password_required_for"])
        self.assertIn("disable", config["password_required_for"])


if __name__ == "__main__":
    unittest.main()
