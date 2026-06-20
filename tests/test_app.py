import tempfile
import unittest
from pathlib import Path

from prompt_parole.app import PromptParole
from prompt_parole.errors import ConfigError


class AppTests(unittest.TestCase):
    def test_setup_rejects_empty_lock_window_list_before_writing_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = PromptParole(Path(tmp))
            with self.assertRaises(ConfigError):
                app.setup("correct horse battery staple", lock_windows=[])
            self.assertFalse(app.secret_file.exists())

    def test_configure_rejects_empty_lock_window_list_without_changing_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = PromptParole(Path(tmp))
            app.setup("correct horse battery staple", lock_windows=["19:00-05:00"])
            before = app.load_config()
            with self.assertRaises(ConfigError):
                app.configure("correct horse battery staple", lock_windows=[])
            self.assertEqual(app.load_config(), before)

    def test_setup_accepts_timezone_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = PromptParole(Path(tmp))
            app.setup("correct horse battery staple", timezone_name="UTC")
            self.assertEqual(app.load_config()["timezone"], "UTC")


if __name__ == "__main__":
    unittest.main()
