import tempfile
import unittest
from pathlib import Path

from prompt_parole.app import PromptParole
from prompt_parole.gui import _parse_window_lines, render_page


class GuiTests(unittest.TestCase):
    def test_render_page_contains_nippon_palette_and_forms(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = PromptParole(Path(tmp))
            app.setup("correct horse battery staple")
            html = render_page(app)
            self.assertIn("Prompt Parole", html)
            self.assertIn("shironeri", html)
            self.assertIn("yamabuki", html)
            self.assertIn('action="/configure"', html)
            self.assertIn('name="password_required_for"', html)

    def test_render_page_supports_first_setup_before_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            html = render_page(PromptParole(Path(tmp)))
            self.assertIn("First Setup", html)
            self.assertIn('action="/setup"', html)
            self.assertIn("Start Parole", html)

    def test_parse_window_lines_preserves_days(self):
        self.assertEqual(
            _parse_window_lines("19:00-05:00 mon,tue\n\n10:00-11:00 fri"),
            ["19:00-05:00 mon,tue", "10:00-11:00 fri"],
        )


if __name__ == "__main__":
    unittest.main()
