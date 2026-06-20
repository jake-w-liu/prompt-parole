import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from prompt_parole.app import PromptParole
from prompt_parole.hooks import hook_payload, hook_stdout


class HookTests(unittest.TestCase):
    def test_hook_allows_when_not_configured(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(hook_stdout("codex", PromptParole(Path(tmp))), "")

    def test_hook_blocks_with_agent_specific_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = PromptParole(Path(tmp))
            app.setup("correct horse battery staple", lock_windows=["00:00-23:59", "23:59-00:00"])
            payload = hook_payload("claude-code", app)
            self.assertEqual(payload["decision"], "block")
            self.assertTrue(payload["suppressOriginalPrompt"])
            self.assertIn("prompt-parole unlock", payload["reason"])

    def test_codex_hook_json_has_block_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = PromptParole(Path(tmp))
            app.setup("correct horse battery staple", lock_windows=["00:00-23:59", "23:59-00:00"])
            output = hook_stdout("codex", app)
            payload = json.loads(output)
            self.assertEqual(payload["decision"], "block")
            self.assertIn("reason", payload)
            self.assertNotIn("suppressOriginalPrompt", payload)


if __name__ == "__main__":
    unittest.main()
