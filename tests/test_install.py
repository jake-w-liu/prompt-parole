import json
import tempfile
import unittest
from pathlib import Path

from prompt_parole.install import install_targets, uninstall_targets


class InstallTests(unittest.TestCase):
    def test_installs_and_uninstalls_hooks_preserving_existing_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            claude_dir = home / ".claude"
            claude_dir.mkdir()
            settings = claude_dir / "settings.json"
            settings.write_text(
                json.dumps(
                    {
                        "hooks": {
                            "UserPromptSubmit": [
                                {"hooks": [{"type": "command", "command": "echo keep"}]}
                            ]
                        }
                    }
                ),
                encoding="utf-8",
            )
            install_targets(["claude", "codex"], home=home, command="PROMPT_PAROLE_HOOK=1 prompt-parole hook --agent test")

            claude_data = json.loads(settings.read_text(encoding="utf-8"))
            codex_data = json.loads((home / ".codex" / "hooks.json").read_text(encoding="utf-8"))
            self.assertEqual(len(claude_data["hooks"]["UserPromptSubmit"]), 2)
            self.assertEqual(len(codex_data["hooks"]["UserPromptSubmit"]), 1)

            results = uninstall_targets(["claude", "codex"], home=home)
            self.assertEqual(results["claude"][0], 1)
            self.assertEqual(results["codex"][0], 1)
            claude_data = json.loads(settings.read_text(encoding="utf-8"))
            self.assertEqual(
                claude_data["hooks"]["UserPromptSubmit"][0]["hooks"][0]["command"],
                "echo keep",
            )


if __name__ == "__main__":
    unittest.main()
