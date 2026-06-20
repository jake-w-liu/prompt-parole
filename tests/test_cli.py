import json
import os
import subprocess
import sys
import tempfile
import unittest


class CliTests(unittest.TestCase):
    def run_cli(self, args, home, input_text=""):
        env = os.environ.copy()
        env["PROMPT_PAROLE_HOME"] = home
        env["PYTHONPATH"] = os.path.abspath("src")
        return subprocess.run(
            [sys.executable, "-m", "prompt_parole", *args],
            input=input_text,
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )

    def test_setup_status_unlock_and_password_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            setup = self.run_cli(
                [
                    "setup",
                    "--password-stdin",
                    "--lock-window",
                    "00:00-23:59",
                    "--lock-window",
                    "23:59-00:00",
                    "--unlock-duration-minutes",
                    "10",
                    "--password-required-for",
                    "unlock,passwd,disable",
                ],
                tmp,
                "correct horse battery staple\ncorrect horse battery staple\n",
            )
            self.assertEqual(setup.returncode, 0, setup.stderr)

            install_without_password = self.run_cli(
                ["install", "--home", tmp, "--hook-command", "PROMPT_PAROLE_HOOK=1 prompt-parole hook --agent codex"],
                tmp,
            )
            self.assertEqual(install_without_password.returncode, 2)

            install_with_password = self.run_cli(
                [
                    "install",
                    "--password-stdin",
                    "--home",
                    tmp,
                    "--hook-command",
                    "PROMPT_PAROLE_HOOK=1 prompt-parole hook --agent codex",
                ],
                tmp,
                "correct horse battery staple\n",
            )
            self.assertEqual(install_with_password.returncode, 0, install_with_password.stderr)

            blocked = self.run_cli(["check", "--json"], tmp)
            self.assertEqual(blocked.returncode, 1)
            self.assertFalse(json.loads(blocked.stdout)["allowed"])

            unlock = self.run_cli(["unlock", "--password-stdin", "--duration-minutes", "5"], tmp, "correct horse battery staple\n")
            self.assertEqual(unlock.returncode, 0, unlock.stderr)

            allowed = self.run_cli(["check", "--json"], tmp)
            self.assertEqual(allowed.returncode, 0)
            self.assertTrue(json.loads(allowed.stdout)["allowed"])

            passwd = self.run_cli(
                ["passwd", "--password-stdin"],
                tmp,
                "correct horse battery staple\nnew correct horse battery staple\nnew correct horse battery staple\n",
            )
            self.assertEqual(passwd.returncode, 0, passwd.stderr)


if __name__ == "__main__":
    unittest.main()
