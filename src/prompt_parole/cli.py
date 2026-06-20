from __future__ import annotations

import argparse
import getpass
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Sequence

from . import __version__
from .app import PromptParole
from .crypto import validate_new_password
from .errors import ConfigError, PasswordError, PromptParoleError
from .gui import DEFAULT_HOST, DEFAULT_PORT, run_gui
from .hooks import hook_stdout
from .install import install_targets, uninstall_targets


def _read_password(prompt: str) -> str:
    try:
        return getpass.getpass(prompt)
    except EOFError as exc:
        raise PasswordError("Password input was required but no terminal input was available.") from exc


def _read_stdin_lines(expected: int) -> list[str]:
    lines = [line.rstrip("\n") for line in sys.stdin.readlines()]
    if len(lines) < expected:
        raise PasswordError(f"Expected {expected} password line(s) on stdin.")
    return lines[:expected]


def _confirm_new_password(args: argparse.Namespace) -> str:
    if args.password_stdin:
        first, second = _read_stdin_lines(2)
    else:
        first = _read_password("Password: ")
        second = _read_password("Password again: ")
    if first != second:
        raise PasswordError("Passwords do not match.")
    validate_new_password(first)
    return first


def _current_password(args: argparse.Namespace, prompt: str = "Current password: ") -> str:
    if args.password_stdin:
        return _read_stdin_lines(1)[0]
    return _read_password(prompt)


def _targets(value: str) -> list[str]:
    parts = [part.strip().lower() for part in value.split(",") if part.strip()]
    if not parts:
        raise argparse.ArgumentTypeError("At least one target is required.")
    valid = {"claude", "codex"}
    invalid = [part for part in parts if part not in valid]
    if invalid:
        raise argparse.ArgumentTypeError(f"Unknown target(s): {', '.join(invalid)}.")
    return parts


def _format_dt(value: datetime | None) -> str:
    if value is None:
        return "none"
    return value.strftime("%Y-%m-%d %H:%M:%S %Z").strip()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="prompt-parole", description="Prompt curfew for Claude Code and Codex.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    setup = sub.add_parser("setup", help="Set the password and initial lock schedule.")
    setup.add_argument("--password-stdin", action="store_true", help="Read password and confirmation from stdin.")
    setup.add_argument("--lock-window", action="append", help="Lock window like 19:00-05:00. Can be repeated.")
    setup.add_argument("--unlock-duration-minutes", type=int, help="Default temporary unlock duration.")
    setup.add_argument("--password-required-for", help="Comma-separated actions requiring password.")

    configure = sub.add_parser("configure", help="Change lock schedule after entering the current password.")
    configure.add_argument("--password-stdin", action="store_true", help="Read current password from stdin.")
    configure.add_argument("--lock-window", action="append", help="Replacement lock window like 19:00-05:00. Can be repeated.")
    configure.add_argument("--timezone", help="Timezone name, or local.")
    configure.add_argument("--unlock-duration-minutes", type=int, help="Default temporary unlock duration.")
    configure.add_argument("--password-required-for", help="Comma-separated actions requiring password.")

    passwd = sub.add_parser("passwd", help="Change the password.")
    passwd.add_argument("--password-stdin", action="store_true", help="Read current password, new password, confirmation from stdin.")

    unlock = sub.add_parser("unlock", help="Temporarily unlock prompts.")
    unlock.add_argument("--password-stdin", action="store_true", help="Read password from stdin.")
    unlock.add_argument("--duration-minutes", type=int, help="Override unlock duration.")

    sub.add_parser("lock", help="Clear any temporary unlock.")

    status = sub.add_parser("status", help="Show current lock status.")
    status.add_argument("--json", action="store_true", help="Print machine-readable status.")

    check = sub.add_parser("check", help="Check whether a prompt would be allowed.")
    check.add_argument("--json", action="store_true", help="Print machine-readable result.")

    hook = sub.add_parser("hook", help="Run as a Claude Code or Codex UserPromptSubmit hook.")
    hook.add_argument("--agent", required=True, choices=["claude-code", "codex"])

    gui = sub.add_parser("gui", help="Open the local settings GUI.")
    gui.add_argument("--host", default=DEFAULT_HOST)
    gui.add_argument("--port", type=int, default=DEFAULT_PORT)
    gui.add_argument("--no-browser", action="store_true")

    install = sub.add_parser("install", help="Install global hooks for Claude Code and/or Codex.")
    install.add_argument("--password-stdin", action="store_true", help="Read current password from stdin when required.")
    install.add_argument("--targets", type=_targets, default=["claude", "codex"], help="Comma-separated: claude,codex.")
    install.add_argument("--home", type=Path, help="Override OS home for testing.")
    install.add_argument("--hook-command", help="Override hook command.")

    uninstall = sub.add_parser("uninstall", help="Remove Prompt Parole hooks.")
    uninstall.add_argument("--password-stdin", action="store_true", help="Read current password from stdin when required.")
    uninstall.add_argument("--targets", type=_targets, default=["claude", "codex"], help="Comma-separated: claude,codex.")
    uninstall.add_argument("--home", type=Path, help="Override OS home for testing.")

    return parser


def _action_list(value: str | None) -> list[str] | None:
    if value is None:
        return None
    return [part.strip().lower() for part in value.split(",") if part.strip()]


def _require_action_password(app: PromptParole, args: argparse.Namespace, action: str) -> None:
    if not app.is_configured():
        return
    if action in app.load_config()["password_required_for"]:
        app.assert_password(_current_password(args))


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    app = PromptParole()
    try:
        if args.subcommand == "setup":
            password = _confirm_new_password(args)
            app.setup(
                password,
                lock_windows=args.lock_window,
                unlock_duration_minutes=args.unlock_duration_minutes,
                password_required_for=_action_list(args.password_required_for),
            )
            print("Prompt Parole is set up.")
            return 0

        if args.subcommand == "configure":
            if not (args.lock_window or args.timezone or args.unlock_duration_minutes is not None or args.password_required_for):
                raise ConfigError("Nothing to configure.")
            current = _current_password(args)
            config = app.configure(
                current,
                lock_windows=args.lock_window,
                timezone_name=args.timezone,
                unlock_duration_minutes=args.unlock_duration_minutes,
                password_required_for=_action_list(args.password_required_for),
            )
            print(json.dumps(config, indent=2, sort_keys=True))
            return 0

        if args.subcommand == "passwd":
            if args.password_stdin:
                current, first, second = _read_stdin_lines(3)
                if first != second:
                    raise PasswordError("Passwords do not match.")
                new_password = first
            else:
                current = _read_password("Current password: ")
                namespace = argparse.Namespace(password_stdin=False)
                new_password = _confirm_new_password(namespace)
            app.change_password(current, new_password)
            print("Password changed.")
            return 0

        if args.subcommand == "unlock":
            password = _current_password(args, "Password: ")
            expires = app.unlock(password, duration_minutes=args.duration_minutes)
            print(f"Unlocked until {_format_dt(expires)}.")
            return 0

        if args.subcommand == "lock":
            app.lock()
            print("Locked.")
            return 0

        if args.subcommand == "status":
            decision = app.decision()
            payload = {
                "allowed": decision.allowed,
                "scheduled_locked": decision.scheduled_locked,
                "temporarily_unlocked": decision.temporarily_unlocked,
                "reason": decision.reason,
                "locked_until": decision.locked_until.isoformat() if decision.locked_until else None,
                "unlock_expires_at": decision.unlock_expires_at.isoformat() if decision.unlock_expires_at else None,
            }
            if args.json:
                print(json.dumps(payload, sort_keys=True))
            else:
                state = "allowed" if decision.allowed else "blocked"
                print(f"Prompts are {state}: {decision.reason}.")
                if decision.locked_until:
                    print(f"Scheduled lock ends: {_format_dt(decision.locked_until)}")
                if decision.unlock_expires_at:
                    print(f"Temporary unlock expires: {_format_dt(decision.unlock_expires_at)}")
            return 0

        if args.subcommand == "check":
            decision = app.decision()
            if args.json:
                print(json.dumps({"allowed": decision.allowed, "reason": decision.reason}, sort_keys=True))
            else:
                print("allowed" if decision.allowed else "blocked")
            return 0 if decision.allowed else 1

        if args.subcommand == "hook":
            sys.stdout.write(hook_stdout(args.agent, app))
            return 0

        if args.subcommand == "gui":
            run_gui(args.host, args.port, open_browser=not args.no_browser, app=app)
            return 0

        if args.subcommand == "install":
            _require_action_password(app, args, "install")
            results = install_targets(args.targets, home=args.home, command=args.hook_command)
            for target, backup in results.items():
                suffix = f" backup: {backup}" if backup else ""
                print(f"Installed {target} hook.{suffix}")
            return 0

        if args.subcommand == "uninstall":
            _require_action_password(app, args, "uninstall")
            results = uninstall_targets(args.targets, home=args.home)
            for target, (removed, backup) in results.items():
                suffix = f" backup: {backup}" if backup else ""
                print(f"Removed {removed} {target} hook(s).{suffix}")
            return 0

        parser.error("Unknown command.")
        return 2
    except PromptParoleError as exc:
        print(f"prompt-parole: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"prompt-parole: {exc}", file=sys.stderr)
        return 2
