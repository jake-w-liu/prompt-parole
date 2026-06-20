from __future__ import annotations

import json
import shlex
import shutil
import sys
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .storage import backup_file, write_json_atomic


HOOK_MARKER = "PROMPT_PAROLE_HOOK=1"


def default_command(agent: str) -> str:
    executable = shutil.which("prompt-parole")
    if executable:
        base = shlex.quote(executable)
    else:
        base = f"{shlex.quote(sys.executable)} -m prompt_parole"
    return f"{HOOK_MARKER} {base} hook --agent {shlex.quote(agent)}"


def claude_settings_path(home: Path | None = None) -> Path:
    root = home or Path.home()
    return root / ".claude" / "settings.json"


def codex_hooks_path(home: Path | None = None) -> Path:
    root = home or Path.home()
    return root / ".codex" / "hooks.json"


def _load_json_object(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON; refusing to overwrite it.") from exc
    if not isinstance(data, dict):
        raise ConfigError(f"{path} must contain a JSON object.")
    return data


def _is_prompt_parole_hook(handler: dict[str, Any]) -> bool:
    command = str(handler.get("command", ""))
    return HOOK_MARKER in command or "prompt-parole hook --agent" in command or "prompt_parole hook --agent" in command


def _remove_from_hooks(data: dict[str, Any], event: str = "UserPromptSubmit") -> int:
    hooks_root = data.get("hooks")
    if hooks_root is None:
        return 0
    if not isinstance(hooks_root, dict):
        raise ConfigError("Existing hooks field must be an object.")
    groups = hooks_root.get(event)
    if groups is None:
        return 0
    if not isinstance(groups, list):
        raise ConfigError(f"Existing hooks.{event} field must be a list.")
    removed = 0
    remaining_groups = []
    for group in groups:
        if not isinstance(group, dict):
            remaining_groups.append(group)
            continue
        handlers = group.get("hooks")
        if not isinstance(handlers, list):
            remaining_groups.append(group)
            continue
        kept = []
        for handler in handlers:
            if isinstance(handler, dict) and _is_prompt_parole_hook(handler):
                removed += 1
            else:
                kept.append(handler)
        if kept:
            new_group = dict(group)
            new_group["hooks"] = kept
            remaining_groups.append(new_group)
    if remaining_groups:
        hooks_root[event] = remaining_groups
    else:
        hooks_root.pop(event, None)
    if not hooks_root:
        data.pop("hooks", None)
    return removed


def _add_hook(data: dict[str, Any], command: str, *, status_message: str) -> None:
    hooks_root = data.setdefault("hooks", {})
    if not isinstance(hooks_root, dict):
        raise ConfigError("Existing hooks field must be an object.")
    groups = hooks_root.setdefault("UserPromptSubmit", [])
    if not isinstance(groups, list):
        raise ConfigError("Existing hooks.UserPromptSubmit field must be a list.")
    groups.append(
        {
            "hooks": [
                {
                    "type": "command",
                    "command": command,
                    "timeout": 5,
                    "statusMessage": status_message,
                }
            ]
        }
    )


def install_json_hook(path: Path, command: str, *, status_message: str) -> Path | None:
    data = _load_json_object(path)
    _remove_from_hooks(data)
    _add_hook(data, command, status_message=status_message)
    backup = backup_file(path)
    write_json_atomic(path, data, mode=0o600)
    return backup


def uninstall_json_hook(path: Path) -> tuple[int, Path | None]:
    data = _load_json_object(path)
    removed = _remove_from_hooks(data)
    if removed == 0:
        return 0, None
    backup = backup_file(path)
    write_json_atomic(path, data, mode=0o600)
    return removed, backup


def install_targets(targets: list[str], *, home: Path | None = None, command: str | None = None) -> dict[str, Path | None]:
    results: dict[str, Path | None] = {}
    for target in targets:
        if target == "claude":
            cmd = command or default_command("claude-code")
            results[target] = install_json_hook(
                claude_settings_path(home),
                cmd,
                status_message="Checking Prompt Parole curfew",
            )
        elif target == "codex":
            cmd = command or default_command("codex")
            results[target] = install_json_hook(
                codex_hooks_path(home),
                cmd,
                status_message="Checking Prompt Parole curfew",
            )
        else:
            raise ConfigError(f"Unknown install target {target!r}.")
    return results


def uninstall_targets(targets: list[str], *, home: Path | None = None) -> dict[str, tuple[int, Path | None]]:
    results: dict[str, tuple[int, Path | None]] = {}
    for target in targets:
        if target == "claude":
            results[target] = uninstall_json_hook(claude_settings_path(home))
        elif target == "codex":
            results[target] = uninstall_json_hook(codex_hooks_path(home))
        else:
            raise ConfigError(f"Unknown install target {target!r}.")
    return results
