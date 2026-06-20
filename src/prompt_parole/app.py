from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from .crypto import hash_password, validate_new_password, verify_password
from .errors import NotConfiguredError, PasswordError
from .paths import config_path, events_path, secret_path, state_path
from .policy import DEFAULT_CONFIG, Decision, evaluate, normalize_config, parse_window, timezone_for_config
from .storage import append_event, now_iso, read_json, write_json_atomic


class PromptParole:
    def __init__(self, home: Path | None = None) -> None:
        self.home = home

    @property
    def config_file(self) -> Path:
        return config_path(self.home)

    @property
    def secret_file(self) -> Path:
        return secret_path(self.home)

    @property
    def state_file(self) -> Path:
        return state_path(self.home)

    @property
    def events_file(self) -> Path:
        return events_path(self.home)

    def is_configured(self) -> bool:
        return self.secret_file.exists()

    def load_config(self) -> dict[str, Any]:
        raw = read_json(self.config_file, DEFAULT_CONFIG)
        return normalize_config(raw)

    def load_state(self) -> dict[str, Any]:
        state = read_json(self.state_file, {"version": 1})
        if not isinstance(state, dict):
            return {"version": 1}
        return {"version": 1, **state}

    def load_secret(self) -> dict[str, Any]:
        if not self.secret_file.exists():
            raise NotConfiguredError("Prompt Parole is not configured. Run `prompt-parole setup`.")
        secret = read_json(self.secret_file)
        if not isinstance(secret, dict):
            raise NotConfiguredError("Password file is invalid.")
        return secret

    def setup(
        self,
        password: str,
        *,
        lock_windows: list[str] | None = None,
        timezone_name: str | None = None,
        unlock_duration_minutes: int | None = None,
        password_required_for: list[str] | None = None,
    ) -> None:
        if self.secret_file.exists():
            raise PasswordError("Prompt Parole is already configured. Use `prompt-parole passwd` to change the password.")
        config = normalize_config(DEFAULT_CONFIG)
        if lock_windows is not None:
            config["lock_windows"] = [parse_window(window) for window in lock_windows]
        if timezone_name:
            config["timezone"] = timezone_name
        if unlock_duration_minutes is not None:
            config["unlock_duration_minutes"] = unlock_duration_minutes
        if password_required_for is not None:
            config["password_required_for"] = password_required_for
        config = normalize_config(config)
        write_json_atomic(self.config_file, config, mode=0o600)
        write_json_atomic(self.secret_file, hash_password(password), mode=0o600)
        write_json_atomic(self.state_file, {"version": 1, "unlock_expires_at": None, "updated_at": now_iso()}, mode=0o600)
        append_event(self.events_file, {"event": "setup"})

    def assert_password(self, password: str) -> None:
        if not verify_password(password, self.load_secret()):
            raise PasswordError("Incorrect password.")

    def change_password(self, current_password: str, new_password: str) -> None:
        self.assert_password(current_password)
        validate_new_password(new_password)
        write_json_atomic(self.secret_file, hash_password(new_password), mode=0o600)
        append_event(self.events_file, {"event": "password_changed"})

    def configure(
        self,
        current_password: str,
        *,
        lock_windows: list[str] | None = None,
        timezone_name: str | None = None,
        unlock_duration_minutes: int | None = None,
        password_required_for: list[str] | None = None,
    ) -> dict[str, Any]:
        self.assert_password(current_password)
        config = self.load_config()
        if lock_windows is not None:
            config["lock_windows"] = [parse_window(window) for window in lock_windows]
        if timezone_name:
            config["timezone"] = timezone_name
        if unlock_duration_minutes is not None:
            config["unlock_duration_minutes"] = unlock_duration_minutes
        if password_required_for is not None:
            config["password_required_for"] = password_required_for
        config = normalize_config(config)
        write_json_atomic(self.config_file, config, mode=0o600)
        append_event(self.events_file, {"event": "configured"})
        return config

    def unlock(self, password: str, *, duration_minutes: int | None = None) -> datetime:
        self.assert_password(password)
        config = self.load_config()
        minutes = duration_minutes or int(config["unlock_duration_minutes"])
        if minutes <= 0:
            raise ValueError("Unlock duration must be positive.")
        tz = timezone_for_config(config)
        expires = datetime.now(tz) + timedelta(minutes=minutes)
        state = self.load_state()
        state.update({"unlock_expires_at": expires.isoformat(), "updated_at": now_iso()})
        write_json_atomic(self.state_file, state, mode=0o600)
        append_event(self.events_file, {"event": "unlocked", "duration_minutes": minutes})
        return expires

    def lock(self) -> None:
        state = self.load_state()
        state.update({"unlock_expires_at": None, "updated_at": now_iso()})
        write_json_atomic(self.state_file, state, mode=0o600)
        append_event(self.events_file, {"event": "manually_locked"})

    def decision(self, now: datetime | None = None) -> Decision:
        if not self.is_configured():
            raise NotConfiguredError("Prompt Parole is not configured. Run `prompt-parole setup`.")
        return evaluate(self.load_config(), self.load_state(), now)

    def record_block(self, agent: str, decision: Decision) -> None:
        payload: dict[str, Any] = {"event": "prompt_blocked", "agent": agent}
        if decision.locked_until:
            payload["locked_until"] = decision.locked_until.isoformat()
        append_event(self.events_file, payload)
