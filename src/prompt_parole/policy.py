from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from .errors import ConfigError


DAY_NAMES = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")


DEFAULT_CONFIG: dict[str, Any] = {
    "version": 1,
    "timezone": "local",
    "unlock_duration_minutes": 30,
    "password_required_for": ["unlock", "passwd", "configure", "install", "uninstall", "disable"],
    "lock_windows": [
        {
            "start": "19:00",
            "end": "05:00",
            "days": list(DAY_NAMES),
        }
    ],
    "log_prompt_text": False,
}

PASSWORD_ACTIONS = {"unlock", "passwd", "configure", "install", "uninstall", "disable"}
MANDATORY_PASSWORD_ACTIONS = {"unlock", "passwd", "configure", "install", "uninstall", "disable"}


@dataclass(frozen=True)
class Decision:
    allowed: bool
    scheduled_locked: bool
    temporarily_unlocked: bool
    reason: str
    locked_until: datetime | None = None
    unlock_expires_at: datetime | None = None


def parse_hhmm(value: str) -> time:
    parts = value.split(":")
    if len(parts) != 2:
        raise ConfigError(f"Invalid time {value!r}; expected HH:MM.")
    try:
        hour = int(parts[0])
        minute = int(parts[1])
    except ValueError as exc:
        raise ConfigError(f"Invalid time {value!r}; expected HH:MM.") from exc
    if not (0 <= hour <= 23 and 0 <= minute <= 59):
        raise ConfigError(f"Invalid time {value!r}; expected HH:MM.")
    return time(hour, minute)


def parse_window(value: str) -> dict[str, Any]:
    parts = value.split()
    if not parts:
        raise ConfigError("Lock window must look like HH:MM-HH:MM.")
    time_part = parts[0]
    if "-" not in time_part:
        raise ConfigError("Lock window must look like HH:MM-HH:MM.")
    start, end = time_part.split("-", 1)
    parse_hhmm(start)
    parse_hhmm(end)
    if start == end:
        raise ConfigError("Lock window start and end cannot be the same.")
    days = list(DAY_NAMES)
    if len(parts) > 1:
        days = [day.strip().lower() for day in " ".join(parts[1:]).replace(";", ",").split(",") if day.strip()]
        invalid = [day for day in days if day not in DAY_NAMES]
        if invalid:
            raise ConfigError(f"Invalid day {invalid[0]!r}; expected one of {', '.join(DAY_NAMES)}.")
    return {"start": start, "end": end, "days": days}


def normalize_config(raw: dict[str, Any] | None = None) -> dict[str, Any]:
    config = {**DEFAULT_CONFIG, **(raw or {})}
    windows = config.get("lock_windows")
    if not isinstance(windows, list) or not windows:
        raise ConfigError("At least one lock window is required.")
    normalized_windows = []
    for window in windows:
        if not isinstance(window, dict):
            raise ConfigError("Each lock window must be an object.")
        start = str(window.get("start", ""))
        end = str(window.get("end", ""))
        parse_hhmm(start)
        parse_hhmm(end)
        if start == end:
            raise ConfigError("Lock window start and end cannot be the same.")
        days = window.get("days", DAY_NAMES)
        if not isinstance(days, list) or not days:
            raise ConfigError("Lock window days must be a non-empty list.")
        clean_days = []
        for day in days:
            day_name = str(day).lower()
            if day_name not in DAY_NAMES:
                raise ConfigError(f"Invalid day {day!r}; expected one of {', '.join(DAY_NAMES)}.")
            clean_days.append(day_name)
        normalized_windows.append({"start": start, "end": end, "days": clean_days})
    try:
        unlock_minutes = int(config.get("unlock_duration_minutes", 30))
    except (TypeError, ValueError) as exc:
        raise ConfigError("unlock_duration_minutes must be an integer.") from exc
    if unlock_minutes <= 0:
        raise ConfigError("unlock_duration_minutes must be positive.")
    password_required_for = config.get("password_required_for", DEFAULT_CONFIG["password_required_for"])
    if not isinstance(password_required_for, list):
        raise ConfigError("password_required_for must be a list.")
    clean_password_actions = set(MANDATORY_PASSWORD_ACTIONS)
    for action in password_required_for:
        clean_action = str(action).lower()
        if clean_action not in PASSWORD_ACTIONS:
            raise ConfigError(
                f"Invalid password action {action!r}; expected one of {', '.join(sorted(PASSWORD_ACTIONS))}."
            )
        clean_password_actions.add(clean_action)
    timezone_name = str(config.get("timezone", "local"))
    if timezone_name != "local":
        try:
            ZoneInfo(timezone_name)
        except ZoneInfoNotFoundError as exc:
            raise ConfigError(f"Unknown timezone {timezone_name!r}.") from exc
    return {
        "version": 1,
        "timezone": timezone_name,
        "unlock_duration_minutes": unlock_minutes,
        "password_required_for": sorted(clean_password_actions),
        "lock_windows": normalized_windows,
        "log_prompt_text": bool(config.get("log_prompt_text", False)),
    }


def timezone_for_config(config: dict[str, Any]) -> timezone | ZoneInfo:
    name = config.get("timezone", "local")
    if name == "local":
        return datetime.now().astimezone().tzinfo or timezone.utc
    return ZoneInfo(str(name))


def parse_iso_datetime(value: Any) -> datetime | None:
    if not value:
        return None
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed


def _window_interval(now: datetime, start_day_offset: int, window: dict[str, Any]) -> tuple[datetime, datetime] | None:
    start_date = (now + timedelta(days=start_day_offset)).date()
    start_day = DAY_NAMES[start_date.weekday()]
    if start_day not in window["days"]:
        return None
    start = parse_hhmm(window["start"])
    end = parse_hhmm(window["end"])
    start_dt = datetime.combine(start_date, start, tzinfo=now.tzinfo)
    end_dt = datetime.combine(start_date, end, tzinfo=now.tzinfo)
    if end_dt <= start_dt:
        end_dt += timedelta(days=1)
    return start_dt, end_dt


def scheduled_lock_until(config: dict[str, Any], now: datetime | None = None) -> datetime | None:
    config = normalize_config(config)
    tz = timezone_for_config(config)
    current = (now or datetime.now(tz)).astimezone(tz)
    matching_ends = []
    for window in config["lock_windows"]:
        for offset in (-1, 0):
            interval = _window_interval(current, offset, window)
            if interval is None:
                continue
            start_dt, end_dt = interval
            if start_dt <= current < end_dt:
                matching_ends.append(end_dt)
    if not matching_ends:
        return None
    return max(matching_ends)


def evaluate(config: dict[str, Any], state: dict[str, Any] | None = None, now: datetime | None = None) -> Decision:
    config = normalize_config(config)
    tz = timezone_for_config(config)
    current = (now or datetime.now(tz)).astimezone(tz)
    locked_until = scheduled_lock_until(config, current)
    unlock_expires = parse_iso_datetime((state or {}).get("unlock_expires_at"))
    if unlock_expires is not None:
        unlock_expires = unlock_expires.astimezone(tz)
    scheduled_locked = locked_until is not None
    temporarily_unlocked = bool(unlock_expires and current < unlock_expires)
    if not scheduled_locked:
        return Decision(True, False, temporarily_unlocked, "outside lock window", None, unlock_expires)
    if temporarily_unlocked:
        return Decision(True, True, True, "temporarily unlocked", locked_until, unlock_expires)
    return Decision(False, True, False, "prompt curfew active", locked_until, unlock_expires)
